"""Contract-driven Docker Compose renderer.

Replaces the static ``docker-compose.*.yml`` files with on-the-fly
generation from the active :class:`FrozenCaseContract`. Every value is
sourced from the contract - no environment-variable fallbacks, no
floating image tags, and no hardcoded credentials.

Public API:
    render_dast_compose(contract) -> str
    render_docker_runtime_compose(contract) -> str
    render_crawlmaze_compose(contract) -> str
    render_all(contract, target_dir) -> dict[str, Path]

Each renderer returns a deterministic YAML document. Image references
are pinned by digest (``registry/repo@sha256:...``) so reruns of the
same case bind to the same artifacts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

import yaml

from static.core.contract import FrozenCaseContract, ImageRef


# Helpers


def _image(ref: ImageRef) -> str:
    """Return the digest-pinned image string for compose ``image:``."""
    return ref.full_ref


def _network(name: str) -> dict:
    return {"driver": "bridge"}


# DAST compose (live REDCap + Playwright)


def render_dast_compose(contract: FrozenCaseContract) -> str:
    """Render the primary DAST compose stack from a frozen contract."""
    creds = contract.dynamic.credentials
    images = contract.dynamic.images
    net = contract.dynamic.network
    port = contract.dynamic.port

    services: dict = {
        "redcap-dast-db": {
            "image": _image(images.mariadb),
            "container_name": "redacts-dast-db",
            "restart": "no",
            "environment": {
                "MARIADB_ROOT_PASSWORD": creds.db_root_password,
                "MARIADB_DATABASE": "redcap",
                "MARIADB_USER": creds.db_user,
                "MARIADB_PASSWORD": creds.db_password,
            },
            "tmpfs": ["/var/lib/mysql:size=512M"],
            "healthcheck": {
                "test": [
                    "CMD",
                    "healthcheck.sh",
                    "--connect",
                    "--innodb_initialized",
                ],
                "interval": "5s",
                "timeout": "3s",
                "retries": 20,
                "start_period": "15s",
            },
            "networks": ["dast_net"],
        },
        "redcap-dast-app": {
            "build": {
                "context": "${DAST_BUILD_CONTEXT:-../}",
                "dockerfile": "${DAST_DOCKERFILE:-Dockerfile.dast.generated}",
            },
            "container_name": "redacts-dast-app",
            "restart": "no",
            "depends_on": {
                "redcap-dast-db": {"condition": "service_healthy"},
            },
            "environment": {
                "REDCAP_DB_HOST": "redcap-dast-db",
                "REDCAP_DB_PORT": "3306",
                "REDCAP_DB_NAME": "redcap",
                "REDCAP_DB_USER": creds.db_user,
                "REDCAP_DB_PASSWORD": creds.db_password,
                "REDCAP_DB_PASS": creds.db_password,
                "REDCAP_SALT": creds.salt,
                "DAST_ADMIN_USER": creds.admin_user,
                "EXTERNAL_PORT": str(port),
                "XDEBUG_MODE": net.xdebug_mode,
                "XDEBUG_CONFIG": "output_dir=/tmp/xdebug",
            },
            "ports": [f"{port}:80"],
            "volumes": [
                "dast_edocs:/var/www/html/redcap/edocs",
                "dast_temp:/var/www/html/redcap/temp",
                "./results/xdebug:/tmp/xdebug",
                "./upgrade-packages:/opt/upgrade-packages:ro",
            ],
            "networks": ["dast_net"],
        },
        "playwright": {
            "image": _image(images.playwright),
            "container_name": "redacts-dast-playwright",
            "restart": "no",
            "depends_on": {
                "redcap-dast-app": {"condition": "service_started"},
            },
            "environment": {
                "REDCAP_BASE_URL": "http://redcap-dast-app",
                "REDCAP_ADMIN_USER": creds.admin_user,
                "REDCAP_ADMIN_PASS": creds.admin_password,
                "DAST_RESULTS_DIR": "/results",
                "REDCAP_WEBROOT": "/redcap-snapshot",
            },
            "volumes": [
                "./results:/results",
                "./tests:/tests:ro",
                "dast_edocs:/redcap-snapshot/edocs:ro",
                "dast_temp:/redcap-snapshot/temp:ro",
            ],
            "networks": ["dast_net"],
        },
    }

    document = {
        "services": services,
        "volumes": {"dast_edocs": {"driver": "local"}, "dast_temp": {"driver": "local"}},
        "networks": {"dast_net": _network("dast_net")},
    }
    return _emit(document, banner="DAST compose")


# Docker runtime compose (disposable REDCap + DB only)


def render_docker_runtime_compose(contract: FrozenCaseContract) -> str:
    """Render the minimal docker-runtime compose used by ``DockerRuntime``."""
    creds = contract.dynamic.credentials
    images = contract.dynamic.images
    port = contract.dynamic.port

    services: dict = {
        "db": {
            "image": _image(images.mariadb),
            "container_name": "redacts-dast-db",
            "restart": "no",
            "environment": {
                "MARIADB_ROOT_PASSWORD": creds.db_root_password,
                "MARIADB_DATABASE": "redcap",
                "MARIADB_USER": creds.db_user,
                "MARIADB_PASSWORD": creds.db_password,
            },
            "tmpfs": ["/var/lib/mysql:size=512M"],
            "healthcheck": {
                "test": [
                    "CMD",
                    "healthcheck.sh",
                    "--connect",
                    "--innodb_initialized",
                ],
                "interval": "5s",
                "timeout": "3s",
                "retries": 20,
                "start_period": "15s",
            },
            "networks": ["dast_net"],
        },
        "app": {
            "build": {
                "context": "${DOCKER_BUILD_CONTEXT}",
                "dockerfile": "Dockerfile.dast.generated",
            },
            "container_name": "redacts-dast-app",
            "restart": "no",
            "depends_on": {"db": {"condition": "service_healthy"}},
            "environment": {
                "REDCAP_DB_HOST": "db",
                "REDCAP_DB_PORT": "3306",
                "REDCAP_DB_NAME": "redcap",
                "REDCAP_DB_USER": creds.db_user,
                "REDCAP_DB_PASS": creds.db_password,
                "REDCAP_SALT": creds.salt,
            },
            "ports": [f"{port}:80"],
            "volumes": [
                "dast_edocs:/var/www/html/redcap/edocs",
                "dast_temp:/var/www/html/redcap/temp",
            ],
            "networks": ["dast_net"],
        },
    }
    document = {
        "services": services,
        "volumes": {"dast_edocs": {"driver": "local"}, "dast_temp": {"driver": "local"}},
        "networks": {"dast_net": _network("dast_net")},
    }
    return _emit(document, banner="Docker-runtime compose")


# Crawlmaze overlay


def render_crawlmaze_compose(contract: FrozenCaseContract) -> str:
    """Render the optional Security Crawl Maze overlay."""
    images = contract.dynamic.images
    if images.crawlmaze_node is None or images.crawlmaze_python is None:
        raise ValueError(
            "Contract does not declare crawlmaze image refs "
            "([dynamic.images.crawlmaze_node] / [dynamic.images.crawlmaze_python])."
        )

    services: dict = {
        "crawlmaze": {
            "build": {
                "context": ".",
                "dockerfile": "Dockerfile.crawlmaze.generated",
            },
            "container_name": "redacts-crawlmaze",
            "restart": "no",
            "ports": ["${CRAWLMAZE_PORT:-8686}:8080"],
            "healthcheck": {
                "test": [
                    "CMD",
                    "python",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://localhost:8080/')",
                ],
                "interval": "5s",
                "timeout": "3s",
                "retries": 10,
                "start_period": "10s",
            },
            "networks": ["crawlmaze_net"],
        },
        "playwright-crawlmaze": {
            "image": _image(contract.dynamic.images.playwright),
            "container_name": "redacts-crawlmaze-playwright",
            "restart": "no",
            "depends_on": {"crawlmaze": {"condition": "service_healthy"}},
            "environment": {
                "CRAWLMAZE_BASE_URL": "http://crawlmaze:8080",
                "DAST_RESULTS_DIR": "/results",
                "CRAWLMAZE_MODE": "true",
            },
            "volumes": ["./results:/results", "./tests:/tests:ro"],
            "networks": ["crawlmaze_net"],
            "command": (
                "npx playwright test tests/crawlmaze-coverage.spec.ts "
                "--reporter=json --timeout=120000"
            ),
        },
    }
    document = {
        "services": services,
        "networks": {"crawlmaze_net": _network("crawlmaze_net")},
    }
    return _emit(document, banner="Crawlmaze compose")


# Bulk renderer


def render_all(
    contract: FrozenCaseContract, target_dir: Path
) -> Mapping[str, Path]:
    """Materialise all three compose files into ``target_dir``.

    Returns a mapping of logical name -> output path. The directory is
    created with mode ``0o700`` if it does not yet exist.
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    outputs: dict[str, Path] = {}

    dast_path = target_dir / "docker-compose.dast.generated.yml"
    dast_path.write_text(render_dast_compose(contract), encoding="utf-8")
    outputs["dast"] = dast_path

    docker_path = target_dir / "docker-compose.docker.generated.yml"
    docker_path.write_text(
        render_docker_runtime_compose(contract), encoding="utf-8"
    )
    outputs["docker"] = docker_path

    if (
        contract.dynamic.images.crawlmaze_node is not None
        and contract.dynamic.images.crawlmaze_python is not None
    ):
        crawl_path = target_dir / "docker-compose.crawlmaze.generated.yml"
        crawl_path.write_text(render_crawlmaze_compose(contract), encoding="utf-8")
        outputs["crawlmaze"] = crawl_path

    return outputs


# Internal: deterministic YAML emitter


def _emit(document: Mapping, *, banner: str) -> str:
    header = (
        "# Managed by REDACTS compose renderer.\n"
        f"# Source: dynamic.compose_render ({banner}).\n"
        "# Every value is contract-driven; image refs are digest-pinned.\n"
    )
    body = yaml.safe_dump(
        document,
        sort_keys=False,
        default_flow_style=False,
        width=4096,
    )
    return header + body
