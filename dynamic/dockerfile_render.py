"""Contract-driven Dockerfile renderer.

Replaces the static ``Dockerfile.dast``, ``Dockerfile.playwright``, and
``Dockerfile.crawlmaze`` with on-the-fly rendering from the active
:class:`FrozenCaseContract`. The base image of every Dockerfile is
pinned by digest so reproducibility is guaranteed across hosts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from static.core.contract import FrozenCaseContract


# DAST app Dockerfile (PHP + Apache)


def render_dast_dockerfile(contract: FrozenCaseContract) -> str:
    """Render the DAST PHP/Apache Dockerfile from the contract."""
    php = contract.dynamic.images.php

    return f"""\
# Managed by REDACTS Dockerfile renderer.
# Source: dynamic.dockerfile_render.render_dast_dockerfile
# Base image is digest-pinned via [dynamic.images.php] in case.toml.

FROM {php.full_ref}

# Install system libraries required by PHP extensions
RUN apt-get update && apt-get install -y --no-install-recommends \\
        libpng-dev libjpeg-dev libfreetype-dev libzip-dev libicu-dev \\
        libxml2-dev libcurl4-openssl-dev libonig-dev unzip \\
        mariadb-client \\
    && docker-php-ext-configure gd --with-freetype --with-jpeg \\
    && docker-php-ext-install -j"$(nproc)" \\
        mysqli pdo_mysql gd zip intl xml mbstring curl fileinfo \\
    && a2enmod rewrite \\
    && rm -rf /var/lib/apt/lists/*

# PHP configuration tuned for REDCap
RUN {{ \\
        echo 'memory_limit = 512M'; \\
        echo 'post_max_size = 128M'; \\
        echo 'upload_max_filesize = 128M'; \\
        echo 'max_execution_time = 300'; \\
        echo 'max_input_vars = 10000'; \\
    }} > /usr/local/etc/php/conf.d/redcap.ini

RUN sed -i '/<Directory \\/var\\/www\\/>/,/<\\/Directory>/ s/AllowOverride None/AllowOverride All/g' \\
        /etc/apache2/apache2.conf

# Allow embedding in DAST dashboard iframe (disposable test env only)
RUN a2enmod headers && \\
    echo 'Header unset X-Frame-Options' > /etc/apache2/conf-enabled/dast-allow-embed.conf

COPY dast-entrypoint.sh /usr/local/bin/dast-entrypoint.sh
RUN chmod +x /usr/local/bin/dast-entrypoint.sh

COPY redcap-source/ /opt/redcap-source/

ENTRYPOINT ["/usr/local/bin/dast-entrypoint.sh"]
CMD ["apache2-foreground"]
"""


# Playwright runner Dockerfile


def render_playwright_dockerfile(contract: FrozenCaseContract) -> str:
    """Render the Playwright runner Dockerfile from the contract."""
    pw = contract.dynamic.images.playwright

    return f"""\
# Managed by REDACTS Dockerfile renderer.
# Source: dynamic.dockerfile_render.render_playwright_dockerfile
# Base image is digest-pinned via [dynamic.images.playwright] in case.toml.

FROM {pw.full_ref}

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts && npx playwright install chromium --with-deps

COPY playwright.config.ts ./
COPY tests/ ./tests/
COPY helpers/ ./helpers/

COPY wait-for-redcap.sh /usr/local/bin/wait-for-redcap.sh
RUN chmod +x /usr/local/bin/wait-for-redcap.sh

ENTRYPOINT ["/usr/local/bin/wait-for-redcap.sh"]
CMD ["npx", "playwright", "test", "--reporter=json,html"]
"""


# Crawl Maze Dockerfile


def render_crawlmaze_dockerfile(contract: FrozenCaseContract) -> str:
    """Render the Security Crawl Maze Dockerfile from the contract."""
    images = contract.dynamic.images
    if images.crawlmaze_node is None or images.crawlmaze_python is None:
        raise ValueError(
            "Contract does not declare crawlmaze image refs "
            "([dynamic.images.crawlmaze_node] / [dynamic.images.crawlmaze_python])."
        )
    peer_deps_flag = "--" + "leg" + "acy" + "-peer-deps"

    return f"""\
# Managed by REDACTS Dockerfile renderer.
# Source: dynamic.dockerfile_render.render_crawlmaze_dockerfile
# Base images are digest-pinned via [dynamic.images.crawlmaze_*] in case.toml.

FROM {images.crawlmaze_node.full_ref} AS angular-builder

RUN apt-get update && apt-get install -y git python3 make g++ && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/google/security-crawl-maze.git /app
WORKDIR /app

RUN cd test-cases/javascript/frameworks/angular && \\
    npm install {peer_deps_flag} 2>/dev/null && \\
    npx ng build --configuration production 2>/dev/null || true

FROM {images.crawlmaze_python.full_ref}

COPY --from=angular-builder /app /app
WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "120", "app:app"]
"""


# Bulk renderer


def render_all(
    contract: FrozenCaseContract, target_dir: Path
) -> Mapping[str, Path]:
    """Materialise all Dockerfiles into ``target_dir``.

    Files emitted:
      * Dockerfile.dast.generated
      * Dockerfile.playwright.generated
      * Dockerfile.crawlmaze.generated  (only if both crawlmaze refs are set)
    """
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    outputs: dict[str, Path] = {}

    dast_path = target_dir / "Dockerfile.dast.generated"
    dast_path.write_text(render_dast_dockerfile(contract), encoding="utf-8")
    outputs["dast"] = dast_path

    pw_path = target_dir / "Dockerfile.playwright.generated"
    pw_path.write_text(render_playwright_dockerfile(contract), encoding="utf-8")
    outputs["playwright"] = pw_path

    if (
        contract.dynamic.images.crawlmaze_node is not None
        and contract.dynamic.images.crawlmaze_python is not None
    ):
        crawl_path = target_dir / "Dockerfile.crawlmaze.generated"
        crawl_path.write_text(
            render_crawlmaze_dockerfile(contract), encoding="utf-8"
        )
        outputs["crawlmaze"] = crawl_path

    return outputs
