"""REDACTS - Frozen Case Contract (the single source of truth).

This module is the *only* place in the codebase that reads a configuration
file or makes a runtime-shaping decision based on the environment. Every
other module receives a ``FrozenCaseContract`` instance and reads from it.

Hard rules (each violation is a refusal at startup, exit code 2):

1. The only configuration input accepted is a ``case.toml`` file. There is
   no global config, no ``.env``, no ``.env.config``, no environment-variable
   override of any setting.
2. The parent process refuses to start if any name in
   ``FORBIDDEN_ENV_PREFIXES`` or ``FORBIDDEN_ENV_EXACT`` is present in
   ``os.environ`` at startup. Silent ignoring would itself be a jeopardy
   surface - a poisoned environment must produce a loud refusal.
3. The parent process refuses to start if any of ``./.env``,
   ``./.env.config``, ``<workspace_root>/.env``, ``~/.redacts/.env`` exists.
4. Every container image in ``[dynamic.images]`` must carry a 64-hex
   ``sha256:`` digest. Tag-only references are a parse error.
5. Every credential in ``[dynamic.credentials]`` must be non-empty. Weak
   credentials produce a warning by default; ``--insecure-credentials`` is
   the only flag that downgrades the failure to a warning when the policy
   is set to ``fail``.
6. Re-running over a directory that already contains a ``case.lock.json``
   refuses on *any* drift (strict reproducibility).

Copyright 2024-2026 The Adimension / Shehab Anwer.
Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import string
import tomllib
from dataclasses import dataclass, field, asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


# Constants

SCHEMA_VERSION = 2
"""Top-level ``schema_version`` accepted by this module."""

FORBIDDEN_ENV_PREFIXES: tuple[str, ...] = (
    "REDACTS_",
    "REDCAP_",
    "DAST_",
    "PLAYWRIGHT_",
    "XDEBUG_",
)
"""Environment-variable prefixes refused at parent startup."""

FORBIDDEN_ENV_EXACT: frozenset[str] = frozenset({
    "MYSQL_ROOT_PASSWORD", "MYSQL_DATABASE", "MYSQL_USER", "MYSQL_PASSWORD",
    "MARIADB_ROOT_PASSWORD", "MARIADB_DATABASE", "MARIADB_USER", "MARIADB_PASSWORD",
})
"""Exact environment-variable names refused at parent startup."""

FORBIDDEN_DOTENV_FILES: tuple[str, ...] = (
    ".env",
    ".env.config",
)
"""File names whose presence in any search path refuses startup."""

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NIX_REV_RE = re.compile(r"^[0-9a-f]{40}$")
_PASSWORD_MIN_LENGTH = 16

# Names that *must* be a non-empty string in [dynamic.credentials].
_REQUIRED_CREDENTIAL_FIELDS: tuple[str, ...] = (
    "admin_user",
    "admin_password",
    "admin_email",
    "db_root_password",
    "db_user",
    "db_password",
    "salt",
)


# Errors


class CaseConfigError(ValueError):
    """A configuration error. Distinct from runtime errors so callers can
    map this to exit code 2 (config) rather than 1 (runtime)."""


# Frozen schema dataclasses


@dataclass(frozen=True, slots=True)
class CaseIdentity:
    id: str
    analyst: str
    organization: str
    date: str
    description: str


@dataclass(frozen=True, slots=True)
class PathsConfig:
    workspace_root: Path
    output_root: Path
    temp_root: Path
    cache_root: Path
    tools_root: Path
    logs_root: Path
    audit_trail: Path


@dataclass(frozen=True, slots=True)
class InputArtifact:
    path: Path
    sha256: str  # may be empty for non-local references; required for local files


@dataclass(frozen=True, slots=True)
class InputsConfig:
    target: InputArtifact
    reference: InputArtifact
    upgrade_package: InputArtifact | None


@dataclass(frozen=True, slots=True)
class StaticConfig:
    enabled: bool
    scanners: tuple[str, ...]
    formats: tuple[str, ...]
    severity_gate: str
    max_total_files: int
    parallel_workers: int
    global_timeout_seconds: int


@dataclass(frozen=True, slots=True)
class ImageRef:
    registry: str
    repo: str
    tag: str
    digest: str

    @property
    def full_ref(self) -> str:
        # Pin via digest; tag is preserved for human readability only.
        return f"{self.registry}/{self.repo}@{self.digest}"


@dataclass(frozen=True, slots=True)
class DynamicImages:
    mariadb: ImageRef
    php: ImageRef
    playwright: ImageRef
    sandbox: ImageRef
    crawlmaze_node: ImageRef | None
    crawlmaze_python: ImageRef | None


@dataclass(frozen=True, slots=True)
class DynamicCredentials:
    admin_user: str
    admin_password: str
    admin_email: str
    db_root_password: str
    db_user: str
    db_password: str
    salt: str


@dataclass(frozen=True, slots=True)
class DynamicNetwork:
    base_url: str
    internal_hosts: tuple[str, ...]
    xdebug_mode: str


@dataclass(frozen=True, slots=True)
class PlaywrightConfig:
    chromium_executable: str
    chromium_args: tuple[str, ...]
    node_version: str


@dataclass(frozen=True, slots=True)
class DynamicConfig:
    enabled: bool
    runtime: str  # docker | podman | nix
    suites: tuple[str, ...]
    port: int
    suite_timeout: int
    keep_stack: bool
    stack_only: bool
    images: DynamicImages
    credentials: DynamicCredentials
    network: DynamicNetwork
    playwright: PlaywrightConfig


@dataclass(frozen=True, slots=True)
class HashedSource:
    url: str
    sha256: str


@dataclass(frozen=True, slots=True)
class NvdSource:
    base_url: str
    api_key: str


@dataclass(frozen=True, slots=True)
class ThreatBaseSources:
    cwe: HashedSource
    nvd: NvdSource
    attack_stix: HashedSource
    yara_rules: tuple[HashedSource, ...]


@dataclass(frozen=True, slots=True)
class ThreatBaseConfig:
    offline_mode: bool
    allow_stale: bool
    ttl_hours: int
    sources: ThreatBaseSources


@dataclass(frozen=True, slots=True)
class ToolSpec:
    version: str
    url_template: str
    sha256_table: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class PythonToolSpec:
    version: str


@dataclass(frozen=True, slots=True)
class ToolsConfig:
    trivy: ToolSpec
    yara: ToolSpec
    semgrep: PythonToolSpec
    repomix: PythonToolSpec
    magika: PythonToolSpec


@dataclass(frozen=True, slots=True)
class NixRuntimeConfig:
    flake_ref: str
    nixpkgs_rev: str
    php_attr: str
    mariadb_attr: str
    chromium_attr: str
    playwright_browsers: str


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    network_disabled: bool
    ssrf_allowlist: tuple[str, ...]
    sandbox_drop_caps: tuple[str, ...]
    sandbox_no_new_priv: bool
    sandbox_read_only: bool


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str
    format: str
    retention_days: int
    to_file: bool
    to_stderr: bool


@dataclass(frozen=True, slots=True)
class FrozenCaseContract:
    schema_version: int
    case: CaseIdentity
    paths: PathsConfig
    inputs: InputsConfig
    static: StaticConfig
    dynamic: DynamicConfig
    threat_base: ThreatBaseConfig
    tools: ToolsConfig
    nix: NixRuntimeConfig
    security: SecurityConfig
    logging: LoggingConfig
    # Provenance
    source_path: Path
    source_sha256: str
    loaded_at_utc: str  # ISO-8601


# Top-level loader



def load_and_freeze(
    case_path: Path,
    *,
    env: Mapping[str, str] | None = None,
    dotenv_search_paths: Iterable[Path] | None = None,
    allow_insecure_credentials: bool = False,
    weak_credentials_policy: str = "warn",  # "warn" | "fail"
) -> FrozenCaseContract:
    """Load a ``case.toml``, validate it, scrub the environment, and return
    an immutable contract.

    Args:
        case_path: Path to the ``case.toml`` (or its parent directory).
        env: The environment mapping to scrub. Defaults to ``os.environ``.
            Tests pass an isolated mapping.
        dotenv_search_paths: Where to refuse ``.env`` / ``.env.config`` files.
            Defaults to the case directory, the resolved ``workspace_root``
            (after parsing), and ``~/.redacts``.
        allow_insecure_credentials: If True, weak credentials only warn even
            when ``weak_credentials_policy='fail'``. Empty credentials are
            still a hard failure regardless.
        weak_credentials_policy: ``"warn"`` (default) emits a warning record;
            ``"fail"`` raises ``CaseConfigError`` (unless overridden by
            ``allow_insecure_credentials``).

    Returns:
        A fully validated, immutable ``FrozenCaseContract``.

    Raises:
        CaseConfigError: For any schema, validation, or refusal failure.
        FileNotFoundError: If ``case_path`` does not exist.
    """
    case_path = Path(case_path)
    if case_path.is_dir():
        case_path = case_path / "case.toml"
    if not case_path.is_file():
        raise FileNotFoundError(f"case.toml not found at: {case_path}")

    # 1. Refuse a poisoned environment BEFORE parsing.
    _scrub_env(os.environ if env is None else env)

    # 2. Hash and parse the file.
    raw_bytes = case_path.read_bytes()
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        raw = tomllib.loads(raw_bytes.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise CaseConfigError(f"case.toml: parse error: {exc}") from exc

    # 3. Schema-walk: top-level keys.
    schema_version = raw.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        raise CaseConfigError(
            f"case.toml: schema_version must be {SCHEMA_VERSION}, "
            f"got {schema_version!r}. See `case.example.toml` in the "
            f"repository root for a working template."
        )
    _reject_unknown(raw, _TOP_LEVEL_KEYS, path="<root>")
    _require_keys(
        raw,
        (
            "case", "paths", "inputs", "static", "dynamic",
            "threat_base", "tools", "runtime", "security", "logging",
        ),
        path="<root>",
    )

    case_dir = case_path.parent.resolve()

    # 4. Build sub-configs (each does its own strict validation).
    case_identity = _build_case_identity(raw["case"])
    paths_cfg = _build_paths(raw["paths"], case_dir)
    inputs_cfg = _build_inputs(raw["inputs"], case_dir)
    static_cfg = _build_static(raw["static"])
    dynamic_cfg = _build_dynamic(
        raw["dynamic"],
        weak_credentials_policy=weak_credentials_policy,
        allow_insecure=allow_insecure_credentials,
    )
    threat_cfg = _build_threat_base(raw["threat_base"])
    tools_cfg = _build_tools(raw["tools"])
    nix_cfg = _build_nix(raw["runtime"]["nix"])
    security_cfg = _build_security(raw["security"])
    logging_cfg = _build_logging(raw["logging"])

    # 5. Refuse forbidden dotenv files (only AFTER paths_cfg is known).
    search_paths: list[Path] = list(dotenv_search_paths) if dotenv_search_paths else [
        case_dir,
        paths_cfg.workspace_root,
        Path.home() / ".redacts",
    ]
    _refuse_dotenv_files(search_paths)

    contract = FrozenCaseContract(
        schema_version=SCHEMA_VERSION,
        case=case_identity,
        paths=paths_cfg,
        inputs=inputs_cfg,
        static=static_cfg,
        dynamic=dynamic_cfg,
        threat_base=threat_cfg,
        tools=tools_cfg,
        nix=nix_cfg,
        security=security_cfg,
        logging=logging_cfg,
        source_path=case_path.resolve(),
        source_sha256=source_sha256,
        loaded_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    # 6. Cross-section invariants.
    _validate_cross_section(contract)
    return contract


# Environment scrub & dotenv refusal



def _scrub_env(env: Mapping[str, str]) -> None:
    """Refuse if any forbidden env name is present.

    We do not delete entries: silent removal would itself be deceptive.
    The analyst must clean their shell.
    """
    offenders: list[str] = []
    for name in env:
        if name in FORBIDDEN_ENV_EXACT or name.startswith(FORBIDDEN_ENV_PREFIXES):
            offenders.append(name)
    if offenders:
        offenders_sorted = ", ".join(sorted(offenders))
        raise CaseConfigError(
            "environment-pollution: the following variables must not be set "
            f"when REDACTS starts: {offenders_sorted}. case.toml is the "
            "single source of truth; remove these variables and re-run."
        )


def _refuse_dotenv_files(search_paths: Iterable[Path]) -> None:
    """Refuse if any ``.env`` / ``.env.config`` file exists in search paths."""
    found: list[str] = []
    for base in search_paths:
        try:
            base = Path(base)
        except TypeError:
            continue
        for name in FORBIDDEN_DOTENV_FILES:
            candidate = base / name
            if candidate.is_file():
                found.append(str(candidate))
    if found:
        joined = ", ".join(sorted(set(found)))
        raise CaseConfigError(
            f"dotenv-refusal: forbidden override files present: {joined}. "
            "Delete them; configuration must come exclusively from case.toml."
        )


# Schema walkers



_TOP_LEVEL_KEYS = frozenset({
    "schema_version", "case", "paths", "inputs", "static", "dynamic",
    "threat_base", "tools", "runtime", "security", "logging",
})


def _reject_unknown(section: Mapping[str, Any], allowed: frozenset[str], *, path: str) -> None:
    extra = set(section.keys()) - allowed
    if extra:
        raise CaseConfigError(
            f"case.toml: unknown keys at {path}: {sorted(extra)!r}"
        )


def _require_keys(section: Mapping[str, Any], required: Iterable[str], *, path: str) -> None:
    missing = [k for k in required if k not in section]
    if missing:
        raise CaseConfigError(f"case.toml: {path} missing required keys: {missing!r}")


def _require_str(value: Any, *, path: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise CaseConfigError(f"case.toml: {path} must be a string, got {type(value).__name__}")
    if not allow_empty and not value.strip():
        raise CaseConfigError(f"case.toml: {path} must be a non-empty string")
    return value


def _require_bool(value: Any, *, path: str) -> bool:
    if not isinstance(value, bool):
        raise CaseConfigError(f"case.toml: {path} must be a boolean, got {type(value).__name__}")
    return value


def _require_int(value: Any, *, path: str, minimum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CaseConfigError(f"case.toml: {path} must be an integer")
    if minimum is not None and value < minimum:
        raise CaseConfigError(f"case.toml: {path} must be >= {minimum}, got {value}")
    return value


def _require_str_list(value: Any, *, path: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise CaseConfigError(f"case.toml: {path} must be a list of strings")
    if not allow_empty and not value:
        raise CaseConfigError(f"case.toml: {path} must not be empty")
    return tuple(value)


# -- [case] ----


_CASE_KEYS = frozenset({"id", "analyst", "organization", "date", "description"})


def _build_case_identity(section: Mapping[str, Any]) -> CaseIdentity:
    _reject_unknown(section, _CASE_KEYS, path="[case]")
    _require_keys(section, _CASE_KEYS, path="[case]")
    return CaseIdentity(
        id=_require_str(section["id"], path="[case].id"),
        analyst=_require_str(section["analyst"], path="[case].analyst"),
        organization=_require_str(section["organization"], path="[case].organization"),
        date=_require_str(section["date"], path="[case].date"),
        description=_require_str(section["description"], path="[case].description"),
    )


# -- [paths] --------


_PATHS_KEYS = frozenset({
    "workspace_root", "output_root", "temp_root", "cache_root",
    "tools_root", "logs_root", "audit_trail",
})


def _resolve_path_template(template: str, *, workspace_root: Path, output_root: Path | None) -> Path:
    """Resolve ``{workspace_root}`` and ``{output_root}`` placeholders.

    Forbids any other placeholder (loud refusal of unknown templating).
    """
    formatter = string.Formatter()
    seen_fields = {fname for _, fname, _, _ in formatter.parse(template) if fname}
    allowed = {"workspace_root", "output_root"}
    extras = seen_fields - allowed
    if extras:
        raise CaseConfigError(
            f"case.toml: [paths] unknown placeholder(s) {sorted(extras)!r} in {template!r}"
        )
    if "output_root" in seen_fields and output_root is None:
        raise CaseConfigError(
            "case.toml: [paths] output_root may not reference itself "
            "(template loop)"
        )
    rendered = template.format(
        workspace_root=str(workspace_root),
        output_root=str(output_root) if output_root else "",
    )
    return Path(rendered).resolve()


def _build_paths(section: Mapping[str, Any], case_dir: Path) -> PathsConfig:
    _reject_unknown(section, _PATHS_KEYS, path="[paths]")
    _require_keys(section, ("workspace_root",), path="[paths]")
    workspace_raw = _require_str(section["workspace_root"], path="[paths].workspace_root")
    workspace_path = Path(workspace_raw)
    if not workspace_path.is_absolute():
        workspace_path = (case_dir / workspace_path).resolve()
    else:
        workspace_path = workspace_path.resolve()

    # Defaults if a key is omitted.
    defaults: dict[str, str] = {
        "output_root": "{workspace_root}/output",
        "temp_root": "{workspace_root}/tmp",
        "cache_root": "{workspace_root}/cache",
        "tools_root": "{workspace_root}/tools",
        "logs_root": "{output_root}/logs",
        "audit_trail": "{output_root}/audit-trail",
    }
    # output_root must resolve first (others may reference it).
    output_template = _require_str(
        section.get("output_root", defaults["output_root"]),
        path="[paths].output_root",
    )
    output_root = _resolve_path_template(
        output_template, workspace_root=workspace_path, output_root=None
    )

    def _resolve(key: str) -> Path:
        template = _require_str(section.get(key, defaults[key]), path=f"[paths].{key}")
        return _resolve_path_template(
            template, workspace_root=workspace_path, output_root=output_root
        )

    return PathsConfig(
        workspace_root=workspace_path,
        output_root=output_root,
        temp_root=_resolve("temp_root"),
        cache_root=_resolve("cache_root"),
        tools_root=_resolve("tools_root"),
        logs_root=_resolve("logs_root"),
        audit_trail=_resolve("audit_trail"),
    )


# -- [inputs] ---------


_INPUTS_KEYS = frozenset({"target", "reference", "upgrade_package"})
_INPUT_ARTIFACT_KEYS = frozenset({"path", "sha256"})


def _build_input_artifact(
    section: Mapping[str, Any], *, path_label: str, case_dir: Path
) -> InputArtifact:
    _reject_unknown(section, _INPUT_ARTIFACT_KEYS, path=path_label)
    _require_keys(section, ("path",), path=path_label)
    raw_path = _require_str(section["path"], path=f"{path_label}.path")
    sha256 = section.get("sha256", "")
    sha256 = _require_str(sha256, path=f"{path_label}.sha256", allow_empty=True)

    # Resolve relative paths against the case file.
    p = Path(raw_path)
    if not p.is_absolute() and not raw_path.startswith(("http://", "https://", "ftp://")):
        p = (case_dir / p).resolve()

    is_local = isinstance(p, Path) and not raw_path.startswith(("http://", "https://", "ftp://"))

    # Local-path rule: the file must exist at load time. Refusing here
    # produces a clean exit-2 contract error rather than a phase-time
    # crash that would leave the operator hunting through scan logs.
    if is_local and not p.exists():
        raise CaseConfigError(
            f"case.toml: {path_label}.path does not exist: {p}"
        )

    # Local-file rule: if the file exists locally, the user MUST pin sha256.
    if is_local and p.is_file():
        if not sha256:
            raise CaseConfigError(
                f"case.toml: {path_label}.sha256 is required for local files; "
                f"compute one with `python -c \"import hashlib,sys; "
                f"print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())\" "
                f"{p}`"
            )
        # Verify.
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        if actual.lower() != sha256.lower():
            raise CaseConfigError(
                f"case.toml: {path_label} sha256 mismatch for {p}: "
                f"declared={sha256}, actual={actual}"
            )

    return InputArtifact(path=p, sha256=sha256)


def _build_inputs(section: Mapping[str, Any], case_dir: Path) -> InputsConfig:
    _reject_unknown(section, _INPUTS_KEYS, path="[inputs]")
    _require_keys(section, ("target", "reference"), path="[inputs]")
    target = _build_input_artifact(section["target"], path_label="[inputs.target]", case_dir=case_dir)
    reference = _build_input_artifact(section["reference"], path_label="[inputs.reference]", case_dir=case_dir)
    upgrade_section = section.get("upgrade_package")
    upgrade = (
        _build_input_artifact(upgrade_section, path_label="[inputs.upgrade_package]", case_dir=case_dir)
        if upgrade_section is not None
        else None
    )
    return InputsConfig(target=target, reference=reference, upgrade_package=upgrade)


# -- [static] ---------


_STATIC_KEYS = frozenset({
    "enabled", "scanners", "formats", "severity_gate",
    "max_total_files", "parallel_workers", "global_timeout_seconds",
})

_VALID_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


def _build_static(section: Mapping[str, Any]) -> StaticConfig:
    _reject_unknown(section, _STATIC_KEYS, path="[static]")
    _require_keys(section, _STATIC_KEYS, path="[static]")
    severity = _require_str(section["severity_gate"], path="[static].severity_gate")
    if severity not in _VALID_SEVERITIES:
        raise CaseConfigError(
            f"case.toml: [static].severity_gate must be one of {sorted(_VALID_SEVERITIES)!r}, "
            f"got {severity!r}"
        )
    return StaticConfig(
        enabled=_require_bool(section["enabled"], path="[static].enabled"),
        scanners=_require_str_list(section["scanners"], path="[static].scanners"),
        formats=_require_str_list(section["formats"], path="[static].formats"),
        severity_gate=severity,
        max_total_files=_require_int(section["max_total_files"], path="[static].max_total_files", minimum=1),
        parallel_workers=_require_int(section["parallel_workers"], path="[static].parallel_workers", minimum=1),
        global_timeout_seconds=_require_int(
            section["global_timeout_seconds"],
            path="[static].global_timeout_seconds",
            minimum=1,
        ),
    )


# -- [dynamic]


_DYNAMIC_KEYS = frozenset({
    "enabled", "runtime", "suites", "port", "suite_timeout",
    "keep_stack", "stack_only", "images", "credentials", "network", "playwright",
})
_VALID_RUNTIMES = frozenset({"docker", "podman", "nix"})

_IMAGES_KEYS = frozenset({
    "mariadb", "php", "playwright", "sandbox", "crawlmaze_node", "crawlmaze_python",
})
_IMAGE_REF_KEYS = frozenset({"registry", "repo", "tag", "digest"})

_NETWORK_KEYS = frozenset({"base_url", "internal_hosts", "xdebug_mode"})
_PLAYWRIGHT_KEYS = frozenset({"chromium_executable", "chromium_args", "node_version"})
_CREDS_KEYS = frozenset(_REQUIRED_CREDENTIAL_FIELDS)


def _build_image_ref(section: Mapping[str, Any], *, path_label: str) -> ImageRef:
    _reject_unknown(section, _IMAGE_REF_KEYS, path=path_label)
    _require_keys(section, _IMAGE_REF_KEYS, path=path_label)
    digest = _require_str(section["digest"], path=f"{path_label}.digest")
    if not _DIGEST_RE.match(digest):
        raise CaseConfigError(
            f"case.toml: {path_label}.digest must match 'sha256:<64-hex>', got {digest!r}"
        )
    return ImageRef(
        registry=_require_str(section["registry"], path=f"{path_label}.registry"),
        repo=_require_str(section["repo"], path=f"{path_label}.repo"),
        tag=_require_str(section["tag"], path=f"{path_label}.tag"),
        digest=digest,
    )


def _build_images(section: Mapping[str, Any]) -> DynamicImages:
    _reject_unknown(section, _IMAGES_KEYS, path="[dynamic.images]")
    required = ("mariadb", "php", "playwright", "sandbox")
    _require_keys(section, required, path="[dynamic.images]")
    optional = {
        k: (
            _build_image_ref(section[k], path_label=f"[dynamic.images.{k}]")
            if k in section else None
        )
        for k in ("crawlmaze_node", "crawlmaze_python")
    }
    return DynamicImages(
        mariadb=_build_image_ref(section["mariadb"], path_label="[dynamic.images.mariadb]"),
        php=_build_image_ref(section["php"], path_label="[dynamic.images.php]"),
        playwright=_build_image_ref(section["playwright"], path_label="[dynamic.images.playwright]"),
        sandbox=_build_image_ref(section["sandbox"], path_label="[dynamic.images.sandbox]"),
        crawlmaze_node=optional["crawlmaze_node"],
        crawlmaze_python=optional["crawlmaze_python"],
    )


def _classify_credential_strength(value: str) -> tuple[bool, str]:
    """Return (is_strong, reason)."""
    if len(value) < _PASSWORD_MIN_LENGTH:
        return False, f"length {len(value)} < {_PASSWORD_MIN_LENGTH}"
    classes = (
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    )
    if sum(classes) < 3:
        return False, "fewer than 3 character classes (lower/upper/digit/symbol)"
    return True, ""


def _build_credentials(
    section: Mapping[str, Any],
    *,
    weak_credentials_policy: str,
    allow_insecure: bool,
) -> DynamicCredentials:
    _reject_unknown(section, _CREDS_KEYS, path="[dynamic.credentials]")
    _require_keys(section, _REQUIRED_CREDENTIAL_FIELDS, path="[dynamic.credentials]")

    values: dict[str, str] = {}
    for fname in _REQUIRED_CREDENTIAL_FIELDS:
        values[fname] = _require_str(section[fname], path=f"[dynamic.credentials].{fname}")

    # Strength: only enforce for password-class fields and salt.
    password_fields = ("admin_password", "db_root_password", "db_password", "salt")
    weaknesses: list[str] = []
    for fname in password_fields:
        is_strong, reason = _classify_credential_strength(values[fname])
        if not is_strong:
            weaknesses.append(f"[dynamic.credentials].{fname}: {reason}")
    if weaknesses:
        message = (
            "weak-credentials: " + "; ".join(weaknesses)
            + " (policy=" + weak_credentials_policy
            + (", insecure-override" if allow_insecure else "")
            + ")"
        )
        if weak_credentials_policy == "fail" and not allow_insecure:
            raise CaseConfigError(message)
        # Surface as a warning record on the contract via logging at module
        # boundary; here we just emit via the std logging.
        import logging as _logging
        _logging.getLogger(__name__).warning(message)

    return DynamicCredentials(**values)


def _build_network(section: Mapping[str, Any]) -> DynamicNetwork:
    _reject_unknown(section, _NETWORK_KEYS, path="[dynamic.network]")
    _require_keys(section, _NETWORK_KEYS, path="[dynamic.network]")
    return DynamicNetwork(
        base_url=_require_str(section["base_url"], path="[dynamic.network].base_url"),
        internal_hosts=_require_str_list(
            section["internal_hosts"], path="[dynamic.network].internal_hosts"
        ),
        xdebug_mode=_require_str(section["xdebug_mode"], path="[dynamic.network].xdebug_mode"),
    )


def _build_playwright(section: Mapping[str, Any]) -> PlaywrightConfig:
    _reject_unknown(section, _PLAYWRIGHT_KEYS, path="[dynamic.playwright]")
    _require_keys(section, _PLAYWRIGHT_KEYS, path="[dynamic.playwright]")
    args = section["chromium_args"]
    if not isinstance(args, list) or not all(isinstance(v, str) for v in args):
        raise CaseConfigError("case.toml: [dynamic.playwright].chromium_args must be a list of strings")
    return PlaywrightConfig(
        chromium_executable=_require_str(
            section["chromium_executable"],
            path="[dynamic.playwright].chromium_executable",
            allow_empty=True,
        ),
        chromium_args=tuple(args),
        node_version=_require_str(section["node_version"], path="[dynamic.playwright].node_version"),
    )


def _build_dynamic(
    section: Mapping[str, Any],
    *,
    weak_credentials_policy: str,
    allow_insecure: bool,
) -> DynamicConfig:
    _reject_unknown(section, _DYNAMIC_KEYS, path="[dynamic]")
    _require_keys(section, _DYNAMIC_KEYS, path="[dynamic]")
    runtime = _require_str(section["runtime"], path="[dynamic].runtime")
    if runtime not in _VALID_RUNTIMES:
        raise CaseConfigError(
            f"case.toml: [dynamic].runtime must be one of {sorted(_VALID_RUNTIMES)!r}, got {runtime!r}"
        )
    return DynamicConfig(
        enabled=_require_bool(section["enabled"], path="[dynamic].enabled"),
        runtime=runtime,
        suites=_require_str_list(section["suites"], path="[dynamic].suites"),
        port=_require_int(section["port"], path="[dynamic].port", minimum=1),
        suite_timeout=_require_int(section["suite_timeout"], path="[dynamic].suite_timeout", minimum=1),
        keep_stack=_require_bool(section["keep_stack"], path="[dynamic].keep_stack"),
        stack_only=_require_bool(section["stack_only"], path="[dynamic].stack_only"),
        images=_build_images(section["images"]),
        credentials=_build_credentials(
            section["credentials"],
            weak_credentials_policy=weak_credentials_policy,
            allow_insecure=allow_insecure,
        ),
        network=_build_network(section["network"]),
        playwright=_build_playwright(section["playwright"]),
    )


# -- [threat_base] ----


_THREAT_KEYS = frozenset({"offline_mode", "allow_stale", "ttl_hours", "sources"})
_THREAT_SOURCES_KEYS = frozenset({"cwe", "nvd", "attack_stix", "yara_rules"})
_HASHED_SOURCE_KEYS = frozenset({"url", "sha256"})
_NVD_SOURCE_KEYS = frozenset({"base_url", "api_key"})


def _build_hashed_source(section: Mapping[str, Any], *, path_label: str) -> HashedSource:
    _reject_unknown(section, _HASHED_SOURCE_KEYS, path=path_label)
    _require_keys(section, ("url",), path=path_label)
    return HashedSource(
        url=_require_str(section["url"], path=f"{path_label}.url"),
        sha256=_require_str(section.get("sha256", ""), path=f"{path_label}.sha256", allow_empty=True),
    )


def _build_threat_base(section: Mapping[str, Any]) -> ThreatBaseConfig:
    _reject_unknown(section, _THREAT_KEYS, path="[threat_base]")
    _require_keys(section, _THREAT_KEYS, path="[threat_base]")
    sources = section["sources"]
    _reject_unknown(sources, _THREAT_SOURCES_KEYS, path="[threat_base.sources]")
    _require_keys(sources, _THREAT_SOURCES_KEYS, path="[threat_base.sources]")

    nvd_section = sources["nvd"]
    _reject_unknown(nvd_section, _NVD_SOURCE_KEYS, path="[threat_base.sources.nvd]")
    _require_keys(nvd_section, ("base_url",), path="[threat_base.sources.nvd]")

    yara_raw = sources["yara_rules"]
    if not isinstance(yara_raw, list):
        raise CaseConfigError("case.toml: [threat_base.sources.yara_rules] must be a list")
    yara_rules = tuple(
        _build_hashed_source(item, path_label=f"[threat_base.sources.yara_rules][{i}]")
        for i, item in enumerate(yara_raw)
    )

    return ThreatBaseConfig(
        offline_mode=_require_bool(section["offline_mode"], path="[threat_base].offline_mode"),
        allow_stale=_require_bool(section["allow_stale"], path="[threat_base].allow_stale"),
        ttl_hours=_require_int(section["ttl_hours"], path="[threat_base].ttl_hours", minimum=0),
        sources=ThreatBaseSources(
            cwe=_build_hashed_source(sources["cwe"], path_label="[threat_base.sources.cwe]"),
            nvd=NvdSource(
                base_url=_require_str(nvd_section["base_url"], path="[threat_base.sources.nvd].base_url"),
                api_key=_require_str(
                    nvd_section.get("api_key", ""),
                    path="[threat_base.sources.nvd].api_key",
                    allow_empty=True,
                ),
            ),
            attack_stix=_build_hashed_source(sources["attack_stix"], path_label="[threat_base.sources.attack_stix]"),
            yara_rules=yara_rules,
        ),
    )


# -- [tools] ----------


_TOOLS_KEYS = frozenset({"trivy", "yara", "semgrep", "repomix", "magika"})
_TOOL_SPEC_KEYS = frozenset({"version", "url_template", "sha256_table"})
_PYTHON_TOOL_KEYS = frozenset({"version"})


def _build_tool_spec(section: Mapping[str, Any], *, path_label: str) -> ToolSpec:
    _reject_unknown(section, _TOOL_SPEC_KEYS, path=path_label)
    _require_keys(section, _TOOL_SPEC_KEYS, path=path_label)
    table = section["sha256_table"]
    if not isinstance(table, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in table.items()
    ):
        raise CaseConfigError(f"case.toml: {path_label}.sha256_table must be a {{string: string}} table")
    return ToolSpec(
        version=_require_str(section["version"], path=f"{path_label}.version"),
        url_template=_require_str(section["url_template"], path=f"{path_label}.url_template"),
        sha256_table=dict(table),
    )


def _build_python_tool(section: Mapping[str, Any], *, path_label: str) -> PythonToolSpec:
    _reject_unknown(section, _PYTHON_TOOL_KEYS, path=path_label)
    _require_keys(section, _PYTHON_TOOL_KEYS, path=path_label)
    return PythonToolSpec(version=_require_str(section["version"], path=f"{path_label}.version"))


def _build_tools(section: Mapping[str, Any]) -> ToolsConfig:
    _reject_unknown(section, _TOOLS_KEYS, path="[tools]")
    _require_keys(section, _TOOLS_KEYS, path="[tools]")
    return ToolsConfig(
        trivy=_build_tool_spec(section["trivy"], path_label="[tools.trivy]"),
        yara=_build_tool_spec(section["yara"], path_label="[tools.yara]"),
        semgrep=_build_python_tool(section["semgrep"], path_label="[tools.semgrep]"),
        repomix=_build_python_tool(section["repomix"], path_label="[tools.repomix]"),
        magika=_build_python_tool(section["magika"], path_label="[tools.magika]"),
    )


# -- [runtime.nix] ----


_NIX_KEYS = frozenset({
    "flake_ref", "nixpkgs_rev", "php_attr", "mariadb_attr",
    "chromium_attr", "playwright_browsers",
})


def _build_nix(section: Mapping[str, Any]) -> NixRuntimeConfig:
    _reject_unknown(section, _NIX_KEYS, path="[runtime.nix]")
    _require_keys(section, _NIX_KEYS, path="[runtime.nix]")
    rev = _require_str(section["nixpkgs_rev"], path="[runtime.nix].nixpkgs_rev")
    if not _NIX_REV_RE.match(rev):
        raise CaseConfigError(
            f"case.toml: [runtime.nix].nixpkgs_rev must be a 40-hex commit SHA, got {rev!r}"
        )
    return NixRuntimeConfig(
        flake_ref=_require_str(section["flake_ref"], path="[runtime.nix].flake_ref"),
        nixpkgs_rev=rev,
        php_attr=_require_str(section["php_attr"], path="[runtime.nix].php_attr"),
        mariadb_attr=_require_str(section["mariadb_attr"], path="[runtime.nix].mariadb_attr"),
        chromium_attr=_require_str(section["chromium_attr"], path="[runtime.nix].chromium_attr"),
        playwright_browsers=_require_str(
            section["playwright_browsers"], path="[runtime.nix].playwright_browsers"
        ),
    )


# -- [security] -------


_SECURITY_KEYS = frozenset({
    "network_disabled", "ssrf_allowlist", "sandbox_drop_caps",
    "sandbox_no_new_priv", "sandbox_read_only",
})


def _build_security(section: Mapping[str, Any]) -> SecurityConfig:
    _reject_unknown(section, _SECURITY_KEYS, path="[security]")
    _require_keys(section, _SECURITY_KEYS, path="[security]")
    return SecurityConfig(
        network_disabled=_require_bool(section["network_disabled"], path="[security].network_disabled"),
        ssrf_allowlist=_require_str_list(
            section["ssrf_allowlist"], path="[security].ssrf_allowlist", allow_empty=True
        ),
        sandbox_drop_caps=_require_str_list(
            section["sandbox_drop_caps"], path="[security].sandbox_drop_caps", allow_empty=True
        ),
        sandbox_no_new_priv=_require_bool(
            section["sandbox_no_new_priv"], path="[security].sandbox_no_new_priv"
        ),
        sandbox_read_only=_require_bool(
            section["sandbox_read_only"], path="[security].sandbox_read_only"
        ),
    )


# -- [logging] --------


_LOGGING_KEYS = frozenset({"level", "format", "retention_days", "to_file", "to_stderr"})
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_VALID_LOG_FORMATS = frozenset({"json", "text"})


def _build_logging(section: Mapping[str, Any]) -> LoggingConfig:
    _reject_unknown(section, _LOGGING_KEYS, path="[logging]")
    _require_keys(section, _LOGGING_KEYS, path="[logging]")
    level = _require_str(section["level"], path="[logging].level")
    if level not in _VALID_LOG_LEVELS:
        raise CaseConfigError(
            f"case.toml: [logging].level must be one of {sorted(_VALID_LOG_LEVELS)!r}, got {level!r}"
        )
    fmt = _require_str(section["format"], path="[logging].format")
    if fmt not in _VALID_LOG_FORMATS:
        raise CaseConfigError(
            f"case.toml: [logging].format must be one of {sorted(_VALID_LOG_FORMATS)!r}, got {fmt!r}"
        )
    return LoggingConfig(
        level=level,
        format=fmt,
        retention_days=_require_int(section["retention_days"], path="[logging].retention_days", minimum=0),
        to_file=_require_bool(section["to_file"], path="[logging].to_file"),
        to_stderr=_require_bool(section["to_stderr"], path="[logging].to_stderr"),
    )


# -- Cross-section invariants -----------


def _validate_cross_section(c: FrozenCaseContract) -> None:
    """Invariants that span multiple sections."""
    # SSRF allowlist must contain every URL host the contract references.
    referenced_urls: list[str] = [
        c.threat_base.sources.cwe.url,
        c.threat_base.sources.nvd.base_url,
        c.threat_base.sources.attack_stix.url,
        c.tools.trivy.url_template,
        c.tools.yara.url_template,
    ] + [s.url for s in c.threat_base.sources.yara_rules]

    from urllib.parse import urlparse

    allow = {h.lower() for h in c.security.ssrf_allowlist}
    bad: list[str] = []
    for url in referenced_urls:
        host = urlparse(url).hostname or ""
        # Skip placeholders inside url_templates ({version}, {os}, {arch}).
        if "{" in host or not host:
            # Replace the {...} parts with a literal to extract the host.
            cleaned = re.sub(r"\{[^}]+\}", "x", url)
            host = urlparse(cleaned).hostname or ""
        if host and host.lower() not in allow:
            bad.append(f"{url} (host={host})")
    if bad:
        raise CaseConfigError(
            "ssrf-allowlist: the following URLs reference hosts not in "
            f"[security].ssrf_allowlist: {bad!r}"
        )

    # Nix runtime requires nix attrs (already validated); if runtime != nix
    # we don't *require* nix to be sensible, but we still validated it.
    if c.dynamic.runtime == "nix" and not c.nix.nixpkgs_rev:
        raise CaseConfigError(
            "case.toml: [dynamic].runtime is 'nix' but [runtime.nix].nixpkgs_rev is empty"
        )


# Lockfile (strict reproducibility)



_LOCKFILE_NAME = "case.lock.json"


def _to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    return obj


def _serialize_contract(contract: FrozenCaseContract) -> str:
    """Deterministic JSON serialization (sorted keys, fixed separators)."""
    payload = _to_jsonable(contract)
    # Strip volatile fields from the *comparison* surface; record them separately.
    volatile = {"loaded_at_utc"}
    stable = {k: v for k, v in payload.items() if k not in volatile}
    return json.dumps(
        {"stable": stable, "loaded_at_utc": payload["loaded_at_utc"]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def write_lockfile(contract: FrozenCaseContract, lockfile_path: Path) -> None:
    """Write ``case.lock.json`` deterministically."""
    lockfile_path = Path(lockfile_path)
    lockfile_path.parent.mkdir(parents=True, exist_ok=True)
    lockfile_path.write_text(_serialize_contract(contract), encoding="utf-8")


def verify_lockfile(contract: FrozenCaseContract, lockfile_path: Path) -> None:
    """Refuse if any drift is detected against an existing lockfile.

    Strict policy (per project decision): any byte-level change in the
    stable surface is a refusal.
    """
    lockfile_path = Path(lockfile_path)
    if not lockfile_path.is_file():
        return
    existing = lockfile_path.read_text(encoding="utf-8")
    fresh = _serialize_contract(contract)

    existing_stable = json.loads(existing).get("stable")
    fresh_stable = json.loads(fresh).get("stable")
    if existing_stable != fresh_stable:
        raise CaseConfigError(
            f"lockfile-drift: {lockfile_path} disagrees with the current "
            "case.toml; strict reproducibility is enforced. Either revert "
            "the case.toml or delete the lockfile (and the run dir) and "
            "start a new scan."
        )


__all__ = [
    "SCHEMA_VERSION",
    "FORBIDDEN_ENV_PREFIXES",
    "FORBIDDEN_ENV_EXACT",
    "FORBIDDEN_DOTENV_FILES",
    "CaseConfigError",
    "FrozenCaseContract",
    "CaseIdentity",
    "PathsConfig",
    "InputArtifact",
    "InputsConfig",
    "StaticConfig",
    "ImageRef",
    "DynamicImages",
    "DynamicCredentials",
    "DynamicNetwork",
    "PlaywrightConfig",
    "DynamicConfig",
    "HashedSource",
    "NvdSource",
    "ThreatBaseSources",
    "ThreatBaseConfig",
    "ToolSpec",
    "PythonToolSpec",
    "ToolsConfig",
    "NixRuntimeConfig",
    "SecurityConfig",
    "LoggingConfig",
    "load_and_freeze",
    "write_lockfile",
    "verify_lockfile",
]
