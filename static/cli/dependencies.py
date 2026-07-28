"""
REDACTS Dependency Detection - Single Source of Truth.

Two tiers (BLOCK / WARN):
    BLOCK - Python packages (pip) that the scan CANNOT run without.
    WARN  - External binaries (Trivy, YARA, Docker, Node.js)
            that enhance coverage.  Missing WARN-tier tools are
            recorded as "REDUCED COVERAGE" in the final report.

Two registries declared here are the canonical inventory consumed by
*every* downstream code path:

* :data:`PYTHON_PACKAGES` - drives ``pip`` auto-install and preflight
  Layer 2. Kept in sync by hand with ``requirements.txt`` and the
  ``[project.dependencies]`` table in ``pyproject.toml``.
* :data:`SYSTEM_TOOLS` - drives Trivy/YARA download and preflight
  Layer 4.

There is intentionally **no second list** anywhere in the codebase; the
CLI and scan workflow both derive from these two tuples.

Called at startup before any analysis runs.
"""

from __future__ import annotations

import importlib
import logging
import subprocess
import sys
from dataclasses import dataclass, field

from ..core.subprocess_env import resolve_and_wrap_cmd

logger = logging.getLogger(__name__)


class DependencyError(RuntimeError):
    """Raised when a required dependency is missing or broken."""


@dataclass
class DependencyStatus:
    """Result of a single dependency check."""

    name: str
    available: bool
    required: bool
    version: str = ""
    error: str = ""
    install_cmd: str = ""
    install_url: str = ""
    description: str = ""
    category: str = "python"  # "python" | "system" | "optional"

    @property
    def ok(self) -> bool:
        return self.available or not self.required


@dataclass
class DependencyReport:
    """Aggregated dependency-check results."""

    checks: list[DependencyStatus] = field(default_factory=list)
    python_version: str = ""
    docker_available: bool = False
    docker_compose_available: bool = False

    @property
    def all_required_ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def missing_required(self) -> list[DependencyStatus]:
        return [c for c in self.checks if c.required and not c.available]

    @property
    def missing_python(self) -> list[DependencyStatus]:
        return [
            c for c in self.checks
            if not c.available and c.category == "python"
        ]

    @property
    def missing_system(self) -> list[DependencyStatus]:
        return [
            c for c in self.checks
            if not c.available and c.required and c.category == "system"
        ]

    @property
    def missing_optional(self) -> list[DependencyStatus]:
        return [c for c in self.checks if not c.required and not c.available]

    def summary(self) -> str:
        ok = sum(1 for c in self.checks if c.available)
        total = len(self.checks)
        lines = [f"Dependencies: {ok}/{total} available"]
        for m in self.missing_required:
            lines.append(f"  MISSING (required): {m.name} - {m.error}")
        for m in self.missing_optional:
            lines.append(f"  MISSING (optional): {m.name} - {m.error}")
        return "\n".join(lines)


# (import_name, pip_name, required, min_version, description)
#
# This list is the canonical inventory for preflight checks and
# pip auto-install. ``requirements.txt`` and the
# ``[project.dependencies]`` table in ``pyproject.toml`` mirror it
# by hand; keep all three in lock-step.
#   * preflight.py    -> Layer 2 BLOCK checks (required=True only)
#   * auto_install.py -> ``pip install`` calls
PYTHON_PACKAGES: list[tuple[str, str, bool, str, str]] = [
    ("chardet", "chardet", True, "5.0.0",
     "Character encoding detection"),
    ("magika", "magika", True, "0.6.0",
     "AI-powered file type detection (Google) - routing intelligence"),
    ("paramiko", "paramiko", True, "3.4.0",
     "SSH/SFTP for remote loaders"),
    ("requests", "requests", True, "2.31.0",
     "HTTP client for loaders and community rule downloads"),
    ("py7zr", "py7zr", True, "0.20.0",
     "7-Zip archive extraction"),
    ("rarfile", "rarfile", True, "4.1",
     "RAR archive extraction"),
    ("rich", "rich", True, "13.0.0",
     "Terminal formatting - progress bars, tables, panels"),
    ("yaml", "pyyaml", True, "6.0",
     "YAML config file parsing"),
    ("tree_sitter", "tree-sitter", True, "0.23.0",
     "AST parsing engine - accurate PHP code analysis"),
    ("tree_sitter_php", "tree-sitter-php", True, "0.23.0",
     "PHP grammar for tree-sitter AST parser"),
    ("stix2", "stix2", True, "3.0.0",
     "STIX 2.1 parsing for ATT&CK knowledge base"),
    # Semgrep Python wrapper is BLOCK-tier; binary runtime is WARN (graceful degradation)
    ("semgrep", "semgrep", True, "1.0.0",
     "AST-based PHP security scanner - primary vulnerability detection"),
    ("repomix", "repomix", True, "0.5.0",
     "Compressed codebase representation for analyst review (Python package)"),
    ("playwright", "playwright", True, "1.51.0",
     "Browser automation for DAST (dynamic analysis)"),
    ("pytest_asyncio", "pytest-asyncio", True, "0.24.0",
     "Async test support for DAST Playwright suites"),
    ("keyring", "keyring", False, "25.0.0",
     "OS-native credential store (Windows Credential Manager / macOS Keychain / Linux Secret Service)"),
]

_SYSTEM_TOOLS: list[dict] = [
    {
        "name": "trivy",
        "binary": "trivy",
        "required": True,
        "description": "Dependency CVE scanner + secret detection",
        "install_cmd": "winget install AquaSecurity.Trivy --source winget (Windows) or brew install trivy (macOS/Linux)",
        "install_cmd_win": "winget install AquaSecurity.Trivy --source winget",
        "install_cmd_posix": "brew install trivy or apt install trivy",
        "install_url": "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
        "auto_install": False,
    },
    {
        "name": "yara",
        "binary": "yara",
        "required": True,
        "description": "Malware signature matching with community rules",
        "install_cmd": "winget install YARA.YARA --source winget (Windows) or brew install yara (macOS/Linux)",
        "install_cmd_win": "winget install YARA.YARA --source winget",
        "install_cmd_posix": "brew install yara or apt install yara",
        "install_url": "https://yara.readthedocs.io/en/stable/gettingstarted.html",
        "auto_install": False,
    },
    {
        "name": "semgrep",
        "binary": "semgrep",
        "required": True,
        "description": "AST-based PHP security scanner - primary vulnerability detection binary",
        "install_cmd": "pip install semgrep",
        "install_cmd_win": "pip install semgrep",
        "install_cmd_posix": "pip install semgrep or brew install semgrep",
        "install_url": "https://semgrep.dev/docs/getting-started/",
        "auto_install": False,
    },
    # Repomix is a Python dependency (see PYTHON_PACKAGES), not an external
    # binary. Node.js and npx were only ever needed to run the old Node-based
    # repomix on the host - the Python package removed that need. Playwright
    # (DAST) uses its own bundled Node via ``python -m playwright``, and the
    # DAST container builds its own Node inside Docker, so neither requires a
    # host Node.js.
    {
        "name": "docker",
        "binary": "docker",
        "required": True,
        # DAST-only: never invoked by a static scan. Preflight treats this as a
        # BLOCK only when the case enables dynamic analysis
        # ([dynamic].enabled = true); a static-only run degrades it to WARN so
        # an analyst without Docker is not blocked for a tool their scan never
        # calls. See run_preflight(dynamic_enabled=...).
        "dast_only": True,
        "description": "Required for DAST (dynamic application security testing)",
        "install_cmd": "Install Docker Desktop from https://docker.com",
        "install_cmd_win": "winget install Docker.DockerDesktop --source winget or download from https://docker.com",
        "install_cmd_posix": "Install Docker Desktop from https://docker.com or brew install --cask docker / apt install docker.io",
        "install_url": "https://docs.docker.com/get-docker/",
    },
]


# Public and private spellings of each registry refer to the same list
# object so all importers see identical contents.
_PYTHON_PACKAGES = PYTHON_PACKAGES
SYSTEM_TOOLS = _SYSTEM_TOOLS


def pip_install_spec(import_name: str, pip_name: str, min_version: str) -> str:
    """Return the canonical ``pip install`` argument for one package.

    Used by both ``auto_install_python`` and ``requirements.txt``
    generation so the version pin string matches in every channel.
    """
    return f"{pip_name}>={min_version}" if min_version else pip_name


def fix_hint_for_python(pip_name: str, min_version: str) -> str:
    """Operator-facing remediation message for a missing Python package."""
    return f"pip install {pip_install_spec(pip_name, pip_name, min_version)}"


def fix_hint_for_tool(tool: dict) -> str:
    """Operator-facing remediation message for a missing system tool.

    Returns platform-specific installation instructions (Windows vs Linux/macOS).
    """
    is_win = sys.platform == "win32"
    if is_win and tool.get("install_cmd_win"):
        return tool["install_cmd_win"]
    elif not is_win and tool.get("install_cmd_posix"):
        return tool["install_cmd_posix"]

    cmd = (tool.get("install_cmd") or "").strip()
    if cmd:
        return cmd

    url = (tool.get("install_url") or "").strip()
    if url:
        return f"see {url}"

    binary = tool.get("binary", tool.get("name", "tool"))
    if is_win:
        return f"install '{binary}' on PATH or winget install {binary}"
    else:
        return f"install '{binary}' on PATH via your package manager (brew/apt)"


def requirements_lines(*, include_optional: bool = True) -> list[str]:
    """Render ``PYTHON_PACKAGES`` as ``requirements.txt`` lines.

    Used by tests to assert that the on-disk ``requirements.txt``
    matches the in-code registry.
    """
    out: list[str] = []
    for import_name, pip_name, required, min_version, _desc in PYTHON_PACKAGES:
        if not required and not include_optional:
            continue
        out.append(pip_install_spec(import_name, pip_name, min_version))
    return out


def _check_python_package(
    import_name: str,
    pip_name: str,
    required: bool,
    min_version: str,
    description: str,
) -> DependencyStatus:
    """Check whether a Python package is importable."""
    install_hint = fix_hint_for_python(pip_name, min_version)
    try:
        mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", getattr(mod, "VERSION", ""))
        if isinstance(version, tuple):
            version = ".".join(str(v) for v in version)
        return DependencyStatus(
            name=pip_name,
            available=True,
            required=required,
            version=str(version),
            description=description,
            category="python",
            install_cmd=install_hint,
        )
    except ImportError:
        return DependencyStatus(
            name=pip_name,
            available=False,
            required=required,
            error=f"Not installed. Fix: {install_hint}",
            description=description,
            category="python",
            install_cmd=install_hint,
        )
    except Exception as exc:
        return DependencyStatus(
            name=pip_name,
            available=False,
            required=required,
            error=f"Import error: {exc}",
            description=description,
            category="python",
            install_cmd=install_hint,
        )


def _tool_is_required(tool: dict) -> bool:
    """Effective requiredness for *tool*, accounting for DAST-only tools.

    A tool marked ``dast_only`` (currently Docker) is only genuinely required
    when the case enables dynamic analysis. Without this, a static-only
    workflow calling ``check_dependencies()`` with the default
    ``fail_on_missing=True`` would raise for a tool the scan never invokes -
    contradicting the documented "Docker is required only for dynamic (DAST)
    mode" behaviour that preflight already implements via
    ``run_preflight(dynamic_enabled=...)``.
    """
    if not tool.get("required"):
        return False
    if not tool.get("dast_only"):
        return True

    try:
        from ..core import runtime_context

        contract = runtime_context.get_optional_contract()
        # No contract installed -> assume static-only, the safer default for a
        # bare `check_dependencies()` call.
        return bool(contract is not None and contract.dynamic.enabled)
    except Exception:  # pragma: no cover - defensive; partial/absent contract
        return False


def _check_system_tool(tool: dict) -> DependencyStatus:
    """Check whether a system tool binary is available on PATH or in _TOOLS_DIR.

    Delegates binary resolution to the canonical ``_resolve_venv_tool``
    in ``scanners.external`` - which checks PATH, venv Scripts, and
    the managed ``~/.redacts/tools/`` directory.
    """
    from ..scanners.external import _resolve_venv_tool

    binary = tool["binary"]
    path = _resolve_venv_tool(binary)
    target = path or binary

    required = _tool_is_required(tool)
    hint = fix_hint_for_tool(tool)

    if path:
        version = ""
        try:
            proc = subprocess.run(
                resolve_and_wrap_cmd([target, "--version"]),
                capture_output=True,
                text=True,
                timeout=10,
            )
            version = (proc.stdout or proc.stderr).strip().split("\n")[0][:80]
        except Exception:
            version = "found"

        return DependencyStatus(
            name=tool["name"],
            available=True,
            required=required,
            version=version,
            description=tool["description"],
            category="system",
            install_cmd=hint,
            install_url=tool.get("install_url", ""),
        )

    return DependencyStatus(
        name=tool["name"],
        available=False,
        required=required,
        error=f"'{binary}' not found in PATH. Fix: {hint}",
        description=tool["description"],
        category="system",
        install_cmd=hint,
        install_url=tool.get("install_url", ""),
    )


def _check_docker_compose() -> bool:
    """Check if docker compose (v2) is available."""
    try:
        proc = subprocess.run(
            resolve_and_wrap_cmd(["docker", "compose", "version"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_dependencies(
    include_optional_tools: bool = True,
    fail_on_missing: bool = True,
) -> DependencyReport:
    """
    Validate all REDACTS dependencies and return a report.

    Args:
        include_optional_tools: Also check optional external CLI tools.
        fail_on_missing: Raise ``DependencyError`` if any *required*
                         dependency is missing.

    Returns:
        A :class:`DependencyReport` with per-dependency status.

    Raises:
        DependencyError: if *fail_on_missing* is ``True`` and a required
                         dependency is absent.
    """
    report = DependencyReport()
    report.python_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )

    # Check Python version (pyproject.toml requires-python = >=3.12).
    if sys.version_info < (3, 12):
        logger.error("Python 3.12+ required, got %s", report.python_version)

    # Python packages
    for import_name, pip_name, required, min_ver, desc in PYTHON_PACKAGES:
        status = _check_python_package(import_name, pip_name, required, min_ver, desc)
        report.checks.append(status)
        if status.available:
            logger.debug("  %s %s", pip_name, status.version)
        elif status.required:
            logger.error("  %s - %s", pip_name, status.error)
        else:
            logger.warning("  %s - %s (optional)", pip_name, status.error)

    # System tools
    for tool in SYSTEM_TOOLS:
        if not include_optional_tools and not tool["required"]:
            continue
        status = _check_system_tool(tool)
        report.checks.append(status)
        if status.available:
            logger.debug("  %s %s", tool["name"], status.version)
            if tool["name"] == "docker":
                report.docker_available = True
                compose_ok = _check_docker_compose()
                report.docker_compose_available = compose_ok
                # Add a visible status entry for Docker Compose
                compose_ver = ""
                if compose_ok:
                    try:
                        cp = subprocess.run(
                            resolve_and_wrap_cmd(["docker", "compose", "version"]),
                            capture_output=True, text=True, timeout=10,
                        )
                        compose_ver = cp.stdout.strip().split("\n")[0][:80]
                    except Exception:
                        compose_ver = "found"
                report.checks.append(DependencyStatus(
                    name="docker-compose",
                    available=compose_ok,
                    required=False,
                    version=compose_ver,
                    error="" if compose_ok else "'docker compose' not working",
                    description="Docker Compose v2 (required for DAST)",
                    category="system",
                ))
        elif status.required:
            logger.error("  %s - %s", tool["name"], status.error)
        else:
            logger.debug("  %s - %s (optional)", tool["name"], status.error)

    # Fail fast
    if fail_on_missing and not report.all_required_ok:
        missing = report.missing_required
        names = ", ".join(m.name for m in missing)
        details = "\n".join(f"  {m.name}: {m.error}" for m in missing)
        raise DependencyError(
            f"Missing required dependencies: {names}\n{details}\n"
            f"Install them and retry."
        )

    return report
