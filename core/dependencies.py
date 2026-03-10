"""
REDACTS Dependency Manager
===========================
Checks, reports, and auto-installs all required dependencies.

Three tiers:
    1. Python packages — auto-installable via pip (incl. semgrep)
    2. System tools    — auto-downloaded as binaries to ~/.redacts/tools/
    3. Optional tools  — enhance analysis but not strictly required

Called at startup before any analysis runs.
"""

from __future__ import annotations

import importlib
import io
import logging
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Portable tool cache — survives venv rebuilds
_TOOLS_DIR = Path(
    os.environ.get(
        "REDACTS_TOOLS_DIR",
        str(Path.home() / ".redacts" / "tools"),
    )
)


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
    node_available: bool = False

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
            lines.append(f"  MISSING (required): {m.name} — {m.error}")
        for m in self.missing_optional:
            lines.append(f"  MISSING (optional): {m.name} — {m.error}")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# Python package registry
# ═══════════════════════════════════════════════════════════════

# (import_name, pip_name, required, min_version, description)
_PYTHON_PACKAGES: list[tuple[str, str, bool, str, str]] = [
    ("chardet", "chardet", True, "5.0.0",
     "Character encoding detection"),
    ("magika", "magika", True, "0.6.0",
     "AI-powered file type detection (Google) — routing intelligence"),
    ("paramiko", "paramiko", True, "3.4.0",
     "SSH/SFTP for remote loaders"),
    ("requests", "requests", True, "2.31.0",
     "HTTP client for loaders and community rule downloads"),
    ("py7zr", "py7zr", True, "0.20.0",
     "7-Zip archive extraction"),
    ("rarfile", "rarfile", True, "4.1",
     "RAR archive extraction"),
    ("rich", "rich", True, "13.0.0",
     "Terminal formatting — progress bars, tables, panels"),
    ("yaml", "pyyaml", True, "6.0",
     "YAML config file parsing"),
    ("tree_sitter", "tree-sitter", True, "0.23.0",
     "AST parsing engine — accurate PHP code analysis"),
    ("tree_sitter_php", "tree-sitter-php", True, "0.23.0",
     "PHP grammar for tree-sitter AST parser"),
    # Semgrep is pip-installable so we treat it as a Python package
    ("semgrep", "semgrep", True, "1.0.0",
     "AST-based PHP security scanner — primary vulnerability detection"),
]

# ═══════════════════════════════════════════════════════════════
# System tools registry
# ═══════════════════════════════════════════════════════════════

_SYSTEM_TOOLS: list[dict] = [
    {
        "name": "trivy",
        "binary": "trivy",
        "required": True,
        "description": "Dependency CVE scanner + secret detection",
        "install_cmd": "Auto-downloaded by REDACTS",
        "install_url": "https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
        "auto_install": True,
    },
    {
        "name": "yara",
        "binary": "yara",
        "required": True,
        "description": "Malware signature matching with community rules",
        "install_cmd": "Auto-downloaded by REDACTS",
        "install_url": "https://yara.readthedocs.io/en/stable/gettingstarted.html",
        "auto_install": True,
    },
    {
        "name": "docker",
        "binary": "docker",
        "required": False,
        "description": "Required for DAST (dynamic application security testing)",
        "install_cmd": "Install Docker Desktop from https://docker.com",
        "install_url": "https://docs.docker.com/get-docker/",
    },
    {
        "name": "node",
        "binary": "node",
        "required": False,
        "description": "Required for DAST (Playwright test runner) and Repomix",
        "install_cmd": "Install from https://nodejs.org or use nvm",
        "install_url": "https://nodejs.org/en/download/",
    },
    {
        "name": "repomix",
        "binary": "repomix",
        "required": False,
        "description": "Compressed codebase representation for LLM analysis",
        "install_cmd": "npm install -g repomix",
        "install_url": "https://github.com/yamadashy/repomix",
    },
]


# ═══════════════════════════════════════════════════════════════
# Checking functions
# ═══════════════════════════════════════════════════════════════


def _check_python_package(
    import_name: str,
    pip_name: str,
    required: bool,
    min_version: str,
    description: str,
) -> DependencyStatus:
    """Check whether a Python package is importable."""
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
            install_cmd=f"pip install {pip_name}>={min_version}" if min_version else f"pip install {pip_name}",
        )
    except ImportError:
        hint = f"pip install {pip_name}>={min_version}" if min_version else f"pip install {pip_name}"
        return DependencyStatus(
            name=pip_name,
            available=False,
            required=required,
            error=f"Not installed. Fix: {hint}",
            description=description,
            category="python",
            install_cmd=hint,
        )
    except Exception as exc:
        return DependencyStatus(
            name=pip_name,
            available=False,
            required=required,
            error=f"Import error: {exc}",
            description=description,
            category="python",
        )


def _check_system_tool(tool: dict) -> DependencyStatus:
    """Check whether a system tool binary is available on PATH or in _TOOLS_DIR."""
    binary = tool["binary"]
    path = shutil.which(binary)

    # Also check our managed tools directory
    if not path:
        candidate = _TOOLS_DIR / (binary + (".exe" if sys.platform == "win32" else ""))
        if candidate.is_file():
            path = str(candidate)
            # Ensure _TOOLS_DIR is on PATH for subprocess calls later
            tools_str = str(_TOOLS_DIR)
            if tools_str not in os.environ.get("PATH", ""):
                os.environ["PATH"] = tools_str + os.pathsep + os.environ.get("PATH", "")

    if path:
        version = ""
        try:
            proc = subprocess.run(
                [binary, "--version"],
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
            required=tool["required"],
            version=version,
            description=tool["description"],
            category="system",
            install_cmd=tool.get("install_cmd", ""),
            install_url=tool.get("install_url", ""),
        )

    return DependencyStatus(
        name=tool["name"],
        available=False,
        required=tool["required"],
        error=f"'{binary}' not found in PATH",
        description=tool["description"],
        category="system",
        install_cmd=tool.get("install_cmd", ""),
        install_url=tool.get("install_url", ""),
    )


def _check_docker_compose() -> bool:
    """Check if docker compose (v2) is available."""
    try:
        proc = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ═══════════════════════════════════════════════════════════════
# Auto-installer
# ═══════════════════════════════════════════════════════════════


def auto_install_python(report: DependencyReport) -> list[str]:
    """Auto-install missing Python packages via pip.

    Returns list of successfully installed package names.
    """
    missing = report.missing_python
    if not missing:
        return []

    installed: list[str] = []
    for dep in missing:
        pip_spec = dep.install_cmd.replace("pip install ", "") if dep.install_cmd else dep.name
        print(f"  Installing {pip_spec}...")

        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_spec, "--quiet"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                installed.append(dep.name)
                dep.available = True
                dep.error = ""
                print(f"    OK {dep.name}")
            else:
                dep.error = proc.stderr.strip()[:200]
                print(f"    FAILED: {dep.error}")
        except subprocess.TimeoutExpired:
            dep.error = "Timed out after 120s"
            print(f"    TIMEOUT: {dep.name}")
        except Exception as exc:
            dep.error = str(exc)
            print(f"    ERROR: {dep.name} — {exc}")

    return installed


# ═══════════════════════════════════════════════════════════════
# System tool auto-installer
# ═══════════════════════════════════════════════════════════════

# Release versions pinned for reproducibility
_TRIVY_VERSION = "0.58.2"
_YARA_VERSION = "4.5.2"


def _download_and_extract_zip(url: str, dest_dir: Path, label: str) -> bool:
    """Download a ZIP from *url* and extract into *dest_dir*."""
    import requests

    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"    Downloading {label}...")
    logger.info("Downloading %s from %s", label, url)

    try:
        resp = requests.get(url, timeout=120)
        resp.raise_for_status()
        data = resp.content
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(dest_dir)
        return True
    except requests.exceptions.RequestException as exc:
        logger.error("Network error downloading %s: %s", label, exc)
        print(f"    FAILED to download {label} (network error): {exc}")
        return False
    except zipfile.BadZipFile as exc:
        logger.error("Invalid ZIP file downloaded for %s: %s", label, exc)
        print(f"    FAILED to extract {label} (invalid ZIP): {exc}")
        return False
    except Exception as exc:
        logger.error("Failed to download %s: %s", label, exc)
        print(f"    FAILED to download {label}: {exc}")
        return False


def _install_trivy(dest_dir: Path) -> bool:
    """Download the Trivy binary for the current platform."""
    system = platform.system().lower()  # windows, linux, darwin
    machine = platform.machine().lower()

    arch_map = {"x86_64": "64bit", "amd64": "64bit", "arm64": "ARM64", "aarch64": "ARM64"}
    arch = arch_map.get(machine, "64bit")

    if system == "windows":
        slug = f"trivy_{_TRIVY_VERSION}_windows-{arch}.zip"
    elif system == "darwin":
        slug = f"trivy_{_TRIVY_VERSION}_macOS-{arch}.zip"
    else:
        slug = f"trivy_{_TRIVY_VERSION}_Linux-{arch}.zip"

    url = f"https://github.com/aquasecurity/trivy/releases/download/v{_TRIVY_VERSION}/{slug}"
    return _download_and_extract_zip(url, dest_dir, f"Trivy v{_TRIVY_VERSION}")


def _install_yara(dest_dir: Path) -> bool:
    """Download the YARA binary for the current platform."""
    system = platform.system().lower()

    if system == "windows":
        # VirusTotal official Windows release
        url = (
            f"https://github.com/VirusTotal/yara/releases/download/"
            f"v{_YARA_VERSION}/yara-v{_YARA_VERSION}-2326-win64.zip"
        )
        ok = _download_and_extract_zip(url, dest_dir, f"YARA v{_YARA_VERSION}")
        if ok:
            # Release ships yara64.exe — create yara.exe alias so PATH lookup works
            src = dest_dir / "yara64.exe"
            dst = dest_dir / "yara.exe"
            if src.is_file() and not dst.is_file():
                shutil.copy2(src, dst)
                logger.info("Created %s → %s", src.name, dst.name)
        return ok
    elif system == "darwin":
        # macOS — try Homebrew first, then binary download
        try:
            proc = subprocess.run(
                ["brew", "install", "yara"],
                capture_output=True, text=True, timeout=180,
            )
            if proc.returncode == 0:
                print("    Installed YARA via Homebrew")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        print("    YARA auto-install not available for macOS without Homebrew")
        print("    Install manually: brew install yara")
        return False
    else:
        # Linux — try apt/yum, fall back to guidance
        for pkg_mgr, args in [
            ("apt-get", ["sudo", "apt-get", "install", "-y", "yara"]),
            ("yum", ["sudo", "yum", "install", "-y", "yara"]),
        ]:
            if shutil.which(pkg_mgr):
                try:
                    proc = subprocess.run(
                        args, capture_output=True, text=True, timeout=180,
                    )
                    if proc.returncode == 0:
                        print(f"    Installed YARA via {pkg_mgr}")
                        return True
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
        print("    YARA auto-install not available — install manually")
        return False


def auto_install_system_tools(report: DependencyReport) -> list[str]:
    """Auto-download missing system tool binaries.

    Downloads into ``~/.redacts/tools/`` and adds to PATH.
    Returns list of successfully installed tool names.
    """
    missing = [
        c for c in report.checks
        if not c.available and c.category == "system"
    ]
    if not missing:
        return []

    _TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []

    # Ensure tools dir is on PATH
    tools_str = str(_TOOLS_DIR)
    if tools_str not in os.environ.get("PATH", ""):
        os.environ["PATH"] = tools_str + os.pathsep + os.environ.get("PATH", "")

    installers = {
        "trivy": _install_trivy,
        "yara": _install_yara,
    }

    for dep in missing:
        installer = installers.get(dep.name)
        if not installer:
            continue  # docker, node, repomix — not auto-installable

        print(f"  Auto-installing {dep.name}...")
        if installer(_TOOLS_DIR):
            # Verify it actually works now
            binary = dep.name + (".exe" if sys.platform == "win32" else "")
            if (_TOOLS_DIR / binary).is_file() or shutil.which(dep.name):
                dep.available = True
                dep.error = ""
                installed.append(dep.name)
                print(f"    OK — {dep.name} installed to {_TOOLS_DIR}")
            else:
                dep.error = f"Downloaded but binary not found in {_TOOLS_DIR}"
                print(f"    WARNING: {dep.error}")
        else:
            dep.error = f"Auto-install failed — install manually: {dep.install_url}"
            print(f"    FAILED: {dep.error}")

    return installed


# ═══════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════


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

    # Check Python version
    if sys.version_info < (3, 10):
        logger.error("Python 3.10+ required, got %s", report.python_version)

    # Python packages
    for import_name, pip_name, required, min_ver, desc in _PYTHON_PACKAGES:
        status = _check_python_package(import_name, pip_name, required, min_ver, desc)
        report.checks.append(status)
        if status.available:
            logger.debug("  %s %s", pip_name, status.version)
        elif status.required:
            logger.error("  %s — %s", pip_name, status.error)
        else:
            logger.warning("  %s — %s (optional)", pip_name, status.error)

    # System tools
    for tool in _SYSTEM_TOOLS:
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
                            ["docker", "compose", "version"],
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
            elif tool["name"] == "node":
                report.node_available = True
        elif status.required:
            logger.error("  %s — %s", tool["name"], status.error)
        else:
            logger.debug("  %s — %s (optional)", tool["name"], status.error)

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
