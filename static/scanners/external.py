"""Adapter framework for the third-party scanners REDACTS shells out to.

Three tools are integrated; each has a separate adapter module that
inherits from :class:`ExternalToolAdapter` defined here:

    * YARA - pattern matching against community + custom rule sets.
      Limit: signature-based, so obfuscated or never-before-seen
      payloads are missed by design. See VirusTotal's YARA docs
      (https://yara.readthedocs.io/) for the rule grammar.
    * Semgrep - AST pattern + taint analysis. Limit: no runtime
      context; a sink reachable only via reflection or dynamic
      ``call_user_func`` chains will not be flagged. Rulesets used:
      ``p/php-security``, ``p/php``, ``p/security-audit``.
    * Trivy - CVE / secret scanning of dependencies. Limit: only as
       current as the local CVE feed (``trivy image --download-db-only``
       refresh cadence is the user's responsibility); CVEs disclosed
       between feed pulls are invisible.

Adapters fail soft: ``is_available()`` checks ``shutil.which`` plus the
venv ``Scripts/`` and ``~/.redacts/tools/`` install locations, and runtime
failures land in :attr:`ExternalToolResult.errors` rather than raise so
the orchestrator can continue with the remaining tools.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Canonical tool-cache path: always resolved fresh against the active
# FrozenCaseContract via static.core.paths (no import-time capture).
from ..core.paths import tools_dir as _resolve_tools_dir, inject_tools_on_path
from ..core.subprocess_env import UnsafeCommandError, resolve_and_wrap_cmd


def _interpreter_script_dirs() -> list[Path]:
    """Return every directory pip may deposit a console script into.

    Console scripts (``semgrep.exe``, ``lizard.exe`` ...) are **not** placed
    beside ``python.exe`` - they go in a ``Scripts`` (Windows) / ``bin``
    (POSIX) directory whose location depends on the install scheme:

    * default / venv install -> the interpreter's own scripts dir
      (``sysconfig.get_path("scripts")``);
    * ``pip install --user`` -> the *user* scheme scripts dir
      (e.g. ``%APPDATA%\\Python\\Python3xx\\Scripts``), which is a different
      directory and is frequently absent from ``PATH``.

    Probing both mirrors what the Semgrep adapter already does, so preflight
    resolution is consistent with actual tool availability.
    """
    import sysconfig

    candidates: list[Path] = []

    # The interpreter directory and its adjacent Scripts/bin subdir. In a venv
    # python lives inside Scripts/bin already, so the parent itself is valid.
    exe_parent = Path(sys.executable).resolve().parent
    candidates += [exe_parent, exe_parent / "Scripts", exe_parent / "bin"]

    # sysconfig's own scripts dir, plus the per-user scheme.
    user_scheme = "nt_user" if os.name == "nt" else "posix_user"
    for scheme in (None, user_scheme):
        try:
            path = (
                sysconfig.get_path("scripts")
                if scheme is None
                else sysconfig.get_path("scripts", scheme=scheme)
            )
        except (KeyError, OSError):
            continue
        if path:
            candidates.append(Path(path))

    seen: set[str] = set()
    ordered: list[Path] = []
    for directory in candidates:
        key = str(directory)
        if key not in seen:
            seen.add(key)
            ordered.append(directory)
    return ordered


def _resolve_venv_tool(name: str) -> str | None:
    """Resolve a tool binary, checking PATH, interpreter/user Scripts dirs,
    and the managed tools directory.

    When REDACTS is invoked via its full interpreter path (e.g.
    ``/path/to/.venv/Scripts/python -m REDACTS``) the venv ``Scripts``
    directory is **not** on ``$PATH``, so ``shutil.which()`` misses
    co-installed console-scripts such as ``lizard.exe`` or ``radon``.

    Strategy:
        1. ``shutil.which(name)`` - honours ``$PATH`` as usual.
        2. Probe every interpreter/user console-script directory (see
           :func:`_interpreter_script_dirs`) for common suffixed variants
           (plain name, ``.exe``, ``.cmd``, ``.bat``). ``.ps1`` is excluded:
           running one needs an execution-policy bypass that
           ``subprocess_env`` refuses to issue.
        3. Probe :func:`static.core.paths.tools_dir` - the auto-install
           directory used by ``core.dependencies`` for Trivy, YARA, etc.
           When found here, ``PATH`` is updated via the canonical
           chokepoint so that subsequent ``subprocess`` calls also
           discover the binary.
    """
    found = shutil.which(name)
    if found:
        return found

    # Check interpreter and per-user console-script directories.
    for scripts_dir in _interpreter_script_dirs():
        for suffix in ("", ".exe", ".cmd", ".bat"):
            candidate = scripts_dir / f"{name}{suffix}"
            if candidate.is_file():
                return str(candidate)

    # Check the managed REDACTS tools directory.
    tools_dir = _resolve_tools_dir()
    for suffix in ("", ".exe", ".cmd", ".bat"):
        candidate = tools_dir / f"{name}{suffix}"
        if candidate.is_file():
            # Ensure tools_dir is on PATH for downstream subprocess calls.
            inject_tools_on_path()
            return str(candidate)

    # Also check ~/.redacts/tools fallback if contract tools_dir differs
    from ..core.paths import _DEFAULT_HOME
    default_tools = _DEFAULT_HOME / "tools"
    if default_tools != tools_dir:
        for suffix in ("", ".exe", ".cmd", ".bat"):
            candidate = default_tools / f"{name}{suffix}"
            if candidate.is_file():
                if str(default_tools) not in os.environ.get("PATH", "").split(os.pathsep):
                    os.environ["PATH"] = str(default_tools) + os.pathsep + os.environ.get("PATH", "")
                return str(candidate)

    return None


#: Default timeout (seconds) for external tool subprocesses.  Callers
#: can override per-invocation via the ``timeout`` keyword argument.
#: The :pyclass:`InvestigationConfig` exposes the same default as
#: ``external_tool_timeout`` so that end-users may tune it from config.
DEFAULT_TOOL_TIMEOUT: int = 120


@dataclass
class ExternalToolResult:
    """Outcome of a single tool execution."""

    tool_name: str
    tool_version: str = ""
    available: bool = False
    success: bool = False
    execution_time_seconds: float = 0.0
    raw_output: str = ""
    parsed_data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    files_analyzed: int = 0

    # Serialisation ---

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "available": self.available,
            "success": self.success,
            "execution_time_seconds": round(self.execution_time_seconds, 3),
            "raw_output": self.raw_output,
            "parsed_data": self.parsed_data,
            "errors": self.errors,
            "files_analyzed": self.files_analyzed,
        }


@dataclass
class ExternalToolsReport:
    """Aggregated report for all external-tool runs."""

    tools_discovered: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)
    results: dict[str, ExternalToolResult] = field(default_factory=dict)
    total_execution_time: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools_discovered": self.tools_discovered,
            "tools_missing": self.tools_missing,
            "results": {k: v.to_dict() for k, v in self.results.items()},
            "total_execution_time": round(self.total_execution_time, 3),
        }


class ExternalToolAdapter(ABC):
    """Abstract base for every tool adapter."""

    name: str = ""
    description: str = ""
    install_hint: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """Return *True* when the tool is installed and usable."""

    @abstractmethod
    def get_version(self) -> str:
        """Return a human-readable version string, or ``""``."""

    @abstractmethod
    def run(
        self, target_path: Path, config: dict[str, Any] | None = None
    ) -> ExternalToolResult:
        """Execute the tool against *target_path* and return a result."""

    # Helpers available to every subclass

    @staticmethod
    def _run_subprocess(
        cmd: list[str],
        *,
        timeout: int = DEFAULT_TOOL_TIMEOUT,
        cwd: Path | None = None,
    ) -> tuple[str, str, int]:
        """Run *cmd* and return ``(stdout, stderr, returncode)``."""
        try:
            proc = subprocess.run(
                resolve_and_wrap_cmd(cmd),
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            return proc.stdout, proc.stderr, proc.returncode
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except subprocess.TimeoutExpired:
            return "", f"Command timed out after {timeout}s", -2
        except UnsafeCommandError as exc:
            # Refusing to launch is the safe outcome; surface it as a failed
            # tool run so the scan degrades instead of aborting.
            logger.error("Refused unsafe subprocess invocation: %s", exc)
            return "", str(exc), -3

    @staticmethod
    def _collect_files(
        root: Path,
        extensions: set[str],
        *,
        skip_dirs: set[str] | None = None,
    ) -> list[Path]:
        """Recursively collect files matching *extensions* under *root*.

        Directories whose name appears in *skip_dirs* are pruned.  By
        default ``vendor``, ``node_modules``, and ``.git`` are always
        excluded to avoid scanning third-party / generated code.
        """
        _always_skip = {"vendor", "node_modules", ".git", "__pycache__", ".tox"}
        deny = (_always_skip | skip_dirs) if skip_dirs else _always_skip

        matches: list[Path] = []
        if root.is_file():
            if root.suffix.lower() in extensions:
                matches.append(root)
            return matches
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune directories in-place so os.walk doesn't descend
            dirnames[:] = [d for d in dirnames if d not in deny]
            for fn in filenames:
                fp = Path(dirpath) / fn
                if fp.suffix.lower() in extensions:
                    matches.append(fp)
        return sorted(matches)

    def _empty_result(self, errors: list[str] | None = None) -> ExternalToolResult:
        return ExternalToolResult(
            tool_name=self.name,
            available=False,
            errors=errors or [f"{self.name} is not installed. {self.install_hint}"],
        )



from .yara_adapter import YaraAdapter  # noqa: E402, F401




class ExternalToolRunner:
    """Discovers and orchestrates all registered external-tool adapters."""

    def __init__(
        self,
        *,
        adapters: list[ExternalToolAdapter] | None = None,
    ) -> None:
        self._adapters: dict[str, ExternalToolAdapter] = {}
        if adapters is not None:
            for adapter in adapters:
                self._adapters[adapter.name] = adapter
        else:
            self._register_defaults()

    # Registration ----

    def _register_defaults(self) -> None:
        from .semgrep_adapter import SemgrepAdapter
        from .trivy_adapter import TrivyAdapter
        from .yara_adapter import YaraAdapter as _YaraAdapter

        for adapter_cls in (
            _YaraAdapter,
            SemgrepAdapter,
            TrivyAdapter,
        ):
            adapter = adapter_cls()
            self._adapters[adapter.name] = adapter

    def register(self, adapter: ExternalToolAdapter) -> None:
        """Register a custom adapter (for extensibility)."""
        self._adapters[adapter.name] = adapter

    # Discovery -------

    def discover_tools(self) -> dict[str, bool]:
        """Probe every registered adapter and return availability mapping."""
        result: dict[str, bool] = {}
        for name, adapter in self._adapters.items():
            try:
                result[name] = adapter.is_available()
            except Exception:
                result[name] = False
        return result

    # Execution -------

    def run_tool(
        self,
        tool_name: str,
        target_path: Path,
        config: dict[str, Any] | None = None,
    ) -> ExternalToolResult:
        """Run a single tool by name."""
        adapter = self._adapters.get(tool_name)
        if adapter is None:
            return ExternalToolResult(
                tool_name=tool_name,
                errors=[f"Unknown tool: {tool_name}"],
            )
        if not adapter.is_available():
            return adapter._empty_result()
        try:
            return adapter.run(target_path, config)
        except Exception as exc:
            logger.warning("Tool %s failed: %s", tool_name, exc)
            return ExternalToolResult(
                tool_name=tool_name,
                tool_version=adapter.get_version(),
                available=True,
                success=False,
                errors=[str(exc)],
            )

    def run_all(
        self,
        target_path: Path,
        output_dir: Path | None = None,
        config: dict[str, Any] | None = None,
    ) -> ExternalToolsReport:
        """Run every available tool and aggregate results."""
        config = dict(config) if config else {}
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            config.setdefault("output_dir", str(output_dir))

        availability = self.discover_tools()
        report = ExternalToolsReport(
            tools_discovered=[n for n, ok in availability.items() if ok],
            tools_missing=[n for n, ok in availability.items() if not ok],
        )

        logger.info(
            "External tools - available: %s, missing: %s",
            report.tools_discovered,
            report.tools_missing,
        )

        total_start = time.monotonic()

        for name, adapter in self._adapters.items():
            if not availability.get(name, False):
                report.results[name] = adapter._empty_result()
                continue
            try:
                result = adapter.run(target_path, config)
            except Exception as exc:
                logger.warning("Tool %s raised: %s", name, exc, exc_info=True)
                result = ExternalToolResult(
                    tool_name=name,
                    tool_version=adapter.get_version(),
                    available=True,
                    success=False,
                    errors=[str(exc)],
                )
            report.results[name] = result

        report.total_execution_time = time.monotonic() - total_start
        return report
