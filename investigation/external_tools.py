"""
REDACTS External Tools Integration — runtime discovery and orchestration
of security analysis tools for forensic enrichment.

Provides adapters for three battle-tested external tools:

    • **YARA**     — indicator-of-compromise pattern matching (with community rules)
    • **Semgrep**  — AST-based static analysis (via ``SemgrepAdapter``)
    • **Trivy**    — vulnerability / secret scanning (via ``TrivyAdapter``)

Every adapter degrades gracefully when the underlying binary is absent:
``is_available()`` checks ``shutil.which()``, and failures at runtime are
captured in ``ExternalToolResult.errors`` rather than raised.
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


# Reuse the canonical tool-cache path from the dependency manager
# instead of duplicating the resolution logic.
try:
    from ..core.dependencies import _TOOLS_DIR
except ImportError:
    # Fallback for standalone use (e.g. unit tests)
    _TOOLS_DIR = Path(
        os.environ.get(
            "REDACTS_TOOLS_DIR",
            str(Path.home() / ".redacts" / "tools"),
        )
    )


def _resolve_venv_tool(name: str) -> str | None:
    """Resolve a tool binary, checking PATH, venv Scripts, and ~/.redacts/tools/.

    When REDACTS is invoked via its full interpreter path (e.g.
    ``/path/to/.venv/Scripts/python -m REDACTS``) the venv ``Scripts``
    directory is **not** on ``$PATH``, so ``shutil.which()`` misses
    co-installed console-scripts such as ``lizard.exe`` or ``radon``.

    Strategy:
        1. ``shutil.which(name)`` — honours ``$PATH`` as usual.
        2. Probe ``sys.executable``'s sibling directory for common
           suffixed variants (plain name, ``.exe``, ``.cmd``).
        3. Probe ``~/.redacts/tools/`` — the auto-install directory
           used by ``core.dependencies`` for Trivy, YARA, etc.
           When found here, ``PATH`` is updated so that subsequent
           ``subprocess`` calls also find the binary.
    """
    found = shutil.which(name)
    if found:
        return found

    # Check venv Scripts/bin directory
    scripts_dir = Path(sys.executable).resolve().parent
    for suffix in ("", ".exe", ".cmd"):
        candidate = scripts_dir / f"{name}{suffix}"
        if candidate.is_file():
            return str(candidate)

    # Check the managed REDACTS tools directory (~/.redacts/tools/)
    for suffix in ("", ".exe"):
        candidate = _TOOLS_DIR / f"{name}{suffix}"
        if candidate.is_file():
            # Ensure _TOOLS_DIR is on PATH so subprocess calls find it too
            tools_str = str(_TOOLS_DIR)
            if tools_str not in os.environ.get("PATH", ""):
                os.environ["PATH"] = tools_str + os.pathsep + os.environ.get("PATH", "")
            return str(candidate)

    return None


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

#: Default timeout (seconds) for external tool subprocesses.  Callers
#: can override per-invocation via the ``timeout`` keyword argument.
#: The :pyclass:`InvestigationConfig` exposes the same default as
#: ``external_tool_timeout`` so that end-users may tune it from config.
DEFAULT_TOOL_TIMEOUT: int = 120


# ═══════════════════════════════════════════════════════════════════════════
# Data classes
# ═══════════════════════════════════════════════════════════════════════════


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

    # Serialisation --------------------------------------------------------

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


# ═══════════════════════════════════════════════════════════════════════════
# Base adapter
# ═══════════════════════════════════════════════════════════════════════════


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

    # Helpers available to every subclass -----------------------------------

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
                cmd,
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


# ═══════════════════════════════════════════════════════════════════════════
# Tool Adapters — re-exported from dedicated modules for backward compat
# ═══════════════════════════════════════════════════════════════════════════

from .yara_adapter import YaraAdapter  # noqa: E402, F401


# ═══════════════════════════════════════════════════════════════════════════
# Runner / orchestrator
# ═══════════════════════════════════════════════════════════════════════════


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

    # Registration ---------------------------------------------------------

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

    # Discovery ------------------------------------------------------------

    def discover_tools(self) -> dict[str, bool]:
        """Probe every registered adapter and return availability mapping."""
        result: dict[str, bool] = {}
        for name, adapter in self._adapters.items():
            try:
                result[name] = adapter.is_available()
            except Exception:
                result[name] = False
        return result

    # Execution ------------------------------------------------------------

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
            output_dir.mkdir(parents=True, exist_ok=True)
            config.setdefault("output_dir", str(output_dir))

        availability = self.discover_tools()
        report = ExternalToolsReport(
            tools_discovered=[n for n, ok in availability.items() if ok],
            tools_missing=[n for n, ok in availability.items() if not ok],
        )

        logger.info(
            "External tools — available: %s, missing: %s",
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
