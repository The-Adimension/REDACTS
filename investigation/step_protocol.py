"""
Investigation step protocol and shared context.

Defines the :class:`InvestigationStep` protocol that every discrete
investigation phase implements, the :class:`StepResult` return type,
the :class:`InvestigationContext` shared state, and the small helper
functions used by multiple step implementations.

Extracted from :class:`investigation.investigator.Investigator`
(Step 6.1 — Strangler Fig decomposition).
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..core.constants import get_scannable_extensions
from ..core.hashing import compute_single_hash


# ═══════════════════════════════════════════════════════════════════════════
# Investigation data classes (shared across steps and orchestrator)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class InvestigationFinding:
    """A single investigation finding."""

    id: str  # e.g., "INV-001"
    source: str  # "ioc_scan", "security_scan", "sensitive_data", "config_check", "external_tool", "attack_vector"
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    file_path: str  # Relative path to the affected file
    line: int  # Line number (0 if not applicable)
    conclusiveness: str  # "conclusive", "suspicious", "informational"
    category: str  # e.g., "persistence", "webshell", "credential_exposure"
    recommendation: str
    cwe_id: str = ""
    cwe_name: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    related_ioc_ids: list[str] = field(default_factory=list)
    related_attack_vector_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict."""
        return asdict(self)


@dataclass
class ConfigIntegrityResult:
    """Results of configuration file integrity checking."""

    database_php: dict[str, Any] = field(default_factory=dict)
    htaccess_files: list[dict[str, Any]] = field(default_factory=list)
    user_ini_files: list[dict[str, Any]] = field(default_factory=list)
    hook_functions: dict[str, Any] = field(default_factory=dict)
    cron_php: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════
# Step result and context
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class StepResult:
    """Return value of :meth:`InvestigationStep.execute`.

    Attributes:
        findings:       New findings produced by this step.
        report_updates: Mapping of ``InvestigationReport`` attribute names
                        to values that should be set on the report by the
                        orchestrator (e.g. ``{"security_scan_summary": {...}}``).
    """

    findings: list = field(default_factory=list)
    report_updates: dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationContext:
    """Shared state threaded through every step.

    Attributes:
        root:              Resolved path to the evidence/source directory.
        output_dir:        Where investigation artefacts are written.
        only_files:        When not ``None``, restrict scans to these
                           relative paths only (audit-mode delta).
        run_external_tools: Whether external tool adapters should run.
        all_findings:      Accumulated findings from all previous steps
                           (read-only for most steps; post-processing
                           steps like attack-vector assessment use it).
    """

    root: Path
    output_dir: Path
    only_files: set[str] | None = None
    run_external_tools: bool = True
    all_findings: list = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# Protocol
# ═══════════════════════════════════════════════════════════════════════════


@runtime_checkable
class InvestigationStep(Protocol):
    """One discrete phase of the investigation pipeline.

    Implementations must expose a ``name`` attribute (used for logging
    and progress reporting) and an ``execute`` method that receives the
    shared :class:`InvestigationContext` and returns a :class:`StepResult`.
    """

    name: str

    def execute(self, context: InvestigationContext) -> StepResult:
        """Run this investigation step and return findings."""
        ...


# ═══════════════════════════════════════════════════════════════════════════
# Utility helpers (formerly Investigator static methods)
# ═══════════════════════════════════════════════════════════════════════════


def rel_path(path: Path, root: Path) -> str:
    """Return a forward-slash relative path string."""
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def sha256(path: Path) -> str:
    """Compute SHA-256 hex digest of a file.

    Delegates to :func:`core.hashing.compute_single_hash` (canonical
    implementation, DUP-001).  Returns ``""`` on any error.
    """
    return compute_single_hash(path, suppress_errors=True)


def iter_scannable_files(
    root: Path, only_files: set[str] | None = None
) -> list[Path]:
    """Collect files with scannable extensions under *root*.

    When *only_files* is provided the scan is restricted to exactly
    those relative paths — no globbing, no extension filtering.
    """
    if only_files is not None:
        files: list[Path] = []
        for rel in sorted(only_files):
            fpath = root / rel.replace("/", os.sep)
            if fpath.is_file():
                try:
                    if fpath.stat().st_size <= 10 * 1024 * 1024:
                        files.append(fpath)
                except OSError:
                    pass
        return files

    scannable_exts = get_scannable_extensions()
    files = []
    for fpath in root.rglob("*"):
        if fpath.is_file():
            ext = fpath.suffix.lower()
            name = fpath.name.lower()
            if ext in scannable_exts or name in scannable_exts:
                try:
                    if fpath.stat().st_size <= 10 * 1024 * 1024:
                        files.append(fpath)
                except OSError:
                    pass
    return files


def count_by(findings: list, attr: str) -> dict[str, int]:
    """Count findings by a given attribute."""
    counts: dict[str, int] = {}
    for f in findings:
        val = getattr(f, attr, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts
