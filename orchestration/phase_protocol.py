"""
Scan phase protocol and shared orchestrator context.

Defines the :class:`ScanPhase` protocol that every discrete orchestration
phase implements, the :class:`PhaseResult` return type, and the
:class:`OrchestratorContext` shared state threaded through each phase.

Extracted from :class:`orchestration.tool_orchestrator.ToolOrchestrator`
(Step 6.2 — Strangler Fig decomposition).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ..core.models import FindingCollection


# ═══════════════════════════════════════════════════════════════════════════
# Shared data structures
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class PhaseResult:
    """Return value of :meth:`ScanPhase.execute`.

    Attributes:
        skipped:  ``True`` when the phase opted out (tool not available or
                  not enabled in config).
    """

    skipped: bool = False


@dataclass
class OrchestratorContext:
    """Shared mutable state threaded through every scan phase.

    Attributes:
        target_path:       Resolved path to the scan target directory.
        baseline_path:     Optional baseline for delta-aware scanning.
        config:            The :class:`OrchestratorConfig` governing this run.
        only_files:        When not ``None``, restrict findings generation
                           to this set of relative paths (audit-mode delta).
        output_dir:        Where analysis artefacts are written.
        collection:        The shared :class:`FindingCollection` that all
                           phases append to.
        magika_results:    Magika file-type map populated by
                           :class:`MagikaPhase` and consumed by downstream
                           phases (YARA synergy, correlation, enrichment).
        tool_availability: Which tools are installed and usable (populated
                           by :class:`DiscoverPhase`).
        phase_timings:     Execution time per phase in seconds.
    """

    target_path: Path
    baseline_path: Path | None
    config: Any  # OrchestratorConfig — avoids circular import
    only_files: set[str] | None
    output_dir: Path
    collection: FindingCollection
    magika_results: dict[str, Any] = field(default_factory=dict)
    tool_availability: dict[str, bool] = field(default_factory=dict)
    phase_timings: dict[str, float] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# Protocol
# ═══════════════════════════════════════════════════════════════════════════


@runtime_checkable
class ScanPhase(Protocol):
    """One discrete phase of the orchestrated scan pipeline.

    Implementations must expose a ``name`` attribute (used for logging
    and progress reporting) and an ``execute`` method that receives the
    shared :class:`OrchestratorContext` and returns a :class:`PhaseResult`.
    """

    name: str

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        """Run this scan phase."""
        ...
