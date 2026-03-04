"""
REDACTS Tool Orchestrator — Central coordinator for cross-tool synergy.

This is the brain of REDACTS.  It coordinates all integrated tools and
implements the cross-tool intelligence that makes REDACTS more than the
sum of its parts:

    1. **Magika-first routing** — Every file is typed by Magika BEFORE
       being routed to appropriate scanners.  PHP files → Semgrep;
       images that contain PHP → critical alert + YARA + Semgrep;
       SQLite hiding as .txt → INFINITERED indicator.

    2. **Cross-tool corroboration** — When Semgrep, YARA, and Magika
       all flag the same file, confidence is upgraded to CONFIRMED
       and the finding rises in priority.

    3. **Trivy + Semgrep synergy** — Known-vulnerable dependencies
       from Trivy drive targeted Semgrep scans of the calling code.

    4. **YARA + Magika mutual enrichment** — YARA webshell hits on
       files that Magika already flagged as content-type mismatches
       receive the highest severity.

    5. **tree-sitter structural context** — When Semgrep reports a
       finding, tree-sitter provides the full function/class context
       for the report.

All findings flow into a single FindingCollection for SARIF export.

Usage::

    orchestrator = ToolOrchestrator(target_path=Path("/path/to/redcap"))
    collection = orchestrator.run_all()

    # Export to SARIF
    from REDACTS.reporting.sarif_exporter import SarifExporter
    SarifExporter().write(collection, Path("output.sarif"))
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.models import (
    FindingCollection,
    SeverityLevel,
)
from .phase_protocol import OrchestratorContext
from .phases import (
    CorrelatePhase,
    DastPhase,
    DiscoverPhase,
    LegacyScannerPhase,
    MagikaPhase,
    SemgrepPhase,
    TreeSitterPhase,
    TrivyPhase,
    YaraPhase,
)

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorConfig:
    """Configuration for the tool orchestrator."""

    # Tool toggles
    enable_semgrep: bool = True
    enable_trivy: bool = True
    enable_yara: bool = True
    enable_magika: bool = True
    enable_tree_sitter: bool = True
    enable_legacy_scanner: bool = True  # SecurityScanner (regex)
    enable_dast: bool = True  # Dynamic Application Security Testing

    # DAST
    dast_suites: list[str] = field(
        default_factory=lambda: ["export", "admin", "upgrade"]
    )
    dast_timeout: int = 600  # per-suite timeout in seconds
    dast_keep_stack: bool = False
    dast_port: int = 0  # 0 = use DAST_PORT env or default 8585
    redcap_version: str = ""  # e.g. "15.7.4" — derived from target ZIP name

    # YARA
    yara_rules_path: str = ""
    yara_community_rules: bool = True

    # Semgrep
    semgrep_rulesets: list[str] = field(
        default_factory=lambda: [
            "p/php",  # PHP-specific rules
            "p/phpcs-security-audit",  # PHP CodeSniffer security audit
            "p/owasp-top-ten",  # OWASP Top 10 coverage
            "p/security-audit",  # General security audit
        ]
    )
    semgrep_exclude: list[str] = field(
        default_factory=lambda: [
            "vendor",
            "node_modules",
            ".git",
        ]
    )

    # Trivy
    trivy_scanners: list[str] = field(default_factory=lambda: ["vuln", "secret"])
    trivy_severity: str = ""  # e.g. "MEDIUM,HIGH,CRITICAL"

    # Timeouts
    tool_timeout: int = 300  # per-tool timeout in seconds

    # Output
    generate_sbom: bool = False
    sbom_output_path: str = ""

    # Pre-checked dependency state (avoids double Docker detection)
    docker_available: bool | None = None  # None = not pre-checked
    docker_compose_available: bool | None = None


class ToolOrchestrator:
    """Central orchestrator coordinating all REDACTS tools.

    Uses the Strategy pattern with :class:`ScanPhase` plugins.
    Phases are executed in order; each receives the shared
    :class:`OrchestratorContext` carrying mutable state
    (findings, Magika results, tool availability, timings).

    Default pipeline::

        1. DiscoverPhase      — probe tool availability
        2. MagikaPhase        — type every file (routing intelligence)
        3. SemgrepPhase       — AST-based PHP security analysis
        4. TrivyPhase         — dependency CVE scanning and secrets
        5. YaraPhase          — webshell/backdoor detection
        6. LegacyScannerPhase — regex-based supplementary hints
        7. TreeSitterPhase    — structural context enrichment
        8. CorrelatePhase     — cross-tool correlation
        9. DastPhase          — dynamic validation via Playwright

    Custom phases can be registered via :meth:`register_phase`.
    """

    def __init__(
        self,
        target_path: Path,
        baseline_path: Path | None = None,
        config: OrchestratorConfig | None = None,
        only_files: set[str] | None = None,
        output_dir: Path | None = None,
        *,
        phases: list[Any] | None = None,
    ) -> None:
        self.target_path = target_path
        self.baseline_path = baseline_path
        self.config = config or OrchestratorConfig()

        # Output directory for analysis artifacts (DAST results, SBOM).
        # Falls back to a sibling ``_orchestrator`` dir next to the target
        # to avoid writing into the evidence being analysed.
        self.output_dir = output_dir or target_path.parent / "_orchestrator"

        # Delta-aware scanning: when *only_files* is provided (relative
        # paths like ``"Classes/Foo.php"``), only those files generate
        # findings.  Magika still types ALL files (needed for routing
        # intelligence), but mismatch findings are scoped to the delta.
        self.only_files: set[str] | None = only_files
        if only_files is not None:
            logger.info(
                "Orchestrator: delta-aware mode — %d files in scope",
                len(only_files),
            )

        # Shared mutable context threaded through every phase
        self._context = OrchestratorContext(
            target_path=target_path,
            baseline_path=baseline_path,
            config=self.config,
            only_files=only_files,
            output_dir=self.output_dir,
            collection=FindingCollection(
                target_path=str(target_path),
                baseline_path=str(baseline_path) if baseline_path else "",
            ),
        )

        # ── Phase pipeline (injected or default) ─────────────────────
        self._phases: list[Any] = (
            list(phases)
            if phases is not None
            else [
                DiscoverPhase(),
                MagikaPhase(),
                SemgrepPhase(),
                TrivyPhase(),
                YaraPhase(),
                LegacyScannerPhase(),
                TreeSitterPhase(),
                CorrelatePhase(),
                DastPhase(),
            ]
        )

    # ═══════════════════════════════════════════════════════════════════
    # Plugin registry
    # ═══════════════════════════════════════════════════════════════════

    @property
    def phases(self) -> list[Any]:
        """Return the ordered phase list (read-only snapshot)."""
        return list(self._phases)

    def register_phase(self, phase: Any, *, index: int = -1) -> None:
        """Insert a custom :class:`ScanPhase` into the pipeline.

        Parameters
        ----------
        phase:
            An object satisfying the :class:`ScanPhase` protocol
            (must have a ``name`` attribute and an ``execute`` method).
        index:
            Position in the phase list.  ``-1`` (default) appends.
        """
        if index < 0:
            self._phases.append(phase)
        else:
            self._phases.insert(index, phase)

    # ═══════════════════════════════════════════════════════════════════
    # Execution
    # ═══════════════════════════════════════════════════════════════════

    def run_all(self) -> FindingCollection:
        """Execute the full orchestrated scan pipeline.

        Returns a FindingCollection with cross-tool corroboration,
        Magika enrichment, and MITRE/CWE/CVSS mappings.
        """
        total_start = time.monotonic()
        logger.info("REDACTS Orchestrator: Starting scan of %s", self.target_path)

        for phase in self._phases:
            phase_start = time.monotonic()
            try:
                phase.execute(self._context)
            except Exception as exc:
                logger.error("Phase '%s' failed: %s", phase.name, exc)
            self._context.phase_timings[phase.name] = time.monotonic() - phase_start

        # Finalize
        self._context.collection.scan_completed = datetime.now(timezone.utc).isoformat()
        total_elapsed = time.monotonic() - total_start
        self._context.phase_timings["total"] = total_elapsed

        logger.info(
            "REDACTS Orchestrator: Complete — %d findings, %d corroborated, %.1fs",
            len(self._context.collection.findings),
            len(self._context.collection.corroborated_findings),
            total_elapsed,
        )

        return self._context.collection

    # ═══════════════════════════════════════════════════════════════════
    # Public query API
    # ═══════════════════════════════════════════════════════════════════

    @property
    def findings(self) -> FindingCollection:
        """The current finding collection."""
        return self._context.collection

    @property
    def magika_results(self) -> dict[str, Any]:
        """Magika file type results keyed by relative path."""
        return self._context.magika_results

    @property
    def tool_availability(self) -> dict[str, bool]:
        """Which tools are installed and usable."""
        return self._context.tool_availability

    @property
    def phase_timings(self) -> dict[str, float]:
        """Execution time per phase in seconds."""
        return self._context.phase_timings

    def get_suspicious_files(self) -> list[dict[str, Any]]:
        """Return files flagged by multiple signals.

        A file is suspicious if it has:
            - Magika content-type mismatch, OR
            - Findings from 2+ different tools, OR
            - Any CRITICAL severity finding
        """

        file_signals: dict[str, dict[str, Any]] = {}

        # Magika mismatches
        for path, mr in self._context.magika_results.items():
            if not mr.content_type_match:
                file_signals.setdefault(
                    path,
                    {
                        "path": path,
                        "signals": [],
                        "sources": set(),
                        "max_severity": "info",
                    },
                )
                file_signals[path]["signals"].append(f"magika_mismatch:{mr.label}")
                file_signals[path]["sources"].add("magika")

        # Findings
        for f in self._context.collection.findings:
            if not f.file_path:
                continue
            file_signals.setdefault(
                f.file_path,
                {
                    "path": f.file_path,
                    "signals": [],
                    "sources": set(),
                    "max_severity": "info",
                },
            )
            file_signals[f.file_path]["signals"].append(f"{f.source.value}:{f.rule_id}")
            file_signals[f.file_path]["sources"].add(f.source.value)
            # Track max severity
            current = SeverityLevel.from_string(
                file_signals[f.file_path]["max_severity"]
            )
            if f.severity.numeric_rank > current.numeric_rank:
                file_signals[f.file_path]["max_severity"] = f.severity.value

        # Filter to truly suspicious
        suspicious = []
        for path, info in file_signals.items():
            source_count = len(info["sources"])
            is_multi_tool = source_count >= 2
            is_critical = info["max_severity"] == "critical"
            has_mismatch = any("magika_mismatch" in s for s in info["signals"])

            if is_multi_tool or is_critical or has_mismatch:
                suspicious.append(
                    {
                        "path": info["path"],
                        "signal_count": len(info["signals"]),
                        "source_count": source_count,
                        "sources": sorted(info["sources"]),
                        "max_severity": info["max_severity"],
                        "magika_mismatch": has_mismatch,
                        "signals": info["signals"][:10],  # cap for display
                    }
                )

        # Sort by signal count (most suspicious first)
        return sorted(
            suspicious,
            key=lambda x: (
                -SeverityLevel.from_string(x["max_severity"]).numeric_rank,
                -x["signal_count"],
            ),
        )
