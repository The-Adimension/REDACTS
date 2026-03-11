"""
REDACTS Investigator — Tier 2 Analysis Orchestrator.

Takes an evidence package directory (or raw source directory) and runs
systematic analysis to produce investigation findings:
    1. IoC scanning (match filesystem against known indicators)
    2. Attack vector assessment (evaluate exposure to 30+ vectors)
    3. Sensitive data detection (PHI/credentials/PII)
    4. Security scanning (existing 38+ SEC rules)
    5. Configuration integrity checking (database.php, .htaccess, .user.ini,
       hook_functions.php)
    6. External tool enrichment (PHP lint, Lizard, Radon, YARA, etc.)
    7. Finding consolidation and severity assessment
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from ..core import REDACTSConfig
from ..knowledge import (
    AttackVectorDatabase,
    IoCDatabase,
    SensitiveDataScanner,
)
from ..knowledge.cwe_database import CweDatabase
from ..forensics.security_scanner import SecurityScanner
from ..forensics.tree_sitter_analyzer import TreeSitterAnalyzer
from .external_tools import ExternalToolRunner
from .step_protocol import (
    ConfigIntegrityResult,
    InvestigationContext,
    InvestigationFinding,
    StepResult,
    count_by,
)
from .steps import (
    AttackVectorStep,
    ConfigIntegrityStep,
    CweEnrichmentStep,
    ExternalToolsStep,
    IocScanStep,
    RiskCalculationStep,
    SecurityScanStep,
    SensitiveDataStep,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class InvestigationReport:
    """Complete Tier 2 investigation report."""

    evidence_id: str = ""
    evidence_label: str = ""
    investigation_timestamp: str = ""
    investigation_duration_seconds: float = 0.0

    # Findings
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_source: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    findings: list[InvestigationFinding] = field(default_factory=list)

    # Sub-reports
    config_integrity: Optional[ConfigIntegrityResult] = None
    sensitive_data_summary: Optional[dict] = None
    external_tools_summary: Optional[dict] = None
    security_scan_summary: Optional[dict] = None

    # Risk assessment
    overall_risk_level: str = "CLEAN"
    risk_summary: str = ""
    conclusive_indicators: int = 0

    # Attack vector coverage
    vectors_assessed: int = 0
    vectors_with_findings: int = 0

    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full report to a JSON-safe dict."""
        return {
            "evidence_id": self.evidence_id,
            "evidence_label": self.evidence_label,
            "investigation_timestamp": self.investigation_timestamp,
            "investigation_duration_seconds": round(
                self.investigation_duration_seconds, 3
            ),
            "total_findings": self.total_findings,
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_by_source": dict(self.findings_by_source),
            "findings_by_category": dict(self.findings_by_category),
            "findings": [f.to_dict() for f in self.findings],
            "config_integrity": (
                self.config_integrity.to_dict() if self.config_integrity else None
            ),
            "sensitive_data_summary": self.sensitive_data_summary,
            "external_tools_summary": self.external_tools_summary,
            "security_scan_summary": self.security_scan_summary,
            "overall_risk_level": self.overall_risk_level,
            "risk_summary": self.risk_summary,
            "conclusive_indicators": self.conclusive_indicators,
            "vectors_assessed": self.vectors_assessed,
            "vectors_with_findings": self.vectors_with_findings,
            "errors": list(self.errors),
        }


# ---------------------------------------------------------------------------
# Investigator
# ---------------------------------------------------------------------------


class Investigator:
    """
    Tier 2: Investigates evidence against knowledge bases and external tools.

    Usage::

        inv = Investigator()
        report = inv.investigate(
            target_path="/evidence/redcap_14.5.0",
            output_dir="/reports",
            evidence_id="EVD-001",
            evidence_label="REDCap 14.5.0 production snapshot",
        )
        print(report.overall_risk_level)
    """

    def __init__(
        self,
        config: Optional[REDACTSConfig] = None,
        *,
        ioc_db: Optional[IoCDatabase] = None,
        attack_db: Optional[AttackVectorDatabase] = None,
        sensitive_scanner: Optional[SensitiveDataScanner] = None,
        security_scanner: Optional[SecurityScanner] = None,
        php_analyzer: Optional[TreeSitterAnalyzer] = None,
        external_runner: Optional[ExternalToolRunner] = None,
    ) -> None:
        self.config = config or REDACTSConfig()

        # ── Dependency injection (defaults preserve original behaviour) ──
        self.ioc_db = ioc_db or IoCDatabase()
        self.attack_db = attack_db or AttackVectorDatabase()
        self.sensitive_scanner = sensitive_scanner or SensitiveDataScanner()
        self.security_scanner = security_scanner or SecurityScanner()
        self.php_analyzer = php_analyzer or TreeSitterAnalyzer()
        self.external_runner = external_runner or ExternalToolRunner()

        # ── Investigation steps (Strategy pattern) ───────────────────────
        #  Finding-producing steps (order matters — determines INV-NNN IDs)
        self._finding_steps: list = [
            IocScanStep(ioc_db=self.ioc_db),
            ConfigIntegrityStep(ioc_db=self.ioc_db, php_analyzer=self.php_analyzer),
            SecurityScanStep(security_scanner=self.security_scanner),
            SensitiveDataStep(sensitive_scanner=self.sensitive_scanner),
            ExternalToolsStep(external_runner=self.external_runner),
        ]
        #  Post-processing steps (operate on accumulated findings)
        self._cwe_db = CweDatabase()
        self._post_steps: list = [
            AttackVectorStep(attack_db=self.attack_db),
            CweEnrichmentStep(cwe_db=self._cwe_db),
            RiskCalculationStep(),
        ]

    # ── Step registry (plugin-ready) ─────────────────────────────────────

    @property
    def steps(self) -> list:
        """All investigation steps in execution order."""
        return list(self._finding_steps) + list(self._post_steps)

    def register_finding_step(self, step: object, *, index: int = -1) -> None:
        """Insert a finding-producing step at *index* (default: append)."""
        if index < 0:
            self._finding_steps.append(step)
        else:
            self._finding_steps.insert(index, step)

    def register_post_step(self, step: object, *, index: int = -1) -> None:
        """Insert a post-processing step at *index* (default: append)."""
        if index < 0:
            self._post_steps.append(step)
        else:
            self._post_steps.insert(index, step)

    # ── public API ────────────────────────────────────────────────────────

    def investigate(
        self,
        target_path: str,
        output_dir: str,
        evidence_id: str = "",
        evidence_label: str = "",
        run_external_tools: bool = True,
        progress_callback: Optional[Callable[[str, float], None]] = None,
        only_files: Optional[set[str]] = None,
    ) -> InvestigationReport:
        """
        Run full Tier 2 investigation.

        Steps:
            1. Determine if *target_path* is evidence package (has
               ``manifest.json``) or raw directory.
            2. Run IoC scanning.
            3. Run configuration integrity checks.
            4. Run security scanning.
            5. Run sensitive data scanning.
            6. Run external tools (if enabled).
            7. Cross-reference findings with attack vectors.
            8. Consolidate and assess overall risk.

        Args:
            target_path: Evidence package directory or raw source directory.
            output_dir: Where to write investigation artefacts.
            evidence_id: Identifier for the evidence package (optional).
            evidence_label: Human-readable label (optional).
            run_external_tools: Whether to invoke external tool adapters.
            progress_callback: ``callback(stage_name, pct)`` for progress.
            only_files: If provided, restrict ALL scans (IoC, security,
                sensitive data, external tools) to this set of relative
                paths only.  Used by ``audit`` mode after baseline diff.

        Returns:
            A fully populated :class:`InvestigationReport`.
        """
        t0 = time.monotonic()
        root = Path(target_path).resolve()
        out = Path(output_dir).resolve()
        inv_dir = out / "investigation"
        inv_dir.mkdir(parents=True, exist_ok=True)

        report = InvestigationReport(
            evidence_id=evidence_id,
            evidence_label=evidence_label,
            investigation_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # ── 1. Load manifest if evidence package ─────────────────────────
        self._notify(progress_callback, "loading_metadata", 0.0)
        manifest_path = root / "manifest.json"
        if manifest_path.is_file():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
                report.evidence_id = report.evidence_id or manifest_data.get(
                    "evidence_id", ""
                )
                report.evidence_label = report.evidence_label or manifest_data.get(
                    "label", ""
                )
                logger.info("Evidence package detected — id=%s", report.evidence_id)
            except Exception as exc:
                msg = f"Failed to parse manifest.json: {exc}"
                logger.warning(msg)
                report.errors.append(msg)
        else:
            logger.info("No manifest.json — treating %s as raw source directory", root)

        if not root.is_dir():
            report.errors.append(f"Target path is not a directory: {root}")
            report.overall_risk_level = "CLEAN"
            report.risk_summary = "Unable to investigate — target missing."
            report.investigation_duration_seconds = time.monotonic() - t0
            return report

        all_findings: list[InvestigationFinding] = []

        context = InvestigationContext(
            root=root,
            output_dir=inv_dir,
            only_files=only_files,
            run_external_tools=run_external_tools,
        )

        # Progress percentages (preserves original notification order)
        _progress: dict[str, float] = {
            "ioc_scan": 0.10,
            "config_integrity": 0.25,
            "security_scan": 0.40,
            "sensitive_data": 0.55,
            "external_tools": 0.70,
            "attack_vector": 0.85,
            "risk_calculation": 0.95,
        }

        # ── Finding-producing steps ──────────────────────────────────────
        for step in self._finding_steps:
            self._notify(progress_callback, step.name, _progress.get(step.name, 0))
            try:
                result = step.execute(context)
                all_findings.extend(result.findings)
                for key, val in result.report_updates.items():
                    setattr(report, key, val)
                logger.info("%s produced %d findings", step.name, len(result.findings))
            except Exception as exc:
                msg = f"{step.name} failed: {exc}"
                logger.error(msg, exc_info=True)
                report.errors.append(msg)

        # ── Assign incremental IDs ───────────────────────────────────────
        for idx, finding in enumerate(all_findings, start=1):
            finding.id = f"INV-{idx:03d}"

        # ── Post-processing steps (read accumulated findings) ────────────
        context.all_findings = all_findings
        for step in self._post_steps:
            self._notify(progress_callback, step.name, _progress.get(step.name, 0))
            try:
                result = step.execute(context)
                for key, val in result.report_updates.items():
                    setattr(report, key, val)
            except Exception as exc:
                msg = f"{step.name} failed: {exc}"
                logger.error(msg, exc_info=True)
                report.errors.append(msg)

        # ── Consolidate ──────────────────────────────────────────────────
        self._notify(progress_callback, "consolidation", 0.95)
        report.findings = all_findings
        report.total_findings = len(all_findings)
        report.findings_by_severity = count_by(all_findings, "severity")
        report.findings_by_source = count_by(all_findings, "source")
        report.findings_by_category = count_by(all_findings, "category")
        report.conclusive_indicators = sum(
            1 for f in all_findings if f.conclusiveness == "conclusive"
        )

        report.investigation_duration_seconds = time.monotonic() - t0

        # ── Persist results ──────────────────────────────────────────────
        self._write_results(report, inv_dir)

        self._notify(progress_callback, "complete", 1.0)
        logger.info(
            "Investigation complete — %d findings, risk=%s, duration=%.1fs",
            report.total_findings,
            report.overall_risk_level,
            report.investigation_duration_seconds,
        )
        return report

    # ── Persistence ──────────────────────────────────────────────────────

    def _write_results(self, report: InvestigationReport, inv_dir: Path) -> None:
        """Write investigation artefacts to disk."""
        try:
            report_path = inv_dir / "investigation_report.json"
            report_path.write_text(
                json.dumps(report.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            logger.info("Investigation report written to %s", report_path)
        except Exception as exc:
            logger.error("Failed to write investigation report: %s", exc)
            report.errors.append(f"Failed to write report: {exc}")

        # Write a findings-only file for easy consumption
        try:
            findings_path = inv_dir / "findings.json"
            findings_data = [f.to_dict() for f in report.findings]
            findings_path.write_text(
                json.dumps(findings_data, indent=2, default=str),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.error("Failed to write findings.json: %s", exc)

        # Write summary
        try:
            summary_path = inv_dir / "summary.txt"
            lines = [
                "REDACTS Investigation Summary",
                "=" * 40,
                f"Evidence ID:      {report.evidence_id}",
                f"Evidence Label:   {report.evidence_label}",
                f"Timestamp:        {report.investigation_timestamp}",
                f"Duration:         {report.investigation_duration_seconds:.1f}s",
                "",
                f"Overall Risk:     {report.overall_risk_level}",
                f"{report.risk_summary}",
                "",
                f"Total Findings:   {report.total_findings}",
                f"  CRITICAL:       {report.findings_by_severity.get('CRITICAL', 0)}",
                f"  HIGH:           {report.findings_by_severity.get('HIGH', 0)}",
                f"  MEDIUM:         {report.findings_by_severity.get('MEDIUM', 0)}",
                f"  LOW:            {report.findings_by_severity.get('LOW', 0)}",
                f"  INFO:           {report.findings_by_severity.get('INFO', 0)}",
                "",
                f"Conclusive Indicators: {report.conclusive_indicators}",
                f"Attack Vectors Assessed: {report.vectors_assessed}",
                f"Attack Vectors with Findings: {report.vectors_with_findings}",
                "",
                f"Errors: {len(report.errors)}",
            ]
            for err in report.errors:
                lines.append(f"  - {err}")
            summary_path.write_text("\n".join(lines), encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to write summary.txt: %s", exc)

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _notify(
        callback: Optional[Callable[[str, float], None]],
        stage: str,
        pct: float,
    ) -> None:
        """Fire progress callback if provided."""
        if callback is not None:
            try:
                callback(stage, pct)
            except Exception:
                pass
