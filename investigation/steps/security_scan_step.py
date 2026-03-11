"""
Security scan step — runs the rule-based security scanner.

Extracted from ``Investigator._run_security_scan``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from ..step_protocol import InvestigationContext, StepResult
from ..step_protocol import InvestigationFinding
from ...forensics.security_scanner import SecurityScanner

logger = logging.getLogger(__name__)


class SecurityScanStep:
    """Run the rule-based security scanner.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "security_scan"

    def __init__(self, security_scanner: SecurityScanner) -> None:
        self._scanner = security_scanner

    # ── protocol entry point ─────────────────────────────────────────────

    def execute(self, context: InvestigationContext) -> StepResult:
        summary, findings = self._run_security_scan(
            context.root, only_files=context.only_files
        )
        return StepResult(
            findings=findings,
            report_updates={"security_scan_summary": summary},
        )

    # ── implementation (moved verbatim from Investigator) ────────────────

    def _run_security_scan(
        self, root: Path, *, only_files: Optional[set[str]] = None
    ) -> tuple[dict[str, Any], list[InvestigationFinding]]:
        """Run security scanner and convert results to investigation findings."""
        if only_files is not None:
            sec_report = self._scanner.scan_files(root, only_files)
        else:
            sec_report = self._scanner.scan_directory(root)
        summary = sec_report.to_dict()

        findings: list[InvestigationFinding] = []
        for sf in sec_report.findings:
            findings.append(
                InvestigationFinding(
                    id="",
                    source="security_scan",
                    severity=sf.severity,
                    title=f"[{sf.rule}] {sf.message[:100]}",
                    description=sf.message,
                    file_path=sf.file,
                    line=sf.line,
                    conclusiveness=(
                        "conclusive"
                        if sf.severity == "CRITICAL"
                        else "suspicious" if sf.severity == "HIGH" else "informational"
                    ),
                    category=sf.category,
                    recommendation=sf.recommendation,
                    cwe_id=sf.cwe,
                    evidence={
                        "rule": sf.rule,
                        "snippet": sf.snippet[:200] if sf.snippet else "",
                    },
                )
            )

        return summary, findings
