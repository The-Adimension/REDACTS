"""
Sensitive data scan step — detects PHI/credentials/PII.

Extracted from ``Investigator._run_sensitive_scan``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from ..step_protocol import InvestigationContext, StepResult
from ..step_protocol import InvestigationFinding
from ...knowledge import SensitiveDataScanner

logger = logging.getLogger(__name__)


class SensitiveDataStep:
    """Run the sensitive-data scanner.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "sensitive_data"

    def __init__(self, sensitive_scanner: SensitiveDataScanner) -> None:
        self._scanner = sensitive_scanner

    # ── protocol entry point ─────────────────────────────────────────────

    def execute(self, context: InvestigationContext) -> StepResult:
        summary, findings = self._run_sensitive_scan(
            context.root, only_files=context.only_files
        )
        return StepResult(
            findings=findings,
            report_updates={"sensitive_data_summary": summary},
        )

    # ── implementation (moved verbatim from Investigator) ────────────────

    def _run_sensitive_scan(
        self, root: Path, *, only_files: Optional[set[str]] = None
    ) -> tuple[dict[str, Any], list[InvestigationFinding]]:
        """Run sensitive data scanner and convert to investigation findings."""
        if only_files is not None:
            sens_report = self._scanner.scan_files(root, only_files)
        else:
            sens_report = self._scanner.scan_directory(root)
        summary = sens_report.to_dict()

        findings: list[InvestigationFinding] = []
        for sf in sens_report.findings:
            findings.append(
                InvestigationFinding(
                    id="",
                    source="sensitive_data",
                    severity=sf.severity,
                    title=f"Sensitive data: {sf.data_type}",
                    description=sf.assessment,
                    file_path=sf.file_path,
                    line=sf.line,
                    conclusiveness=(
                        "conclusive"
                        if sf.severity == "CRITICAL"
                        else (
                            "suspicious"
                            if sf.severity in ("HIGH", "MEDIUM")
                            else "informational"
                        )
                    ),
                    category=f"sensitive_{sf.category.lower()}",
                    recommendation=f"Review {sf.data_type} exposure in {sf.file_path}:{sf.line}. Redact or protect.",
                    evidence={
                        "data_type": sf.data_type,
                        "category": sf.category,
                        "snippet_redacted": sf.snippet_redacted,
                        "hipaa_identifier": sf.hipaa_identifier,
                    },
                )
            )

        return summary, findings
