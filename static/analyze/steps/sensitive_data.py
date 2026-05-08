"""Sensitive data scanner adapter (PHI / PII / credentials)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from threat_base import SensitiveDataScanner

from ..step_protocol import (
    InvestigationContext,
    InvestigationFinding,
    StepResult,
)

logger = logging.getLogger(__name__)

__all__ = ["SensitiveDataStep"]


class SensitiveDataStep:
    """Run the sensitive-data scanner.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "sensitive_data"

    def __init__(self, sensitive_scanner: SensitiveDataScanner) -> None:
        self._scanner = sensitive_scanner

    # --- protocol entry point --------

    def execute(self, context: InvestigationContext) -> StepResult:
        summary, findings = self._run_sensitive_scan(
            context.root, only_files=context.only_files
        )
        return StepResult(
            findings=findings,
            report_updates={"sensitive_data_summary": summary},
        )

    # --- implementation --------------

    def _run_sensitive_scan(
        self, root: Path, *, only_files: set[str] | None = None
    ) -> tuple[dict[str, Any], list[InvestigationFinding]]:
        """Run sensitive data scanner and convert to investigation findings."""
        if only_files is not None:
            sens_report = self._scanner.scan_files(root, only_files)
        else:
            sens_report = self._scanner.scan_directory(root)
        # Dual emission: the ``summary`` field on the step report
        # carries the windowed-snippet view (analyst-grade context
        # bounded by SNIPPET_MAX_BYTES) and ``summary_pointer`` carries
        # the pointer-only view (no snippet bytes, just the integrity
        # tuple) so downstream report writers can choose which audience
        # they are serving without re-running the scan.
        summary = sens_report.to_dict(snippet_mode="windowed")
        summary["pointer_view"] = sens_report.to_dict(snippet_mode="pointer")

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
                        # Snippet view: redacted, windowed, capped.
                        "snippet_redacted": sf.snippet_redacted,
                        "snippet_truncated": sf.snippet_truncated,
                        "snippet_window": list(sf.snippet_window),
                        # Pointer view: re-derivable from the artefact.
                        "column": sf.column,
                        "line_length": sf.line_length,
                        "original_length": sf.original_length,
                        "file_sha256": sf.file_sha256,
                        "hipaa_identifier": sf.hipaa_identifier,
                    },
                )
            )

        return summary, findings
