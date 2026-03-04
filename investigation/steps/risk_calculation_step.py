"""
Risk calculation step — derives overall risk level from findings.

Extracted from ``Investigator._calculate_risk_level``.
"""

from __future__ import annotations

import logging

from ..step_protocol import InvestigationContext, StepResult, count_by
from ..step_protocol import InvestigationFinding

logger = logging.getLogger(__name__)


class RiskCalculationStep:
    """Calculate the overall risk level from accumulated findings.

    Reads ``context.all_findings``.  No external dependencies required.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "risk_calculation"

    # ── protocol entry point ─────────────────────────────────────────────

    def execute(self, context: InvestigationContext) -> StepResult:
        level, summary = self._calculate_risk_level(context.all_findings)
        return StepResult(
            report_updates={
                "overall_risk_level": level,
                "risk_summary": summary,
            },
        )

    # ── implementation (moved verbatim from Investigator) ────────────────

    def _calculate_risk_level(
        self, findings: list[InvestigationFinding]
    ) -> tuple[str, str]:
        """
        Calculate overall risk level and a human-readable summary.

        Returns:
            ``(level, summary)`` where level is one of
            CRITICAL / HIGH / MEDIUM / LOW / CLEAN.
        """
        if not findings:
            return "CLEAN", "No findings — no indicators of compromise detected."

        conclusive_count = sum(1 for f in findings if f.conclusiveness == "conclusive")
        suspicious_count = sum(1 for f in findings if f.conclusiveness == "suspicious")
        _ = sum(1 for f in findings if f.conclusiveness == "informational")

        severity_counts = count_by(findings, "severity")
        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        medium = severity_counts.get("MEDIUM", 0)

        # Determine level
        if conclusive_count > 0 or critical > 0:
            level = "CRITICAL"
            summary = (
                f"CRITICAL: {conclusive_count} conclusive compromise indicator(s) "
                f"detected across {len(findings)} total findings. "
                f"{critical} CRITICAL, {high} HIGH severity issues. "
                "Immediate incident response recommended."
            )
        elif suspicious_count >= 3 or high >= 3:
            level = "HIGH"
            summary = (
                f"HIGH: {suspicious_count} suspicious indicator(s) detected "
                f"across {len(findings)} total findings. "
                f"{high} HIGH, {medium} MEDIUM severity issues. "
                "Detailed review required."
            )
        elif suspicious_count >= 1 or high >= 1 or medium >= 3:
            level = "MEDIUM"
            summary = (
                f"MEDIUM: {suspicious_count} suspicious indicator(s) and "
                f"{medium} MEDIUM severity issues across {len(findings)} findings. "
                "Further investigation recommended."
            )
        elif len(findings) > 0:
            level = "LOW"
            summary = (
                f"LOW: {len(findings)} minor/informational finding(s). "
                "No compromise indicators detected but review recommended."
            )
        else:
            level = "CLEAN"
            summary = "No findings."

        return level, summary
