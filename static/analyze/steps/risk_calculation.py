"""Aggregate-level risk derivation.

The thresholds here (``conclusive_count``, ``suspicious_count``, the
``HIGH``/``MEDIUM`` severity caps) are deliberately conservative ---
this is an analysis aid, not an alerting system.  When in doubt the
output skews toward escalation: the cost of a missed conclusive
indicator vastly outweighs the cost of a few extra MEDIUM banners on a
clean tree.
"""

from __future__ import annotations

from ..step_protocol import (
    InvestigationContext,
    InvestigationFinding,
    StepResult,
    count_by,
)

__all__ = ["RiskCalculationStep"]


class RiskCalculationStep:
    """Calculate the overall risk level from accumulated findings.

    Reads ``context.all_findings``.  No external dependencies required.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "risk_calculation"

    # --- protocol entry point --------

    def execute(self, context: InvestigationContext) -> StepResult:
        level, summary = self._calculate_risk_level(context.all_findings)
        return StepResult(
            report_updates={
                "overall_risk_level": level,
                "risk_summary": summary,
            },
        )

    # --- implementation --------------

    def _calculate_risk_level(
        self, findings: list[InvestigationFinding]
    ) -> tuple[str, str]:
        """Calculate overall risk level and a human-readable summary."""
        if not findings:
            return "CLEAN", "No findings - no indicators of compromise detected."

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
