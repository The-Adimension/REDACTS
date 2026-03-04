"""
Cross-tool correlation phase — corroborate findings across tools.
"""

from __future__ import annotations

import logging

from ...core.models import Confidence, FindingSource
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class CorrelatePhase:
    """Phase 5: Cross-tool correlation and Magika enrichment."""

    name: str = "correlate"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        logger.info("Phase 5: Cross-tool correlation…")

        # Enrich all findings with Magika file types
        if context.magika_results:
            context.collection.enrich_with_magika(context.magika_results)

        # Cross-tool corroboration (same file:line from different tools)
        context.collection.correlate()

        # Trivy→Semgrep synergy
        self._apply_trivy_semgrep_synergy(context)

        logger.info(
            "  Correlation: %d findings corroborated by multiple tools",
            len(context.collection.corroborated_findings),
        )
        return PhaseResult()

    @staticmethod
    def _apply_trivy_semgrep_synergy(context: OrchestratorContext) -> None:
        """Cross-reference Trivy CVE findings with Semgrep code findings.

        If a dependency has a known CVE AND Semgrep found vulnerable
        patterns using that dependency, link them together.
        """
        trivy_findings = [
            f
            for f in context.collection.findings
            if f.source == FindingSource.TRIVY and f.cve_id
        ]
        semgrep_findings = [
            f
            for f in context.collection.findings
            if f.source == FindingSource.SEMGREP
        ]

        if not trivy_findings or not semgrep_findings:
            return

        # Build a set of vulnerable component names from Trivy CVEs
        vuln_components: set[str] = set()
        for tf in trivy_findings:
            desc_lower = tf.description.lower()
            for component in desc_lower.split():
                if "/" in component or "-" in component:
                    vuln_components.add(component.strip(".:,()"))

        # Check if any Semgrep findings reference these components
        for sf in semgrep_findings:
            snippet_lower = (sf.snippet or "").lower()
            desc_lower = sf.description.lower()
            for component in vuln_components:
                if component in snippet_lower or component in desc_lower:
                    sf.related_finding_ids.extend(
                        [
                            tf.id
                            for tf in trivy_findings
                            if component in tf.description.lower()
                        ]
                    )
                    sf.corroborated_by.append("trivy")
                    if sf.confidence != Confidence.CONFIRMED:
                        sf.confidence = Confidence.HIGH
                    break
