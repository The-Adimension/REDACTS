"""
CWE enrichment step — adds CWE names and backfills recommendations.

Post-processing step that runs after findings are collected but before
final risk calculation.  Enriches ``InvestigationFinding`` instances
with human-readable CWE weakness names and generic MITRE mitigations
when no tool-specific recommendation exists.

**Offline only** — uses the bundled :class:`knowledge.CweDatabase`.
"""

from __future__ import annotations

import logging

from ..step_protocol import InvestigationContext, StepResult
from ...knowledge.cwe_database import CweDatabase

logger = logging.getLogger(__name__)


class CweEnrichmentStep:
    """Enrich accumulated findings with CWE names and recommendations.

    Reads ``context.all_findings`` and mutates them in-place.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "cwe_enrichment"

    def __init__(self, cwe_db: CweDatabase) -> None:
        self._cwe_db = cwe_db

    def execute(self, context: InvestigationContext) -> StepResult:
        enriched = 0
        backfilled = 0

        for finding in context.all_findings:
            cwe_id = finding.cwe_id
            if not cwe_id:
                continue

            # Enrich name
            name = self._cwe_db.get_name(cwe_id)
            if name:
                finding.cwe_name = name
                enriched += 1

            # Backfill recommendation from MITRE if the tool gave none
            if not finding.recommendation:
                rec = self._cwe_db.get_recommendation(cwe_id)
                if rec:
                    finding.recommendation = rec
                    backfilled += 1

        logger.info(
            "CWE enrichment: %d names resolved, %d recommendations backfilled",
            enriched,
            backfilled,
        )

        return StepResult(
            report_updates={
                "cwe_names_enriched": enriched,
                "cwe_recommendations_backfilled": backfilled,
            },
        )
