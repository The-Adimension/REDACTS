"""
Attack vector assessment step — cross-references findings against vectors.

Extracted from ``Investigator._assess_attack_vectors``.
"""

from __future__ import annotations

import logging
import re

from ..step_protocol import InvestigationContext, StepResult
from ..step_protocol import InvestigationFinding
from ...knowledge import AttackVectorDatabase

logger = logging.getLogger(__name__)


class AttackVectorStep:
    """Cross-reference accumulated findings against the attack vector DB.

    Annotates findings with related attack vector IDs.  Reads
    ``context.all_findings`` (populated by the orchestrator before this
    step runs).

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "attack_vector"

    def __init__(self, attack_db: AttackVectorDatabase) -> None:
        self._attack_db = attack_db

    # ── protocol entry point ─────────────────────────────────────────────

    def execute(self, context: InvestigationContext) -> StepResult:
        vectors_assessed, vectors_with_findings = self._assess_attack_vectors(
            context.all_findings
        )
        return StepResult(
            report_updates={
                "vectors_assessed": vectors_assessed,
                "vectors_with_findings": vectors_with_findings,
            },
        )

    # ── implementation (moved verbatim from Investigator) ────────────────

    def _assess_attack_vectors(
        self, findings: list[InvestigationFinding]
    ) -> tuple[int, int]:
        """
        Cross-reference findings against the attack vector database.

        Annotates findings with related attack vector IDs and returns
        counts of assessed vectors and vectors with findings.
        """
        all_vectors = self._attack_db.all_vectors
        vectors_with_hits: set[str] = set()

        for vector in all_vectors:
            # Build keyword set from vector artifacts and patterns
            keywords: set[str] = set()
            for artifact in vector.filesystem_artifacts:
                words = [
                    w.lower() for w in re.split(r"[\s,./\\]+", artifact) if len(w) > 3
                ]
                keywords.update(words)
            for pat in vector.detection_patterns:
                words = [w.lower() for w in re.split(r"[\s,./\\]+", pat) if len(w) > 3]
                keywords.update(words)

            # Also match on related IoC IDs
            related_ioc_set = set(vector.related_iocs)

            for finding in findings:
                matched = False

                # Match by overlapping IoC IDs
                if related_ioc_set and related_ioc_set.intersection(
                    finding.related_ioc_ids
                ):
                    matched = True

                # Match by keyword overlap in finding title/description/category
                if not matched and keywords:
                    finding_text = (
                        f"{finding.title} {finding.description} {finding.category}"
                    ).lower()
                    if any(kw in finding_text for kw in keywords):
                        matched = True

                if matched:
                    if vector.id not in finding.related_attack_vector_ids:
                        finding.related_attack_vector_ids.append(vector.id)
                    vectors_with_hits.add(vector.id)

        return len(all_vectors), len(vectors_with_hits)
