"""
DAST phase — Playwright-based dynamic application security testing.
"""

from __future__ import annotations

import logging

from ...core.models import (
    Confidence,
    FindingSource,
    UnifiedFinding,
    normalize_dast_result,
)
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class DastPhase:
    """Phase 6: Run Playwright-based DAST against a live REDCap stack.

    Requires Docker + Docker Compose.  Spins up the MariaDB/REDCap/Playwright
    stack defined in ``dast/docker-compose.dast.yml``, executes the selected
    test suites, normalises the results into :class:`UnifiedFinding` objects,
    then tears the stack down (unless ``dast_keep_stack`` is set).

    Any DAST failures produce findings with ``Confidence.CONFIRMED`` because
    they are *observed* runtime behaviours, not heuristic guesses.
    """

    name: str = "dast"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_dast:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("dast"):
            logger.info("Phase 6 — DAST: skipped (Docker/Compose not available)")
            return PhaseResult(skipped=True)

        logger.info("Phase 6 — DAST: running dynamic validation")

        try:
            from ...dast.orchestrator import DASTOrchestrator

            # Output results outside the scan target (forensic integrity)
            dast_output = context.output_dir / "dast-results"
            dast_output.mkdir(parents=True, exist_ok=True)
            dast = DASTOrchestrator(
                output_dir=str(dast_output),
                suites=context.config.dast_suites,
                timeout=context.config.dast_timeout,
                keep_stack=context.config.dast_keep_stack,
                redcap_version=context.config.redcap_version,
                dast_port=context.config.dast_port,
            )
            dast_result = dast.run()

            if dast_result is None:
                logger.warning("  DAST returned no results")
                return PhaseResult()

            # Normalise each test result into a UnifiedFinding
            passed = 0
            failed = 0
            for test in dast_result.test_results:
                status = test.get("status", "unknown")
                if status == "passed":
                    passed += 1
                    continue

                # Failed or errored test -> finding
                failed += 1
                finding = normalize_dast_result(
                    test,
                    suite=test.get("suite", "unknown"),
                )
                if finding is None:
                    continue
                context.collection.add(finding)

                # Cross-reference with static findings
                self._correlate_dast_finding(finding, context)

            logger.info(
                "  DAST complete: %d passed, %d failed → %d findings",
                passed,
                failed,
                failed,
            )

        except FileNotFoundError:
            logger.warning("  DAST module not found — skipping")
        except Exception as exc:
            logger.error("  DAST phase failed: %s", exc)

        return PhaseResult()

    @staticmethod
    def _correlate_dast_finding(
        dast_finding: UnifiedFinding, context: OrchestratorContext
    ) -> None:
        """Cross-reference a DAST finding with earlier static findings.

        If a static tool already flagged the same rule_id, mark both as
        corroborated.  This elevates the static finding to HIGH confidence
        because the DAST result *proves* the static finding is exploitable.
        """
        for f in context.collection.findings:
            if f is dast_finding:
                continue
            if (
                f.rule_id == dast_finding.rule_id
                and f.source != FindingSource.DAST
            ):
                # Static finding confirmed by DAST
                if f.confidence != Confidence.CONFIRMED:
                    f.confidence = Confidence.HIGH
                f.corroborated_by.append("dast")
                f.related_finding_ids.append(dast_finding.id)
                # And vice-versa
                dast_finding.corroborated_by.append(f.source.value)
                dast_finding.related_finding_ids.append(f.id)
