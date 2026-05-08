"""DAST via Playwright on a live REDCap stack.

Spins up the docker-compose stack defined in
``dynamic/docker-compose.dast.yml``, drives Playwright suites against
it, and normalises results into :class:`UnifiedFinding`.  Failures are
surfaced as ``Confidence.CONFIRMED`` findings: they are *observed*
runtime behaviours, not heuristic guesses --- the same posture
Cuckoo Sandbox takes for behavioural artefacts.

Honest limit: when the stack fails to start (Docker missing, port in
use, image pull failure) the phase emits a CRITICAL DAST-ORCHESTRATION-
ERROR finding and returns.  We do *not* attempt static fall-backs: a
missing dynamic signal is not the same as a clean dynamic signal.
"""

from __future__ import annotations

import logging

from ...core.findings import (
    Confidence,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
    normalize_dast_result,
)
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)

__all__ = ["DastPhase"]


class DastPhase:
    """Run Playwright-based DAST against a live REDCap stack.

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
            logger.info("DAST skipped (Docker/Compose not available)")
            return PhaseResult(skipped=True)

        logger.info("DAST running dynamic validation")

        try:
            from dynamic.orchestrator import DASTOrchestrator

            # Output results outside the scan target (forensic integrity)
            dast_output = context.output_dir / "dast-results"
            dast_output.mkdir(parents=True, exist_ok=True, mode=0o700)
            dast = DASTOrchestrator(
                output_dir=str(dast_output),
                suites=context.config.dast_suites,
                timeout=context.config.dast_timeout,
                keep_stack=context.config.dast_keep_stack,
                redcap_version=context.config.redcap_version,
                dast_port=context.config.dast_port,
                package=context.config.dast_package,
            )

            dast_result = dast.run()

            if dast_result is None:
                logger.warning("  DAST returned no results")
                return PhaseResult()

            # Surface orchestration errors as CRITICAL findings AND
            # propagate them to ``phase_failures`` so the workflow's
            # exit-code path treats the run as failed. Recording the
            # finding alone would let the CLI summary print
            # "no errors" while the analyst log shows DAST FAILED ---
            # exactly the kind of dishonest summary the contract-as-
            # source-of-truth design is meant to prevent.
            if dast_result.errors:
                for err_msg in dast_result.errors:
                    logger.error("  DAST orchestration error: %s", err_msg)
                    error_finding = UnifiedFinding(
                        id="",
                        rule_id="DAST-ORCHESTRATION-ERROR",
                        title="DAST orchestration failed",
                        description=(
                            f"The DAST phase could not execute properly: {err_msg}. "
                            "Dynamic security tests were NOT performed - the "
                            "scan results lack runtime validation coverage."
                        ),
                        severity=SeverityLevel.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        source=FindingSource.DAST,
                        category="dast-error",
                        recommendation=(
                            "Investigate and resolve the DAST infrastructure "
                            "failure, then re-run the scan to obtain dynamic "
                            "security coverage."
                        ),
                        tool_name="dast",
                        evidence={"error": err_msg, "suites_requested": context.config.dast_suites},
                    )
                    context.collection.add(error_finding)

                logger.error(
                    "  DAST FAILED: %d error(s) - dynamic coverage NOT obtained",
                    len(dast_result.errors),
                )
                # Record runtime failure for the workflow exit-code path
                # and downgrade availability so the per-tool status line
                # reads "dast: SKIPPED" instead of the misleading "OK".
                context.tool_availability["dast"] = False
                first_err = dast_result.errors[0]
                context.phase_failures.append(
                    (self.name, f"DASTOrchestrationError: {first_err}")
                )
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
                "  DAST complete: %d passed, %d failed -> %d findings",
                passed,
                failed,
                failed,
            )

        except FileNotFoundError:
            logger.warning("  DAST module not found - skipping")
        except Exception as exc:
            logger.error("  DAST phase failed: %s", exc)
            error_finding = UnifiedFinding(
                id="",
                rule_id="DAST-PHASE-ERROR",
                title="DAST phase crashed",
                description=(
                    f"An unhandled error prevented DAST execution: {exc}. "
                    "Dynamic security tests were NOT performed."
                ),
                severity=SeverityLevel.CRITICAL,
                confidence=Confidence.CONFIRMED,
                source=FindingSource.DAST,
                category="dast-error",
                recommendation=(
                    "Check Docker/Compose availability and resolve the error, "
                    "then re-run the scan for dynamic coverage."
                ),
                tool_name="dast",
                evidence={"error": str(exc)},
            )
            context.collection.add(error_finding)

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
