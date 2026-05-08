"""Semgrep AST-based PHP analysis.

Semgrep is the *primary* static analyser for code-level findings; the
regex scanner runs alongside as a corroborating signal.  Note:
Semgrep findings are routed through ``unified_findings`` (already
normalised by the adapter) and filtered through the delta-set when the
investigation is operating in delta-aware mode.
"""

from __future__ import annotations

import logging
from typing import Any

from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)

__all__ = ["SemgrepPhase"]


class SemgrepPhase:
    """Run Semgrep for AST-based PHP security analysis."""

    name: str = "semgrep"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_semgrep:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("semgrep", False):
            return PhaseResult(skipped=True)

        logger.info("Semgrep scan...")

        try:
            from ..semgrep_adapter import SemgrepAdapter

            adapter = SemgrepAdapter()

            config: dict[str, Any] = {
                "timeout": context.config.tool_timeout,
                "rulesets": context.config.semgrep_rulesets,
            }
            if context.config.semgrep_exclude:
                config["exclude"] = context.config.semgrep_exclude

            result = adapter.run(context.target_path, config)

            if result.success:
                findings = result.parsed_data.get("unified_findings", [])

                # Delta-aware: keep only findings on files in the delta set
                if context.only_files is not None:
                    before = len(findings)
                    findings = [
                        f
                        for f in findings
                        if getattr(f, "file_path", "") in context.only_files
                    ]
                    logger.debug(
                        "  Semgrep delta filter: %d -> %d findings",
                        before,
                        len(findings),
                    )

                added = context.collection.add_many(findings)
                logger.info(
                    "  Semgrep: %d findings (%d new) in %.1fs",
                    len(findings),
                    added,
                    result.execution_time_seconds,
                )
            else:
                logger.warning("  Semgrep: scan failed - %s", result.errors)

        except Exception as exc:
            logger.error("  Semgrep phase failed: %s", exc)

        return PhaseResult()
