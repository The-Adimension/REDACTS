"""External tool adapter step.

Wraps :class:`ExternalToolRunner` --- YARA, PHP lint, Lizard, etc. ---
and converts whichever subset of their output the investigator
recognises (currently only YARA) into ``InvestigationFinding``
records.  Other tools' output is preserved in the report-updates
payload but does not produce findings here; that's a deliberate
under-claim: false-positive load from external scanners is high and
mapping their output onto our severity ladder requires per-tool work.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ...scanners.external import ExternalToolRunner
from ..step_protocol import (
    InvestigationContext,
    InvestigationFinding,
    StepResult,
)

logger = logging.getLogger(__name__)

__all__ = ["ExternalToolsStep"]


class ExternalToolsStep:
    """Run external tool adapters and convert results.

    Skips execution when ``context.run_external_tools`` is ``False``.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "external_tools"

    def __init__(self, external_runner: ExternalToolRunner) -> None:
        self._runner = external_runner

    # --- protocol entry point --------

    def execute(self, context: InvestigationContext) -> StepResult:
        if not context.run_external_tools:
            return StepResult()

        summary, findings = self._run_external_tools(
            context.root, context.output_dir, only_files=context.only_files
        )
        return StepResult(
            findings=findings,
            report_updates={"external_tools_summary": summary},
        )

    # --- implementation --------------

    def _run_external_tools(
        self, root: Path, output_dir: Path, *, only_files: set[str] | None = None
    ) -> tuple[dict[str, Any], list[InvestigationFinding]]:
        """Run external tools and convert usable findings."""
        config: dict[str, Any] = {}
        if only_files is not None:
            config["only_files"] = only_files
        ext_report = self._runner.run_all(
            target_path=root, output_dir=output_dir, config=config
        )
        summary = ext_report.to_dict()

        findings: list[InvestigationFinding] = []

        for tool_name, result in ext_report.results.items():
            if not result.success:
                continue

            parsed = result.parsed_data

            # YARA matches -> high-severity findings
            if tool_name == "yara" and parsed.get("matches"):
                for ym in parsed["matches"]:
                    findings.append(
                        InvestigationFinding(
                            id="",
                            source="external_tool",
                            severity="HIGH",
                            title=f"YARA match: {ym.get('rule', '?')}",
                            description=f"YARA rule '{ym.get('rule', '')}' matched in {ym.get('target', '')}",
                            file_path=ym.get("target", ""),
                            line=0,
                            conclusiveness="suspicious",
                            category="malware",
                            recommendation="Investigate YARA match - may indicate malware or IoC.",
                            evidence={"tool": tool_name, "match": ym},
                        )
                    )

        logger.info(
            "External tool finding conversion: %d findings from %d tool results",
            len(findings),
            sum(1 for r in ext_report.results.values() if r.success),
        )
        return summary, findings
