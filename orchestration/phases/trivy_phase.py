"""
Trivy scan phase — dependency CVE scanning and secret detection.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class TrivyPhase:
    """Phase 3b: Run Trivy for dependency CVE scanning and secret detection."""

    name: str = "trivy"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_trivy:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("trivy", False):
            return PhaseResult(skipped=True)

        logger.info("Phase 3b: Trivy scan…")

        try:
            from ...investigation.trivy_adapter import TrivyAdapter

            adapter = TrivyAdapter()

            config: dict[str, Any] = {
                "timeout": context.config.tool_timeout,
                "scanners": context.config.trivy_scanners,
            }
            if context.config.trivy_severity:
                config["severity"] = context.config.trivy_severity

            result = adapter.run(context.target_path, config)

            if result.success:
                findings = result.parsed_data.get("unified_findings", [])

                # Delta-aware: keep only findings whose file_path is in
                # the delta set.  Trivy CVEs on stock composer.lock that
                # is identical in both reference and target are NOT new
                # exploitation indicators — they're pre-existing bugs.
                if context.only_files is not None:
                    before = len(findings)
                    findings = [
                        f
                        for f in findings
                        if getattr(f, "file_path", "") in context.only_files
                    ]
                    logger.debug(
                        "  Trivy delta filter: %d → %d findings",
                        before,
                        len(findings),
                    )

                added = context.collection.add_many(findings)
                cve_count = result.parsed_data.get("cve_findings_count", 0)
                secret_count = result.parsed_data.get("secret_findings_count", 0)
                logger.info(
                    "  Trivy: %d CVEs, %d secrets (%d new findings) in %.1fs",
                    cve_count,
                    secret_count,
                    added,
                    result.execution_time_seconds,
                )
            else:
                logger.warning("  Trivy: scan failed — %s", result.errors)

            # SBOM generation
            if context.config.generate_sbom and result.success:
                sbom_dir = (
                    Path(context.config.sbom_output_path).parent
                    if context.config.sbom_output_path
                    else context.output_dir
                )
                sbom_dir.mkdir(parents=True, exist_ok=True)
                sbom_path = Path(
                    context.config.sbom_output_path
                    or str(sbom_dir / "redacts-sbom.json")
                )
                sbom_result = adapter.run_sbom(context.target_path, sbom_path)
                if sbom_result.success:
                    logger.info("  Trivy: SBOM generated at %s", sbom_path)

        except Exception as exc:
            logger.error("  Trivy phase failed: %s", exc)

        return PhaseResult()
