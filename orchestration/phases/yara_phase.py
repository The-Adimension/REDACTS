"""
YARA scan phase — webshell/backdoor detection with Magika synergy.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ...core.models import Confidence, SeverityLevel, normalize_yara_match
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class YaraPhase:
    """Phase 3c: Run YARA with community rules for webshell/backdoor detection."""

    name: str = "yara"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_yara:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("yara", False):
            return PhaseResult(skipped=True)

        logger.info("Phase 3c: YARA scan…")

        try:
            from ...investigation.external_tools import YaraAdapter

            adapter = YaraAdapter()

            config: dict[str, Any] = {
                "timeout": context.config.tool_timeout,
                "use_community_rules": context.config.yara_community_rules,
            }
            if context.config.yara_rules_path:
                config["rules_path"] = context.config.yara_rules_path

            result = adapter.run(context.target_path, config)

            if result.success:
                matches = result.parsed_data.get("matches", [])
                skipped_delta = 0
                for match in matches:
                    finding = normalize_yara_match(match)

                    # ── Magika synergy ──────────────────────────────────
                    target = match.get("target", "")
                    try:
                        rel = str(
                            Path(target).relative_to(context.target_path)
                        ).replace("\\", "/")
                    except ValueError:
                        rel = target

                    # Delta-aware: skip findings on files outside the
                    # delta set — stock REDCap matches are noise.
                    if (
                        context.only_files is not None
                        and rel not in context.only_files
                    ):
                        skipped_delta += 1
                        continue

                    if rel in context.magika_results:
                        mr = context.magika_results[rel]
                        finding.magika_file_type = mr.label
                        finding.magika_mismatch = not mr.content_type_match
                        if not mr.content_type_match:
                            # YARA + Magika mismatch = highest confidence
                            finding.severity = SeverityLevel.CRITICAL
                            finding.confidence = Confidence.CONFIRMED
                            finding.corroborated_by.append("magika")
                            logger.info(
                                "  YARA+Magika synergy: %s — %s masquerading as %s",
                                finding.rule_id,
                                mr.label,
                                mr.extension_label,
                            )

                    context.collection.add(finding)

                if skipped_delta:
                    logger.info(
                        "  YARA: filtered %d/%d matches to delta set",
                        skipped_delta,
                        len(matches),
                    )
                logger.info(
                    "  YARA: %d matches (%d critical)",
                    len(matches) - skipped_delta,
                    result.parsed_data.get("critical_match_count", 0),
                )
            else:
                logger.warning("  YARA: scan failed — %s", result.errors)

        except Exception as exc:
            logger.error("  YARA phase failed: %s", exc)

        return PhaseResult()
