"""
Magika file-typing phase — route files by content type.

Populates :attr:`OrchestratorContext.magika_results` and generates
mismatch findings.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ...core.constants import get_skip_dirs
from ...core.models import normalize_magika_mismatch
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class MagikaPhase:
    """Phase 2: Magika file typing (routing intelligence)."""

    name: str = "magika"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_magika:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("magika", False):
            return PhaseResult(skipped=True)

        logger.info("Phase 2: Magika file typing…")

        try:
            from ...forensics.magika_analyzer import MagikaAnalyzer

            analyzer = MagikaAnalyzer()
        except Exception as exc:
            logger.error("Failed to initialize Magika: %s", exc)
            return PhaseResult()

        file_count = 0
        mismatch_count = 0
        _skip = get_skip_dirs()

        for dirpath, dirnames, filenames in os.walk(context.target_path):
            dirnames[:] = [d for d in dirnames if d not in _skip]
            for fn in filenames:
                fp = Path(dirpath) / fn
                try:
                    result = analyzer.identify(fp)
                    rel_path = str(
                        fp.relative_to(context.target_path)
                    ).replace("\\", "/")
                    context.magika_results[rel_path] = result

                    # Generate finding for mismatches — but only for
                    # delta files when running in delta-aware mode
                    if not result.content_type_match:
                        mismatch_count += 1
                        if (
                            context.only_files is None
                            or rel_path in context.only_files
                        ):
                            finding = normalize_magika_mismatch(
                                result, file_path=rel_path
                            )
                            if finding:
                                context.collection.add(finding)

                    file_count += 1
                except Exception as exc:
                    logger.debug("Magika failed on %s: %s", fp, exc)

        logger.info(
            "  Magika: typed %d files, %d mismatches detected",
            file_count,
            mismatch_count,
        )
        return PhaseResult()
