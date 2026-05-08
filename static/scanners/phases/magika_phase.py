"""Magika-based file typing for masquerade detection.

Routes content-type metadata into ``context.magika_results`` and emits
findings for files whose declared extension does not match their
detected type.  This signals masquerading content (e.g. PHP webshell
stored as ``.jpg``).
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ...core.constants import get_skip_dirs
from ...core.findings import normalize_magika_mismatch
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)

__all__ = ["MagikaPhase"]


class MagikaPhase:
    """Magika file typing (routing intelligence)."""

    name: str = "magika"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_magika:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("magika", False):
            return PhaseResult(skipped=True)

        logger.info("Magika file typing...")

        try:
            from ..magika_adapter import MagikaAnalyzer

            analyzer = MagikaAnalyzer()
        except Exception as exc:
            logger.error("Failed to initialize Magika: %s", exc)
            return PhaseResult()

        file_count = 0
        mismatch_count = 0
        skipped_size = 0
        _skip = get_skip_dirs()
        _max_bytes = context.max_file_size_mb * 1_048_576

        for dirpath, dirnames, filenames in os.walk(context.target_path):
            dirnames[:] = [d for d in dirnames if d not in _skip]
            for fn in filenames:
                fp = Path(dirpath) / fn
                try:
                    fsize = fp.stat().st_size
                    if fsize > _max_bytes:
                        skipped_size += 1
                        continue

                    result = analyzer.identify(fp)
                    rel_path = str(
                        fp.relative_to(context.target_path)
                    ).replace("\\", "/")
                    context.magika_results[rel_path] = result

                    # Generate finding for mismatches - but only for
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
            "  Magika: typed %d files, %d mismatches detected, %d skipped (size)",
            file_count,
            mismatch_count,
            skipped_size,
        )
        return PhaseResult()
