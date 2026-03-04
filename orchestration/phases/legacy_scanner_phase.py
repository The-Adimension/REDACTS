"""
Legacy SecurityScanner phase — regex-based supplementary hints.
"""

from __future__ import annotations

import logging

from ...core.models import normalize_security_finding
from ...knowledge.mitre_mapping import CVSS_MAP, MITRE_ATTACK_MAP
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class LegacyScannerPhase:
    """Phase 3d: Run the regex-based SecurityScanner as supplementary hints.

    These findings are LOW confidence (regex-based) and serve as
    additional signals.  Semgrep is the primary scanner.
    """

    name: str = "legacy_scanner"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_legacy_scanner:
            return PhaseResult(skipped=True)

        logger.info("Phase 3d: Legacy SecurityScanner…")

        try:
            from ...forensics.security_scanner import SecurityScanner

            scanner = SecurityScanner()

            # Delta-aware: scan only changed files when a delta set is
            # provided.  scan_files() avoids regex-matching every stock
            # REDCap file and dramatically reduces noise.
            if context.only_files is not None:
                report = scanner.scan_files(
                    context.target_path, context.only_files
                )
            else:
                report = scanner.scan_directory(context.target_path)

            for finding in report.findings:
                unified = normalize_security_finding(
                    finding,
                    mitre_map=MITRE_ATTACK_MAP,
                    cvss_map=CVSS_MAP,
                )
                context.collection.add(unified)

            logger.info(
                "  Legacy scanner: %d findings (supplementary)",
                len(report.findings),
            )

        except Exception as exc:
            logger.error("  Legacy scanner phase failed: %s", exc)

        return PhaseResult()
