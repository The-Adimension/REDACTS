"""Regex-based :class:`SecurityScanner` used as a corroborating low-confidence signal.

These findings are LOW confidence by construction (regex pattern
matching cannot distinguish syntactic context the way Semgrep can).
The phase remains in the pipeline as a corroborating signal: when the
same file:line is flagged by both Semgrep and the regex scanner,
correlation in :class:`~static.scanners.phases.correlate_phase.CorrelatePhase`
elevates the consolidated finding's confidence.
"""

from __future__ import annotations

import logging

from threat_base.mitre_mapping import CVSS_MAP, MITRE_ATTACK_MAP

from ...core.findings import normalize_security_finding
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)

__all__ = ["RegexScannerPhase"]


class RegexScannerPhase:
    """Run the regex-based :class:`SecurityScanner` as supplementary hints.

    These findings are LOW confidence (regex-based) and serve as
    additional signals.  Semgrep is the primary scanner.
    """

    name: str = "regex_scanner"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_regex_scanner:
            return PhaseResult(skipped=True)

        logger.info("Regex SecurityScanner...")

        try:
            from ...analyze.scanner import SecurityScanner

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
                "  Regex scanner: %d findings (supplementary)",
                len(report.findings),
            )

        except Exception as exc:
            logger.error("  Regex scanner phase failed: %s", exc)

        return PhaseResult()
