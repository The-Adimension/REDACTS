"""
REDACTS Audit Pipeline — baseline-driven differential forensics.

Usage::

    python -m REDACTS audit <target> --reference <clean-zip-or-folder> \\
        --version 15.7.4 -o ./audit_output --formats html,json,markdown

Pipeline phases:
    Phase 1  Build SHA-256 manifests for both reference & target trees.
    Phase 2  Structural diff — added / removed / matched files.
    Phase 3  Integrity check — hash-compare matched files.
             Identical files are CLEAN → skipped.
             Mismatched files are MODIFIED → feed to Phase 4.
    Phase 4  Deep forensic analysis scoped to delta set only
             (added files + modified files).

This eliminates ~95 %+ of false positives that plague blind
pattern-matching on stock REDCap code.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from ..core import REDACTSConfig
from ..forensics.baseline_validator import (
    BaselineValidator,
    StructuralDiffResult,
)
from ..investigation.investigator import Investigator, InvestigationReport
from ..loaders import detect_loader, detect_redcap_root

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result data class
# ---------------------------------------------------------------------------


@dataclass
class AuditResult:
    """Complete result from an audit pipeline run."""

    success: bool = False
    timestamp: str = ""
    duration_seconds: float = 0.0
    version: str = ""

    # Paths
    reference_path: str = ""
    target_path: str = ""
    output_dir: str = ""

    # Phase 1-3: baseline diff
    baseline_diff: Optional[dict[str, Any]] = None

    # Phase 4: investigation (scoped to delta)
    investigation: Optional[dict[str, Any]] = None

    # Summary
    reference_file_count: int = 0
    target_file_count: int = 0
    files_identical: int = 0
    files_modified: int = 0
    files_added: int = 0
    files_removed: int = 0
    delta_count: int = 0  # added + modified — files that got deep scanned
    deep_scan_findings: int = 0
    overall_risk_level: str = "CLEAN"
    risk_summary: str = ""

    report_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # In-memory only — holds the full InvestigationReport object for
    # downstream phases (e.g. report generation).  Excluded from
    # serialisation because it's redundant with ``investigation``.
    investigation_report_obj: Optional[Any] = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("investigation_report_obj", None)
        return d


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class AuditPipeline:
    """
    Four-phase baseline-driven audit pipeline.

    The *reference* is the clean REDCap archive (ZIP or extracted folder).
    The *target* is the installation under scrutiny.
    """

    def __init__(
        self,
        config: Optional[REDACTSConfig] = None,
        *,
        validator: Optional[BaselineValidator] = None,
    ) -> None:
        self.config = config or REDACTSConfig()
        self.validator = validator or BaselineValidator()

    def run(
        self,
        reference: str,
        target: str,
        output_dir: str,
        version: str = "",
        run_external_tools: bool = True,
        formats: Optional[list[str]] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> AuditResult:
        """
        Execute the full audit.

        Args:
            reference: Path to clean REDCap archive (ZIP or folder).
            target: Path to target REDCap installation (folder, ZIP, URL).
            output_dir: Where to write all output.
            version: REDCap version label (e.g. "15.7.4").
            run_external_tools: Whether to run lizard/radon/etc on delta.
            formats: Report formats (html, json, markdown).
            progress_callback: ``callback(stage, pct)`` for UI.

        Returns:
            A fully populated :class:`AuditResult`.
        """
        t0 = time.monotonic()
        out = Path(output_dir).resolve()
        out.mkdir(parents=True, exist_ok=True)
        formats = formats or ["html", "json", "markdown"]

        result = AuditResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            output_dir=str(out),
            version=version,
        )

        def _progress(stage: str, pct: float) -> None:
            logger.info("[audit] %s (%.0f%%)", stage, pct * 100)
            if progress_callback:
                progress_callback(stage, pct)

        try:
            # ── Step 0: Resolve reference and target  [MANDATORY] ────
            _progress("loading_reference", 0.0)
            ref_path = self._resolve_source(reference, out / "_ref_extract")
            result.reference_path = str(ref_path)

            _progress("loading_target", 0.05)
            tgt_path = self._resolve_source(target, out / "_tgt_extract")
            result.target_path = str(tgt_path)

            # ── Phase 1-3: Baseline diff  [MANDATORY] ────────────────
            _progress("baseline_diff", 0.10)
            diff = self.validator.diff(ref_path, tgt_path, version=version)
            result.baseline_diff = diff.to_dict()

            result.reference_file_count = diff.reference_file_count
            result.target_file_count = diff.target_file_count
            result.files_identical = len(diff.files_identical)
            result.files_modified = len(diff.files_modified)
            result.files_added = len(diff.files_added)
            result.files_removed = len(diff.files_removed)
            result.delta_count = len(diff.delta_files)

            logger.info(
                "Baseline diff: %d identical, %d modified, %d added, %d removed → %d delta files",
                result.files_identical,
                result.files_modified,
                result.files_added,
                result.files_removed,
                result.delta_count,
            )
        except Exception as exc:
            result.errors.append(f"Mandatory step failed: {exc}")
            result.success = False
            result.duration_seconds = time.monotonic() - t0
            logger.error(
                "Audit pipeline failed at mandatory step: %s", exc, exc_info=True
            )
            return result

        try:
            # ── Short-circuit if clean ───────────────────────────────
            if diff.is_clean:
                result.success = True
                result.overall_risk_level = "CLEAN"
                result.risk_summary = (
                    "Target installation is byte-for-byte identical to "
                    f"the reference archive ({result.files_identical:,} files verified). "
                    "No deviations detected."
                )
                result.duration_seconds = time.monotonic() - t0
                self._write_results(result, out, formats)
                _progress("complete", 1.0)
                return result

            # ── Phase 4: Deep forensic analysis (delta only) ─────────
            _progress("deep_analysis", 0.30)
            delta_set = diff.delta_files

            investigator = Investigator(self.config)

            # Thread progress from investigator to our callback
            def inv_progress(stage: str, pct: float) -> None:
                # Map investigator 0-100% into our 30-90% range
                overall = 0.30 + pct * 0.60
                _progress(f"deep_analysis/{stage}", overall)

            inv_report = investigator.investigate(
                target_path=str(tgt_path),
                output_dir=str(out),
                evidence_id=f"AUDIT-{version}",
                evidence_label=f"Audit of REDCap {version}" if version else "Audit",
                run_external_tools=run_external_tools,
                progress_callback=inv_progress,
                only_files=delta_set,
            )

            result.investigation = inv_report.to_dict()
            result.investigation_report_obj = inv_report
            result.deep_scan_findings = inv_report.total_findings
            result.overall_risk_level = inv_report.overall_risk_level
            result.risk_summary = self._build_risk_summary(diff, inv_report)

            # ── Reports ──────────────────────────────────────────────
            _progress("generating_reports", 0.92)
            result.success = True
            result.duration_seconds = time.monotonic() - t0
            self._write_results(result, out, formats)
            _progress("complete", 1.0)

        except Exception as exc:
            result.errors.append(str(exc))
            result.success = False
            result.duration_seconds = time.monotonic() - t0
            logger.error("Audit pipeline failed: %s", exc, exc_info=True)

        return result

    # ==================================================================
    # Helpers
    # ==================================================================

    def _resolve_source(self, source: str, extract_to: Path) -> Path:
        """Resolve a source (path/ZIP/URL) to a local directory.

        Raises ValueError if the source cannot be resolved or no REDCap root is detected.
        """
        source_path = Path(source).resolve()

        # If it's a ZIP, extract it
        if source_path.is_file() and source_path.suffix.lower() == ".zip":
            loader = detect_loader(source)
            loaded = loader.load(source, extract_to)
            root = detect_redcap_root(Path(loaded))
            if root is None:
                raise ValueError(
                    f"No REDCap installation found in archive: {source}. "
                    f"Extracted to {loaded} but no REDCap root detected."
                )
            return root

        # If it's a directory, auto-detect REDCap root
        if source_path.is_dir():
            root = detect_redcap_root(source_path)
            if root is None:
                raise ValueError(
                    f"No REDCap installation found in directory: {source_path}. "
                    f"Expected to find REDCap markers (redcap_connect.php, "
                    f"Classes/, etc.)."
                )
            return root

        # Try generic loader (URL, FTP, etc.)
        loader = detect_loader(source)
        loaded = loader.load(source, str(extract_to))
        root = detect_redcap_root(Path(loaded))
        if root is None:
            raise ValueError(
                f"No REDCap installation found after loading: {source}. "
                f"Loaded to {loaded} but no REDCap root detected."
            )
        return root

    @staticmethod
    def _build_risk_summary(
        diff: StructuralDiffResult, inv: InvestigationReport
    ) -> str:
        """Build a human-readable risk summary."""
        parts: list[str] = []

        if diff.files_modified:
            parts.append(
                f"{len(diff.files_modified)} file(s) modified vs. reference archive."
            )
        if diff.files_added:
            parts.append(f"{len(diff.files_added)} file(s) added (not in reference).")
        if diff.files_removed:
            parts.append(f"{len(diff.files_removed)} file(s) removed from reference.")

        if inv.total_findings:
            parts.append(
                f"Deep analysis of {len(diff.delta_files)} delta file(s) "
                f"produced {inv.total_findings} finding(s) — "
                f"{inv.findings_by_severity.get('CRITICAL', 0)} CRITICAL, "
                f"{inv.findings_by_severity.get('HIGH', 0)} HIGH."
            )
        else:
            parts.append(
                f"Deep analysis of {len(diff.delta_files)} delta file(s) "
                f"produced zero findings — differences may be benign "
                f"(config, line endings, patches)."
            )

        parts.append(
            f"{len(diff.files_identical):,} files verified identical to reference."
        )
        return " ".join(parts)

    def _write_results(
        self, result: AuditResult, out: Path, formats: list[str]
    ) -> None:
        """Persist audit results as JSON, Markdown, and/or HTML."""
        reports_dir = out / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        if "json" in formats:
            path = reports_dir / f"redacts_audit_{ts}.json"
            path.write_text(
                json.dumps(
                    {"audit": result.to_dict()},
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
            result.report_files.append(str(path))

        if "markdown" in formats:
            path = reports_dir / f"redacts_audit_{ts}.md"
            path.write_text(self._render_markdown(result), encoding="utf-8")
            result.report_files.append(str(path))

        if "html" in formats:
            path = reports_dir / f"redacts_audit_{ts}.html"
            path.write_text(self._render_html(result), encoding="utf-8")
            result.report_files.append(str(path))

        logger.info(
            "Wrote %d audit report(s) to %s", len(result.report_files), reports_dir
        )

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _render_markdown(self, result: AuditResult) -> str:
        lines: list[str] = []
        a = lines.append

        a(f"# REDACTS Audit Report — REDCap {result.version or '(unknown)'}")
        a("")
        a(f"**Generated**: {result.timestamp}")
        a(f"**Duration**: {result.duration_seconds:.1f}s")
        a(f"**Risk Level**: **{result.overall_risk_level}**")
        a("")
        a("## Executive Summary")
        a("")
        a(result.risk_summary or "No summary available.")
        a("")

        # Phase 1-3 summary
        a("## Baseline Comparison")
        a("")
        a(f"| Metric | Count |")
        a(f"|--------|------:|")
        a(f"| Reference files | {result.reference_file_count:,} |")
        a(f"| Target files | {result.target_file_count:,} |")
        a(f"| Identical (SHA-256 match) | {result.files_identical:,} |")
        a(f"| Modified (hash mismatch) | {result.files_modified:,} |")
        a(f"| Added (not in reference) | {result.files_added:,} |")
        a(f"| Removed (missing from target) | {result.files_removed:,} |")
        a(f"| **Delta files (deep scanned)** | **{result.delta_count}** |")
        a("")

        # Baseline findings detail
        bd = result.baseline_diff or {}
        if bd.get("findings"):
            a("### Baseline Findings")
            a("")
            a("| Severity | Type | Path | Message |")
            a("|----------|------|------|---------|")
            for f in bd["findings"]:
                a(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` | {f['message'][:80]} |"
                )
            a("")

        # Phase 4 deep scan
        inv = result.investigation or {}
        if inv.get("findings"):
            a("## Deep Analysis Findings (delta files only)")
            a("")
            a(
                f"Total: {inv.get('total_findings', 0)} findings on {result.delta_count} delta files."
            )
            a("")
            by_sev = inv.get("findings_by_severity", {})
            if by_sev:
                a("| Severity | Count |")
                a("|----------|------:|")
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    if ct := by_sev.get(sev, 0):
                        a(f"| {sev} | {ct} |")
                a("")

            a("### Findings Detail")
            a("")
            for f in inv["findings"]:
                sev = f.get("severity", "")
                a(f"- **[{sev}]** {f.get('title', '')}  ")
                a(f"  File: `{f.get('file_path', '')}:{f.get('line', 0)}`  ")
                a(f"  {f.get('description', '')[:200]}")
                a("")
        elif result.delta_count == 0 and result.overall_risk_level == "CLEAN":
            a("## Deep Analysis")
            a("")
            a(
                "No delta files — target is byte-for-byte identical to reference. No deep analysis required."
            )
            a("")
        else:
            a("## Deep Analysis")
            a("")
            a(
                f"Deep analysis of {result.delta_count} delta files produced zero findings."
            )
            a("")

        a("---")
        a(f"*REDACTS v1.0.0 — Audit Mode — {result.timestamp}*")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def _render_html(self, result: AuditResult) -> str:
        import html as html_mod

        md = self._render_markdown(result)

        # Quick-and-dirty HTML wrapper around the markdown content
        escaped = html_mod.escape(md)
        # Convert markdown tables to simple pre-formatted text
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>REDACTS Audit — REDCap {html_mod.escape(result.version or "unknown")}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 960px; margin: 2em auto; padding: 0 1em; color: #222; }}
  h1 {{ border-bottom: 3px solid #0057b7; padding-bottom: .3em; }}
  h2 {{ border-bottom: 1px solid #ddd; padding-bottom: .2em; margin-top: 1.5em; }}
  pre {{ background: #f6f8fa; padding: 1em; border-radius: 6px; overflow-x: auto; }}
  .risk-clean {{ color: #28a745; }} .risk-critical {{ color: #d73a49; }}
  .risk-high {{ color: #e36209; }} .risk-medium {{ color: #dbab09; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #ddd; padding: 6px 12px; text-align: left; }}
  th {{ background: #f6f8fa; }}
</style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>"""
