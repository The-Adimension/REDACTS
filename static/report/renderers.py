"""Report renderers - HTML, JSON, Markdown.

Three formats, three audiences:

* HTML for the REDCap Cybersecurity Committee and other non-technical
  reviewers - needs to be self-contained (no external CSS/JS) so it
  opens correctly on an air-gapped review workstation.
* Markdown for the analyst writing the case file - diff-friendly, pastes
  into Jira/ServiceNow without losing structure.
* JSON for downstream tooling (SIEM ingest, ticket generators).

The SARIF exporter lives separately in :mod:`static.scanners.sarif`
because it targets static-analyzer integrations rather than human
readers.

Copyright 2024-2026 The Adimension / Shehab Anwer
Apache-2.0.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Callable

from ..core.constants import VERSION
from .renderer_protocol import ReportContext

__all__ = [
    "HtmlReportRenderer",
    "JsonReportRenderer",
    "MarkdownReportRenderer",
]


_VERSION = VERSION

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_RISK_LEVEL_COLORS: dict[str, str] = {
    "CRITICAL": "#f85149",
    "HIGH": "#f0883e",
    "MEDIUM": "#d29922",
    "LOW": "#3fb950",
    "INFO": "#8b949e",
    "NONE": "#8b949e",
}

_SENSITIVE_CATEGORIES = [
    "email",
    "ip_address",
    "phone_number",
    "ssn",
    "credit_card",
    "api_key",
    "password",
    "medical_record_number",
    "date_of_birth",
]

_DISCLAIMER_TEXT = (
    "REDACTS is a forensic analysis AID. It does not replace thorough "
    "manual review by qualified security professionals. Results are not "
    "guaranteed to be complete or definitive. Use as an auxiliary tool "
    "within your incident response workflow, not as a sole determination."
)

_OUT_OF_SCOPE_TEXT = (
    "The following areas are outside the scope of REDACTS automated "
    "analysis and require separate manual assessment: network traffic "
    "analysis, memory forensics, database content review beyond schema "
    "comparison, and server-level configuration (OS, web server, PHP-FPM)."
)

_ATTACK_COVERAGE_DISCLAIMER = (
    "ATT&CK COVERAGE: REDACTS maps findings to a targeted subset of "
    "MITRE ATT&CK Enterprise techniques focused on web application "
    "compromise. Full matrix coverage is not claimed."
)




def _esc(value: Any) -> str:
    """HTML-escape a value, converting non-strings to str first."""
    return html.escape(str(value)) if value else ""


def _severity_badge_html(severity: str) -> str:
    """Return a styled severity badge for HTML reports."""
    s = str(severity).upper()
    color = _RISK_LEVEL_COLORS.get(s, "#8b949e")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:0.85em;font-weight:700;">{_esc(s)}</span>'
    )


def _timestamp_now() -> str:
    """Return current UTC timestamp in ISO 8601."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sorted_findings(findings: list[Any]) -> list[Any]:
    """Sort findings by severity (critical first), then by file path."""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(getattr(f, "severity", "INFO")).upper(), 99),
            getattr(f, "file_path", "") or "",
        ),
    )




class HtmlReportRenderer:
    """Render an investigation report as an interactive HTML document."""

    @property
    def format_name(self) -> str:
        return "html"

    @property
    def file_extension(self) -> str:
        return ".html"

    def render(self, context: ReportContext) -> str:
        rpt = context.investigation
        meta = context.meta
        title = context.title
        sorted_findings = context.sorted_findings

        parts: list[str] = []
        p = parts.append

        self._executive_summary(rpt, meta, p)
        self._chain_of_custody(meta, p)
        self._provenance(context.provenance, p)
        self._findings(sorted_findings, p)
        self._config_integrity(rpt.config_integrity, p)
        self._sensitive_data(rpt.sensitive_data_summary, p)
        self._external_tools(rpt.external_tools_summary, p)
        self._attack_vectors(rpt, p)
        self._out_of_scope(p)
        self._recommendations(sorted_findings, p)
        self._disclaimer(p)
        self._footer(rpt, p)

        body = "\n".join(parts)
        return self._html_document(title, rpt.overall_risk_level, body)

    # -- Section helpers ---------------

    @staticmethod
    def _executive_summary(rpt, meta, p: Callable) -> None:
        risk_color = _RISK_LEVEL_COLORS.get(rpt.overall_risk_level, "#8b949e")
        p("<h2>1. Executive Summary</h2>")
        p(
            f'<p><strong>Overall Risk Level:</strong> <span style="color:'
            f'{risk_color};font-size:1.3em;font-weight:700;">'
            f"{_esc(rpt.overall_risk_level)}</span></p>"
        )

        p(
            f"<p><strong>Conclusive Compromise Indicators:</strong> "
            f"{rpt.conclusive_indicators}</p>"
        )

        p("<table><tr><th>Severity</th><th>Count</th></tr>")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = rpt.findings_by_severity.get(sev, 0)
            if not count:
                continue
            p(f"<tr><td>{_severity_badge_html(sev)}</td><td>{count}</td></tr>")
        p("</table>")

        if rpt.risk_summary:
            p(f"<p>{_esc(rpt.risk_summary)}</p>")

        if meta:
            p(
                f"<p><strong>Evidence ID:</strong> <code>"
                f"{_esc(meta.evidence_id)}</code> &nbsp; <strong>Label:</strong> "
                f"{_esc(meta.label)}"
                f" &nbsp; <strong>Collected:</strong> "
                f"{_esc(meta.collection_timestamp)}</p>"
            )

    @staticmethod
    def _chain_of_custody(meta, p: Callable) -> None:
        p("<h2>2. Chain of Custody</h2>")
        if not meta:
            p("<p><em>No evidence package metadata available.</em></p>")
            return
        p("<table>")
        p(f"<tr><th>Source URI</th><td><code>{_esc(meta.source_uri)}</code></td></tr>")
        p(
            f"<tr><th>Collection Timestamp</th><td>"
            f"{_esc(meta.collection_timestamp)}</td></tr>"
        )
        p(
            f"<tr><th>Tool</th><td>{_esc(meta.tool_name)}"
            f" v{_esc(meta.tool_version)}</td></tr>"
        )
        p(
            f"<tr><th>Manifest SHA-256</th><td><code>"
            f"{_esc(meta.manifest_sha256)}</code></td></tr>"
        )
        if meta.notes:
            p(f"<tr><th>Analyst Notes</th><td>{_esc(meta.notes)}</td></tr>")
        p("</table>")

    @staticmethod
    def _provenance(provenance, p: Callable) -> None:
        p("<h2>Provenance</h2>")
        if not provenance:
            p("<p><em>Provenance data not available.</em></p>")
            return
        p("<table>")
        if provenance.scan_started:
            p(f"<tr><th>Scan Started</th><td>{_esc(provenance.scan_started)}</td></tr>")
        if provenance.scan_completed:
            p(
                f"<tr><th>Scan Completed</th><td>"
                f"{_esc(provenance.scan_completed)}</td></tr>"
            )
        p("</table>")
        if provenance.input_hashes:
            p("<h3>Input Artifact Hashes (SHA-256)</h3><table>")
            p("<tr><th>Artifact</th><th>SHA-256</th></tr>")
            for name, digest in sorted(provenance.input_hashes.items()):
                p(f"<tr><td>{_esc(name)}</td><td><code>{_esc(digest)}</code></td></tr>")
            p("</table>")
        if provenance.tool_versions:
            p("<h3>Tool Versions</h3><table>")
            p("<tr><th>Tool</th><th>Version</th></tr>")
            for tool, ver in sorted(provenance.tool_versions.items()):
                p(f"<tr><td>{_esc(tool)}</td><td>{_esc(ver)}</td></tr>")
            p("</table>")
        if provenance.knowledge_data_hashes:
            p("<h3>Knowledge Data Hashes (SHA-256)</h3><table>")
            p("<tr><th>File</th><th>SHA-256</th></tr>")
            for fname, digest in sorted(provenance.knowledge_data_hashes.items()):
                p(f"<tr><td>{_esc(fname)}</td><td><code>{_esc(digest)}</code></td></tr>")
            p("</table>")
        if getattr(provenance, 'coverage_gaps', None):
            p("<h3>Coverage Gaps (REDUCED COVERAGE)</h3>")
            p("<ul>")
            for gap in provenance.coverage_gaps:
                p(f"<li>{_esc(gap)}</li>")
            p("</ul>")
        if provenance.attack_coverage_disclaimer:
            p(
                f"<p class='disclaimer'><em>"
                f"{_esc(provenance.attack_coverage_disclaimer)}</em></p>"
            )

    @staticmethod
    def _findings(findings, p: Callable) -> None:
        p("<h2>3. Findings</h2>")
        if not findings:
            p("<p><em>No findings recorded.</em></p>")
            return
        p("<table>")
        p(
            "<tr><th>ID</th><th>Severity</th><th>Title</th><th>File</th>"
            "<th>Line</th><th>CWE</th><th>Conclusiveness</th><th>Category</th><th>Source</th></tr>"
        )

        for i, f in enumerate(findings):
            line_str = str(f.line) if f.line else "-"
            cwe_display = ""
            if getattr(f, "cwe_id", ""):
                cwe_name = getattr(f, "cwe_name", "")
                cwe_display = f"{_esc(f.cwe_id)}: {_esc(cwe_name)}" if cwe_name else _esc(f.cwe_id)
            p(
                f"<tr><td>{_esc(f.id)}</td><td>"
                f"{_severity_badge_html(f.severity)}"
                f"</td><td class='finding-title' onclick=\"toggleDetail('fd-"
                f"{i}')\" style='cursor:pointer;text-decoration:underline dotted;'>"
                f"{_esc(f.title)}</td><td><code>"
                f"{_esc(f.file_path)}</code></td><td>"
                f"{line_str}</td><td>"
                f"{cwe_display}</td><td>"
                f"{_esc(f.conclusiveness)}</td><td>"
                f"{_esc(f.category)}</td><td>"
                f"{_esc(f.source)}</td></tr>"
            )

            desc = _esc(f.description) if f.description else ""
            rec = _esc(f.recommendation) if f.recommendation else ""

            ev = _esc(json.dumps(f.evidence, default=str)) if f.evidence else ""

            p(
                f"<tr id='fd-{i}' class='detail-row' style='display:none;'>"
                f"<td colspan='9'><strong>Description:</strong> "
                f"{desc}"
                f"<br><strong>Recommendation:</strong> "
                f"{rec}<br>"
                + (f"<strong>Evidence:</strong> <code>{ev}</code>" if ev else "")
                + "</td></tr>"
            )

        p("</table>")

    @staticmethod
    def _config_integrity(cfg, p: Callable) -> None:
        p("<h2>4. Configuration Integrity</h2>")
        if not cfg:
            p("<p><em>Configuration integrity check was not performed.</em></p>")
            return

        db = cfg.database_php
        if db:
            valid = db.get("valid", True)
            status_label = "PASS" if valid else "FAIL"
            status_color = "#3fb950" if valid else "#f85149"
            p(
                f"<h3>database.php - <span style='color:"
                f"{status_color};'>{status_label}</span></h3>"
            )
            violations = db.get("violations", [])
            if violations:
                p("<ul>")
                for v in violations:
                    p(f"<li>{_esc(v)}</li>")
                p("</ul>")
            else:
                p("<p>No violations detected.</p>")

        if cfg.htaccess_files:
            p("<h3>.htaccess Files</h3><ul>")
            for ht in cfg.htaccess_files:
                p(
                    f"<li><code>{_esc(ht.get('path', 'unknown'))}"
                    f"</code> - Dangerous directives: "
                    f"{ht.get('dangerous_directives', 0)}</li>"
                )
            p("</ul>")

        if cfg.user_ini_files:
            p("<h3>.user.ini Files (Anomalous)</h3><ul>")
            for ui in cfg.user_ini_files:
                p(f"<li><code>{_esc(ui.get('path', 'unknown'))}</code></li>")
            p("</ul>")

        hf = cfg.hook_functions
        if hf:
            known = hf.get("known_functions", [])
            unknown = hf.get("unknown_functions", [])
            p("<h3>hook_functions.php</h3>")
            p(f"<p>Known: {len(known)} | Unknown: {len(unknown)}</p>")
            if unknown:
                p("<ul>")
                for fn in unknown:
                    p(f"<li><code>{_esc(fn)}</code></li>")
                p("</ul>")

        cr = cfg.cron_php
        if cr:
            match = cr.get("hash_match", False)
            color = "#3fb950" if match else "#f85149"
            p("<h3>cron.php</h3>")
            p(
                f'<p>Hash verified: <span style="color:'
                f'{color};">{"Yes" if match else "No"}</span></p>'
            )

    @staticmethod
    def _sensitive_data(summary, p: Callable) -> None:
        p("<h2>5. Sensitive Data Exposure</h2>")
        if not summary:
            p("<p><em>Sensitive data scan was not performed.</em></p>")
            return
        p("<p><em>All sensitive values are REDACTED in this report.</em></p>")
        by_cat = summary.get("by_category", {})
        if by_cat:
            p("<table><tr><th>Category</th><th>Occurrences</th></tr>")
            for cat in _SENSITIVE_CATEGORIES:
                count = by_cat.get(cat, 0)
                if not count:
                    continue
                p(f"<tr><td>{_esc(cat)}</td><td>{count}</td></tr>")
            p("</table>")
        hipaa = summary.get("hipaa_identifiers", {})
        if hipaa:
            p("<h3>HIPAA Identifier Exposure</h3>")
            p("<table><tr><th>Identifier Type</th><th>Found</th></tr>")
            for ident, found in hipaa.items():
                color = "#f85149" if found else "#3fb950"
                label = "Yes" if found else "No"
                p(
                    f"<tr><td>{_esc(ident)}"
                    f'</td><td style="color:{color};">'
                    f"{label}</td></tr>"
                )
            p("</table>")

    @staticmethod
    def _external_tools(summary, p: Callable) -> None:
        p("<h2>6. External Tools Results</h2>")
        if not summary:
            p("<p><em>External tools were not executed.</em></p>")
            return
        discovered = summary.get("tools_discovered", [])
        missing = summary.get("tools_missing", [])
        p("<table><tr><th>Tool</th><th>Status</th></tr>")
        for t in discovered:
            p(f'<tr><td>{_esc(t)}</td><td style="color:#3fb950;">Discovered</td></tr>')
        for t in missing:
            p(f'<tr><td>{_esc(t)}</td><td style="color:#8b949e;">Missing</td></tr>')
        p("</table>")
        results = summary.get("results", {})
        for tool_name, result in results.items():
            if not isinstance(result, dict):
                continue
            if not result.get("success"):
                continue
            parsed = result.get("parsed_data", {})
            p(f"<h3>{_esc(tool_name)}</h3>")
            p(f"<p>Files analyzed: {result.get('files_analyzed', 0)}</p>")
            grade = parsed.get("grade")
            if not grade:
                continue
            p(f"<p>Complexity grade: <strong>{_esc(grade)}</strong></p>")

    @staticmethod
    def _attack_vectors(rpt, p: Callable) -> None:
        p("<h2>7. Attack Vector Coverage</h2>")
        p("<table>")
        p(f"<tr><th>Vectors Assessed</th><td>{rpt.vectors_assessed}</td></tr>")
        p(
            f"<tr><th>Vectors With Findings</th><td>"
            f"{rpt.vectors_with_findings}</td></tr>"
        )
        p("</table>")
        vector_ids = set()
        for f in rpt.findings:
            vector_ids.update(f.related_attack_vector_ids)
        if vector_ids:
            p("<h3>Vectors With Findings</h3><ul>")
            for vid in sorted(vector_ids):
                p(f"<li><code>{_esc(vid)}</code></li>")
            p("</ul>")

    @staticmethod
    def _out_of_scope(p: Callable) -> None:
        p("<h2>8. Out of Scope Declaration</h2>")
        p(f"<pre class='code-block'>{_esc(_OUT_OF_SCOPE_TEXT)}</pre>")

    @staticmethod
    def _recommendations(findings, p: Callable) -> None:
        p("<h2>9. Recommendations</h2>")
        if not findings:
            p("<p><em>No findings - no recommendations required.</em></p>")
            return
        by_cat: dict = {}
        for f in findings:
            by_cat.setdefault(f.category, []).append(f)
        for cat, cat_findings in sorted(by_cat.items()):
            p(f"<h3>{_esc(cat)}</h3><ul>")
            for f in cat_findings:
                if not f.recommendation:
                    continue
                p(
                    f"<li>{_severity_badge_html(f.severity)}"
                    f" <strong>{_esc(f.title)}:</strong> "
                    f"{_esc(f.recommendation)}</li>"
                )
            p("</ul>")

    @staticmethod
    def _footer(rpt, p: Callable) -> None:
        p("<hr>")
        p(
            f"<p><strong>Generated:</strong> {_timestamp_now()}"
            f" &nbsp; <strong>REDACTS version:</strong> {_VERSION}"
            f" &nbsp; <strong>Investigation duration:</strong> "
            f"{rpt.investigation_duration_seconds:.1f}s</p>"
        )
        p(
            "<p><em>This report reflects filesystem-based static analysis only. "
            "It does not cover database-resident, network, memory, or "
            "infrastructure-level threats. See section 8 for full scope "
            "limitations.</em></p>"
        )
        p(
            "<p><em>\u00a9 2024\u20132026 The Adimension / Shehab Anwer "
            "\u2014 atrium@theadimension.com</em></p>"
        )
        p(
            "<p><em>CWE\u2122 content \u00a9 2006\u20132026 The MITRE Corporation. "
            "Used under the CWE Terms of Use "
            "(https://cwe.mitre.org/about/termsofuse.html).</em></p>"
        )

    @staticmethod
    def _disclaimer(p: Callable) -> None:
        p("<h2>10. Disclaimer</h2>")
        p(
            "<div style='background:#1c1c00;border:2px solid var(--yellow);"
            "border-radius:6px;padding:1rem;margin:1rem 0;'>"
        )
        p(
            f"<pre style='white-space:pre-wrap;color:var(--yellow);'>{_esc(_DISCLAIMER_TEXT)}</pre>"
        )
        p("</div>")

    # -- HTML wrapper -

    @staticmethod
    def _html_document(title: str, risk_level: str, body: str) -> str:
        risk_color = _RISK_LEVEL_COLORS.get(risk_level, "#8b949e")
        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            f"<title>{_esc(title)}</title>\n"
            "<style>\n"
            ":root {\n"
            "    --bg: #0d1117;\n"
            "    --surface: #161b22;\n"
            "    --border: #30363d;\n"
            "    --text: #c9d1d9;\n"
            "    --text-muted: #8b949e;\n"
            "    --accent: #58a6ff;\n"
            "    --green: #3fb950;\n"
            "    --red: #f85149;\n"
            "    --yellow: #d29922;\n"
            "    --orange: #db6d28;\n"
            "}\n"
            "* { margin: 0; padding: 0; box-sizing: border-box; }\n"
            "body {\n"
            "    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;\n"
            "    background: var(--bg);\n"
            "    color: var(--text);\n"
            "    line-height: 1.6;\n"
            "    padding: 2rem;\n"
            "    max-width: 1200px;\n"
            "    margin: 0 auto;\n"
            "}\n"
            "h1 {\n"
            "    color: var(--accent);\n"
            "    border-bottom: 2px solid var(--border);\n"
            "    padding-bottom: 0.5rem;\n"
            "    margin: 1.5rem 0 1rem;\n"
            "}\n"
            "h1 .risk-indicator {\n"
            "    font-size: 0.6em;\n"
            "    padding: 4px 12px;\n"
            "    border-radius: 6px;\n"
            "    color: #fff;\n"
            f"    background: {risk_color};\n"
            "    vertical-align: middle;\n"
            "    margin-left: 1rem;\n"
            "}\n"
            "h2 {\n"
            "    color: var(--green);\n"
            "    border-bottom: 1px solid var(--border);\n"
            "    padding-bottom: 0.3rem;\n"
            "    margin: 1.5rem 0 0.8rem;\n"
            "}\n"
            "h3 { color: var(--yellow); margin: 1rem 0 0.5rem; }\n"
            "p { margin: 0.3rem 0; }\n"
            "ul { margin: 0.5rem 0 0.5rem 1.5rem; }\n"
            "li { margin: 0.2rem 0; }\n"
            "code {\n"
            "    background: var(--surface);\n"
            "    padding: 0.15rem 0.4rem;\n"
            "    border-radius: 3px;\n"
            "    font-size: 0.9em;\n"
            "}\n"
            "strong { color: #e6edf3; }\n"
            "em { color: var(--text-muted); font-style: italic; }\n"
            "hr { border: none; border-top: 1px solid var(--border); margin: 2rem 0; }\n"
            "table {\n"
            "    width: 100%;\n"
            "    border-collapse: collapse;\n"
            "    margin: 0.8rem 0;\n"
            "    background: var(--surface);\n"
            "    border-radius: 6px;\n"
            "    overflow: hidden;\n"
            "}\n"
            "th, td {\n"
            "    padding: 0.5rem 0.8rem;\n"
            "    text-align: left;\n"
            "    border-bottom: 1px solid var(--border);\n"
            "    font-size: 0.9em;\n"
            "}\n"
            "th { background: #21262d; color: var(--accent); font-weight: 600; }\n"
            "tr:hover td { background: #1c2128; }\n"
            ".code-block {\n"
            "    background: #0d1117;\n"
            "    border: 1px solid var(--border);\n"
            "    border-radius: 6px;\n"
            "    padding: 1rem;\n"
            "    overflow-x: auto;\n"
            "    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;\n"
            "    font-size: 0.85em;\n"
            "    line-height: 1.4;\n"
            "    margin: 0.8rem 0;\n"
            "    white-space: pre;\n"
            "}\n"
            ".detail-row td {\n"
            "    background: #1c2128;\n"
            "    border-left: 3px solid var(--accent);\n"
            "    font-size: 0.88em;\n"
            "    padding: 0.8rem 1.2rem;\n"
            "}\n"
            "@media print {\n"
            "    body { background: #fff; color: #000; }\n"
            "    table { background: #f8f8f8; }\n"
            "    th { background: #e0e0e0; color: #000; }\n"
            "    .detail-row td { background: #f0f0f5; border-left-color: #0366d6; }\n"
            "    code { background: #f0f0f0; }\n"
            "    .code-block { background: #f8f8f8; border-color: #ccc; }\n"
            "    h1 { color: #0366d6; }\n"
            "    h2 { color: #22863a; }\n"
            "    h3 { color: #b08800; }\n"
            "}\n"
            "</style>\n"
            "</head>\n"
            "<body>\n"
            f'<h1>{_esc(title)} <span class="risk-indicator">'
            f"{_esc(risk_level)}</span></h1>\n"
            f"{body}"
            "\n<script>\n"
            "function toggleDetail(id) {\n"
            "    var el = document.getElementById(id);\n"
            "    if (el) {\n"
            "        el.style.display = el.style.display === 'none' ? 'table-row' : 'none';\n"
            "    }\n"
            "}\n"
            "</script>\n"
            "</body>\n"
            "</html>"
        )




class JsonReportRenderer:
    """Render an investigation report as a JSON document."""

    @property
    def format_name(self) -> str:
        return "json"

    @property
    def file_extension(self) -> str:
        return ".json"

    def render(self, context: ReportContext) -> str:
        rpt = context.investigation
        meta = context.meta

        data: dict[str, Any] = {
            "report_title": context.title,
            "generated_at": _timestamp_now(),
            "overall_risk_level": rpt.overall_risk_level,
            "conclusive_indicators": rpt.conclusive_indicators,
            "risk_summary": rpt.risk_summary,
            "findings_by_severity": rpt.findings_by_severity,
            "findings": [
                self._serialize_finding(f) for f in context.sorted_findings
            ],
        }

        if meta:
            data["evidence"] = {
                "evidence_id": getattr(meta, "evidence_id", ""),
                "label": getattr(meta, "label", ""),
                "source_uri": getattr(meta, "source_uri", ""),
                "collection_timestamp": getattr(meta, "collection_timestamp", ""),
                "manifest_sha256": getattr(meta, "manifest_sha256", ""),
            }

        if context.provenance:
            data["provenance"] = context.provenance.to_dict()

        return json.dumps(data, indent=2, default=str, ensure_ascii=False)

    @staticmethod
    def _serialize_finding(f: Any) -> dict[str, Any]:
        """Convert a finding to a JSON-safe dict."""
        return {
            "id": getattr(f, "id", ""),
            "severity": str(getattr(f, "severity", "")),
            "title": getattr(f, "title", ""),
            "description": getattr(f, "description", ""),
            "file_path": getattr(f, "file_path", ""),
            "line": getattr(f, "line", 0),
            "category": getattr(f, "category", ""),
            "source": getattr(f, "source", ""),
            "cwe_id": getattr(f, "cwe_id", ""),
            "cwe_name": getattr(f, "cwe_name", ""),
            "conclusiveness": getattr(f, "conclusiveness", ""),
            "recommendation": getattr(f, "recommendation", ""),
            "evidence": getattr(f, "evidence", {}),
        }




class MarkdownReportRenderer:
    """Render an investigation report as a Markdown document."""

    @property
    def format_name(self) -> str:
        return "markdown"

    @property
    def file_extension(self) -> str:
        return ".md"

    def render(self, context: ReportContext) -> str:
        rpt = context.investigation
        meta = context.meta
        lines: list[str] = []
        a = lines.append

        a(f"# {context.title}")
        a(f"*Generated: {_timestamp_now()} | REDACTS v{_VERSION}*\n")

        # Executive summary
        a("## 1. Executive Summary\n")
        a(f"**Overall Risk Level:** {rpt.overall_risk_level}\n")
        a(f"**Conclusive Compromise Indicators:** {rpt.conclusive_indicators}\n")
        if rpt.risk_summary:
            a(f"{rpt.risk_summary}\n")

        a("| Severity | Count |")
        a("|----------|-------|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = rpt.findings_by_severity.get(sev, 0)
            if count:
                a(f"| {sev} | {count} |")
        a("")

        # Chain of custody
        a("## 2. Chain of Custody\n")
        if meta:
            a(f"- **Evidence ID:** `{getattr(meta, 'evidence_id', 'N/A')}`")
            a(f"- **Source:** `{getattr(meta, 'source_uri', 'N/A')}`")
            a(f"- **Collected:** {getattr(meta, 'collection_timestamp', 'N/A')}")
            a(f"- **Manifest SHA-256:** `{getattr(meta, 'manifest_sha256', 'N/A')}`")
        else:
            a("*No evidence package metadata available.*")
        a("")

        # Findings
        a("## 3. Findings\n")
        if not context.sorted_findings:
            a("*No findings recorded.*\n")
        else:
            a("| ID | Severity | Title | File | Line | CWE |")
            a("|----|----------|-------|------|------|-----|")
            for f in context.sorted_findings:
                line = getattr(f, "line", 0) or "-"
                cwe = getattr(f, "cwe_id", "") or "-"
                a(
                    f"| {getattr(f, 'id', '')} "
                    f"| {getattr(f, 'severity', '')} "
                    f"| {getattr(f, 'title', '')} "
                    f"| `{getattr(f, 'file_path', '')}` "
                    f"| {line} "
                    f"| {cwe} |"
                )
            a("")

        # Disclaimer
        a("## Disclaimer\n")
        a(f"> {_DISCLAIMER_TEXT}\n")
        a("## Out of Scope\n")
        a(f"> {_OUT_OF_SCOPE_TEXT}\n")

        # Provenance
        if context.provenance:
            prov = context.provenance
            a("## Provenance\n")
            if prov.scan_started:
                a(f"- **Scan Started:** {prov.scan_started}")
            if prov.scan_completed:
                a(f"- **Scan Completed:** {prov.scan_completed}")
            a("")
            if prov.input_hashes:
                a("### Input Artifact Hashes (SHA-256)\n")
                a("| Artifact | SHA-256 |")
                a("|----------|---------|")
                for name, digest in sorted(prov.input_hashes.items()):
                    a(f"| {name} | `{digest}` |")
                a("")
            if prov.tool_versions:
                a("### Tool Versions\n")
                a("| Tool | Version |")
                a("|------|---------|")
                for tool, ver in sorted(prov.tool_versions.items()):
                    a(f"| {tool} | {ver} |")
                a("")
            if prov.knowledge_data_hashes:
                a("### Knowledge Data Hashes (SHA-256)\n")
                a("| File | SHA-256 |")
                a("|------|---------|")
                for fname, digest in sorted(prov.knowledge_data_hashes.items()):
                    a(f"| {fname} | `{digest}` |")
                a("")
            if getattr(prov, 'coverage_gaps', None):
                a("### Coverage Gaps (REDUCED COVERAGE)\n")
                for gap in prov.coverage_gaps:
                    a(f"- {gap}")
                a("")
            if prov.attack_coverage_disclaimer:
                a(f"> {prov.attack_coverage_disclaimer}\n")

        return "\n".join(lines)
