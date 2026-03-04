"""
REDACTS HTML Report Renderer.

Produces a dark-themed, interactive HTML forensic report with expandable
finding details, severity badges, and print-friendly CSS.
"""

from __future__ import annotations

import json
from typing import Callable

from ..renderer_protocol import ReportContext
from ._shared import (
    _DISCLAIMER_TEXT,
    _OUT_OF_SCOPE_TEXT,
    _RISK_LEVEL_COLORS,
    _SENSITIVE_CATEGORIES,
    _VERSION,
    _esc,
    _severity_badge_html,
    _timestamp_now,
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

    # -- Section helpers --------------------------------------------------

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
    def _findings(findings, p: Callable) -> None:
        p("<h2>3. Findings</h2>")
        if not findings:
            p("<p><em>No findings recorded.</em></p>")
            return
        p("<table>")
        p(
            "<tr><th>ID</th><th>Severity</th><th>Title</th><th>File</th>"
            "<th>Line</th><th>Conclusiveness</th><th>Category</th><th>Source</th></tr>"
        )

        for i, f in enumerate(findings):
            line_str = str(f.line) if f.line else "-"
            p(
                f"<tr><td>{_esc(f.id)}</td><td>"
                f"{_severity_badge_html(f.severity)}"
                f"</td><td class='finding-title' onclick=\"toggleDetail('fd-"
                f"{i}')\" style='cursor:pointer;text-decoration:underline dotted;'>"
                f"{_esc(f.title)}</td><td><code>"
                f"{_esc(f.file_path)}</code></td><td>"
                f"{line_str}</td><td>"
                f"{_esc(f.conclusiveness)}</td><td>"
                f"{_esc(f.category)}</td><td>"
                f"{_esc(f.source)}</td></tr>"
            )

            desc = _esc(f.description) if f.description else ""
            rec = _esc(f.recommendation) if f.recommendation else ""

            ev = _esc(json.dumps(f.evidence, default=str)) if f.evidence else ""

            p(
                f"<tr id='fd-{i}' class='detail-row' style='display:none;'>"
                f"<td colspan='8'><strong>Description:</strong> "
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
                f"<h3>database.php — <span style='color:"
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
                    f"</code> — Dangerous directives: "
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
            p("<p><em>No findings — no recommendations required.</em></p>")
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

    # -- HTML wrapper ------------------------------------------------------

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
