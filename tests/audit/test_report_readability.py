"""Unit tests for R6 Report Readability & Pagination (Milestone 4).

Tests baseline findings table capping, deep analysis findings grouping by severity
in Markdown, and structured HTML document rendering.
"""

from __future__ import annotations

import pytest
from static.audit.pipeline import AuditPipeline, AuditResult


def _create_sample_audit_result(
    baseline_findings_count: int = 0,
    deep_findings: list[dict] | None = None,
    risk_level: str = "HIGH",
) -> AuditResult:
    """Helper to construct an AuditResult for testing report rendering."""
    b_findings = []
    for i in range(baseline_findings_count):
        b_findings.append({
            "severity": "MEDIUM",
            "type": "modified_file",
            "path": f"classes/REDCap/TestFile_{i}.php",
            "message": f"Hash mismatch in baseline file #{i}",
        })

    baseline_diff = {
        "is_clean": False,
        "reference_file_count": 5000,
        "target_file_count": 5010,
        "files_identical": 4990,
        "files_modified": baseline_findings_count,
        "files_added": 10,
        "files_removed": 0,
        "findings": b_findings,
    }

    inv_findings = deep_findings or []
    by_sev = {}
    for f in inv_findings:
        sev = str(f.get("severity", "INFO")).upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1

    investigation = {
        "total_findings": len(inv_findings),
        "overall_risk_level": risk_level,
        "findings_by_severity": by_sev,
        "findings": inv_findings,
    }

    return AuditResult(
        success=True,
        timestamp="2026-07-21T12:00:00Z",
        duration_seconds=3.5,
        version="15.7.4",
        reference_path="/tmp/ref",
        target_path="/tmp/tgt",
        output_dir="/tmp/out",
        baseline_diff=baseline_diff,
        investigation=investigation,
        reference_file_count=5000,
        target_file_count=5010,
        files_identical=4990,
        files_modified=baseline_findings_count,
        files_added=10,
        files_removed=0,
        delta_count=10 + baseline_findings_count,
        deep_scan_findings=len(inv_findings),
        overall_risk_level=risk_level,
        risk_summary=f"Audit completed with {len(inv_findings)} deep analysis findings.",
    )


class TestBaselineFindingsCapping:
    """Tests capping of baseline findings table to 50 rows in Markdown and HTML."""

    def test_baseline_findings_under_cap_markdown(self):
        pipeline = AuditPipeline()
        result = _create_sample_audit_result(baseline_findings_count=10)
        md = pipeline._render_markdown(result)

        assert "### Baseline Findings" in md
        assert "| MEDIUM | modified_file | `classes/REDCap/TestFile_0.php` |" in md
        assert "| MEDIUM | modified_file | `classes/REDCap/TestFile_9.php` |" in md
        assert "Baseline table capped at 50 rows" not in md

    def test_baseline_findings_over_cap_markdown(self):
        pipeline = AuditPipeline()
        total_findings = 65
        result = _create_sample_audit_result(baseline_findings_count=total_findings)
        md = pipeline._render_markdown(result)

        assert "### Baseline Findings" in md

        # Row 0 to 49 should be rendered
        assert "| MEDIUM | modified_file | `classes/REDCap/TestFile_0.php` |" in md
        assert "| MEDIUM | modified_file | `classes/REDCap/TestFile_49.php` |" in md

        # Row 50 and beyond should NOT be in the table
        assert "| MEDIUM | modified_file | `classes/REDCap/TestFile_50.php` |" not in md
        assert "| MEDIUM | modified_file | `classes/REDCap/TestFile_64.php` |" not in md

        # Capping note must be present with total interpolated
        expected_note = f"*Baseline table capped at 50 rows (out of {total_findings} total findings). Refer to the full JSON report for complete baseline findings.*"
        assert expected_note in md

    def test_baseline_findings_over_cap_html(self):
        pipeline = AuditPipeline()
        total_findings = 60
        result = _create_sample_audit_result(baseline_findings_count=total_findings)
        html = pipeline._render_html(result)

        assert "Baseline Findings</h3>" in html
        assert "<code>classes/REDCap/TestFile_0.php</code>" in html
        assert "<code>classes/REDCap/TestFile_49.php</code>" in html
        assert "<code>classes/REDCap/TestFile_50.php</code>" not in html

        expected_note = f"Baseline table capped at 50 rows (out of {total_findings} total findings). Refer to the full JSON report for complete baseline findings."
        assert expected_note in html


class TestDeepAnalysisSeverityGrouping:
    """Tests grouping deep analysis findings by severity in collapsible details blocks."""

    def test_markdown_severity_grouping(self):
        pipeline = AuditPipeline()
        deep_findings = [
            {
                "severity": "CRITICAL",
                "title": "SQL Injection in auth.php",
                "file_path": "auth.php",
                "line": 42,
                "description": "User input concatenated directly into query.",
            },
            {
                "severity": "CRITICAL",
                "title": "Remote Code Execution via upload",
                "file_path": "upload.php",
                "line": 105,
                "description": "Unchecked file upload leads to PHP execution.",
            },
            {
                "severity": "HIGH",
                "title": "XSS in survey_header.php",
                "file_path": "survey_header.php",
                "line": 88,
                "description": "Reflected XSS in query parameter.",
            },
            {
                "severity": "LOW",
                "title": "Information Disclosure in debug.php",
                "file_path": "debug.php",
                "line": 12,
                "description": "PHP Info exposed to unauthenticated user.",
            },
        ]

        result = _create_sample_audit_result(
            baseline_findings_count=5, deep_findings=deep_findings, risk_level="CRITICAL"
        )
        md = pipeline._render_markdown(result)

        # Check section header
        assert "## Deep Analysis Findings (delta files only)" in md
        assert "### Findings Detail" in md

        # Check CRITICAL details block
        assert "<details>" in md
        assert "<summary><strong>CRITICAL</strong> (2 findings)</summary>" in md
        assert "- **[CRITICAL]** SQL Injection in auth.php" in md
        assert "- **[CRITICAL]** Remote Code Execution via upload" in md

        # Check HIGH details block
        assert "<summary><strong>HIGH</strong> (1 findings)</summary>" in md
        assert "- **[HIGH]** XSS in survey_header.php" in md

        # Check LOW details block
        assert "<summary><strong>LOW</strong> (1 findings)</summary>" in md
        assert "- **[LOW]** Information Disclosure in debug.php" in md

        # Unused severities (MEDIUM, INFO) should NOT have summary tags
        assert "<summary><strong>MEDIUM</strong>" not in md
        assert "<summary><strong>INFO</strong>" not in md
        assert "</details>" in md

    def test_markdown_severity_case_insensitivity(self):
        pipeline = AuditPipeline()
        deep_findings = [
            {
                "severity": "critical",
                "title": "Lowercase critical severity test",
                "file_path": "test.php",
                "line": 1,
                "description": "Severity in lowercase",
            }
        ]
        result = _create_sample_audit_result(deep_findings=deep_findings)
        md = pipeline._render_markdown(result)

        assert "<summary><strong>CRITICAL</strong> (1 findings)</summary>" in md
        assert "- **[critical]** Lowercase critical severity test" in md


class TestStructuredHtmlRendering:
    """Tests HTML report generation for proper structure and styling."""

    def test_html_structure_elements(self):
        pipeline = AuditPipeline()
        deep_findings = [
            {
                "severity": "HIGH",
                "title": "Hardcoded Credentials",
                "file_path": "db_config.php",
                "line": 15,
                "description": "Database password hardcoded in file.",
            }
        ]
        result = _create_sample_audit_result(
            baseline_findings_count=10, deep_findings=deep_findings, risk_level="HIGH"
        )
        html = pipeline._render_html(result)

        # Must be valid HTML document structure (not raw markdown in <pre>)
        assert "<!DOCTYPE html>" in html
        assert "<html lang=\"en\">" in html
        assert "<head>" in html
        assert "<body>" in html
        assert "<pre>" not in html  # no longer a raw pre dump

        # Executive summary
        assert "<h2>Executive Summary</h2>" in html
        assert "Overall Risk Level:" in html
        assert "HIGH</span>" in html  # styled badge

        # Baseline comparison section
        assert "<h2>Baseline Comparison</h2>" in html
        assert "Reference files" in html
        assert "5,000" in html
        assert "Baseline Findings</h3>" in html

        # Deep Analysis section with details / summary
        assert "<h2>Deep Analysis Findings (delta files only)</h2>" in html
        assert "<details>" in html
        assert "<summary>" in html
        assert "<strong>HIGH</strong> (1 findings)</summary>" in html
        assert "Hardcoded Credentials" in html
        assert "<code>db_config.php</code>" in html

    def test_clean_html_rendering(self):
        pipeline = AuditPipeline()
        result = AuditResult(
            success=True,
            timestamp="2026-07-21T12:00:00Z",
            duration_seconds=0.5,
            version="15.7.4",
            overall_risk_level="CLEAN",
            risk_summary="Target installation is byte-for-byte identical to the reference archive.",
            delta_count=0,
        )
        html = pipeline._render_html(result)

        assert "<!DOCTYPE html>" in html
        assert "CLEAN</span>" in html
        assert "No delta files - target is byte-for-byte identical to reference." in html


class TestSeverityGroupingHelper:
    """Direct tests for the shared ``_group_findings_by_severity`` helper.

    Both renderers delegate to it, so the grouping contract - display order,
    empty-group omission, and the trailing OTHER bucket - is pinned here once
    rather than re-asserted through each renderer's markup.
    """

    @staticmethod
    def _find(sev: str) -> dict:
        return {"severity": sev, "title": "t", "file_path": "f.php", "line": 1, "description": "d"}

    def test_orders_groups_most_severe_first(self):
        findings = [self._find(s) for s in ("LOW", "CRITICAL", "INFO", "HIGH", "MEDIUM")]
        labels = [label for label, _ in AuditPipeline._group_findings_by_severity(findings)]
        assert labels == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def test_omits_empty_groups(self):
        findings = [self._find("CRITICAL"), self._find("INFO")]
        labels = [label for label, _ in AuditPipeline._group_findings_by_severity(findings)]
        assert labels == ["CRITICAL", "INFO"]

    def test_unknown_severities_collapse_into_trailing_other_bucket(self):
        findings = [self._find("HIGH"), self._find("weird"), self._find("bogus")]
        groups = AuditPipeline._group_findings_by_severity(findings)
        assert groups[-1][0] == "OTHER"
        assert len(groups[-1][1]) == 2

    def test_is_case_insensitive_on_severity(self):
        findings = [self._find("critical"), self._find("High")]
        labels = [label for label, _ in AuditPipeline._group_findings_by_severity(findings)]
        assert labels == ["CRITICAL", "HIGH"]

    def test_no_other_bucket_when_all_known(self):
        findings = [self._find("HIGH"), self._find("LOW")]
        labels = [label for label, _ in AuditPipeline._group_findings_by_severity(findings)]
        assert "OTHER" not in labels

    def test_empty_input_yields_no_groups(self):
        assert AuditPipeline._group_findings_by_severity([]) == []

    def test_every_finding_is_preserved(self):
        findings = [self._find(s) for s in ("HIGH", "HIGH", "weird", "LOW")]
        groups = AuditPipeline._group_findings_by_severity(findings)
        assert sum(len(g) for _, g in groups) == len(findings)
