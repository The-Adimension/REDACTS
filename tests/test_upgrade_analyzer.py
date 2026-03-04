"""Tests for forensics/upgrade_analyzer.py — verify all 11 regex rules compile and match."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from REDACTS.forensics.upgrade_analyzer import (
    UpgradeAnalyzer,
    UpgradeAnalysisReport,
)


# ---------- Import / instantiation ----------


class TestUpgradeAnalyzerInstantiation:
    def test_import_ok(self):
        """All 11 compiled regexes should survive import."""
        ua = UpgradeAnalyzer()
        assert len(ua.RULES) == 11, f"Expected 11 rules, got {len(ua.RULES)}"

    def test_every_rule_has_compiled_pattern(self):
        for rule in UpgradeAnalyzer.RULES:
            assert isinstance(rule["pattern"], re.Pattern), (
                f"Rule {rule['id']} pattern is not compiled"
            )

    def test_report_dataclass(self):
        r = UpgradeAnalysisReport()
        assert r.anomalies == []
        assert r.total_anomalies == 0


# ---------- Individual rule matching ----------

# Sample PHP snippets a compromised Upgrade.php would contain.
_SAMPLES = {
    "UPG001": 'eval($upgrade_code);',
    "UPG002": "preg_replace('/pattern/e', $replacement, $subject);",
    "UPG003": '${$callback}("malicious_arg");',
    "UPG010": 'if ($file !== "safe.php")',
    "UPG011": '@unlink($path);',
    "UPG020": 'auto_prepend_file = /tmp/evil.php',
    "UPG021": 'fopen(".htaccess","w");',
    "UPG030": 'return; // bail early',
    "UPG031": 'if (!$patch_applied) return',
    "UPG040": 'base64_decode($encoded);',
    "UPG050": '$db_password = "hunter2";',
}


class TestUpgradeRuleMatching:
    """Each compiled regex should match its expected PHP snippet."""

    @pytest.mark.parametrize("rule_id,snippet", list(_SAMPLES.items()))
    def test_rule_matches_sample(self, rule_id, snippet):
        rule = next(r for r in UpgradeAnalyzer.RULES if r["id"] == rule_id)
        assert rule["pattern"].search(snippet), (
            f"Rule {rule_id} did NOT match sample: {snippet!r}"
        )


# ---------- Integration: analyze_directory ----------


class TestAnalyzeDirectory:
    def _create_upgrade_file(self, tmp_path: Path, content: str) -> Path:
        upgrade = tmp_path / "Upgrade.php"
        upgrade.write_text(content, encoding="utf-8")
        return tmp_path

    def test_clean_upgrade(self, tmp_path):
        root = self._create_upgrade_file(tmp_path, textwrap.dedent("""\
            <?php
            // Normal upgrade logic
            $db->query("ALTER TABLE redcap_config ...");
            ?>
        """))
        report = UpgradeAnalyzer().analyze_directory(root)
        assert report.total_anomalies == 0

    def test_detects_eval_hijack(self, tmp_path):
        root = self._create_upgrade_file(tmp_path, textwrap.dedent("""\
            <?php
            eval($upgrade_code);
            ?>
        """))
        report = UpgradeAnalyzer().analyze_directory(root)
        assert report.has_upgrade_hijack is True
        ids = [a.category for a in report.anomalies]
        assert "upgrade_hijack" in ids

    def test_detects_obfuscation(self, tmp_path):
        root = self._create_upgrade_file(tmp_path, textwrap.dedent("""\
            <?php
            $code = base64_decode($encoded);
            ?>
        """))
        report = UpgradeAnalyzer().analyze_directory(root)
        cats = [a.category for a in report.anomalies]
        assert "obfuscation" in cats

    def test_detects_persistence_injection(self, tmp_path):
        root = self._create_upgrade_file(tmp_path, textwrap.dedent("""\
            <?php
            fopen(".htaccess","w");
            ?>
        """))
        report = UpgradeAnalyzer().analyze_directory(root)
        assert report.has_persistence_injection is True

    def test_skips_comments(self, tmp_path):
        """Matching code inside a block comment should be ignored."""
        root = self._create_upgrade_file(tmp_path, textwrap.dedent("""\
            <?php
            /* eval($upgrade_code); */
            ?>
        """))
        report = UpgradeAnalyzer().analyze_directory(root)
        assert report.total_anomalies == 0

    def test_to_dict(self, tmp_path):
        report = UpgradeAnalysisReport(total_anomalies=0)
        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["total_anomalies"] == 0
