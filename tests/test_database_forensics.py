"""Tests for forensics/database_forensics.py — verify import-blocker fix and regex fix."""

from __future__ import annotations

import textwrap
from pathlib import Path

from REDACTS.forensics.database_forensics import (
    DatabaseAnomaly,
    DatabaseForensics,
    DatabaseForensicsReport,
)


# ---------- Dataclass instantiation (was crashing before fix) ----------


class TestDatabaseForensicsReport:
    """Verify the mutable-default (field) fix works at all."""

    def test_instantiate_no_args(self):
        """Was BLOCKED before fix — crashed with
        `ValueError: mutable default <class 'list'> is not allowed`."""
        report = DatabaseForensicsReport()
        assert isinstance(report.anomalies, list)
        assert report.anomalies == []

    def test_two_instances_independent(self):
        """Shared mutable default would cause cross-contamination."""
        r1 = DatabaseForensicsReport()
        r2 = DatabaseForensicsReport()
        r1.anomalies.append(
            DatabaseAnomaly(severity="HIGH", type="test", message="x")
        )
        assert len(r2.anomalies) == 0

    def test_to_dict(self):
        r = DatabaseForensicsReport(total_anomalies=1, critical=1)
        d = r.to_dict()
        assert d["total_anomalies"] == 1
        assert d["critical"] == 1
        assert isinstance(d["anomalies"], list)


# ---------- Regex fixes (database.php analysis) ----------


class TestDatabasePhpRegex:
    """The regex in _analyze_database_php should match real PHP code."""

    def _write_php(self, tmp_path: Path, content: str) -> Path:
        db_php = tmp_path / "database.php"
        db_php.write_text(content, encoding="utf-8")
        return tmp_path

    def test_catches_dynamic_sql(self, tmp_path):
        """$mysqli->query($variable) should fire the arbitrary_sql rule."""
        root = self._write_php(tmp_path, textwrap.dedent("""\
            <?php
            $result = $mysqli->query($sql_string);
            ?>
        """))
        report = DatabaseForensics().analyze_directory(root)
        types = [a.type for a in report.anomalies]
        assert "arbitrary_sql" in types

    def test_ignores_safe_query(self, tmp_path):
        """A hard-coded query literal should NOT fire the arbitrary_sql rule."""
        root = self._write_php(tmp_path, textwrap.dedent("""\
            <?php
            $result = $mysqli->query("SELECT 1");
            ?>
        """))
        report = DatabaseForensics().analyze_directory(root)
        types = [a.type for a in report.anomalies]
        assert "arbitrary_sql" not in types

    def test_catches_obfuscated_creds(self, tmp_path):
        root = self._write_php(tmp_path, textwrap.dedent("""\
            <?php
            $db_user = base64_decode('cm9vdA==');
            ?>
        """))
        report = DatabaseForensics().analyze_directory(root)
        types = [a.type for a in report.anomalies]
        assert "obfuscated_creds" in types

    def test_catches_multiple_connections(self, tmp_path):
        root = self._write_php(tmp_path, textwrap.dedent("""\
            <?php
            $mysqli = mysqli_connect('host','user','pass','db');
            $mysqli2 = mysqli_connect('host2','user','pass','db');
            ?>
        """))
        report = DatabaseForensics().analyze_directory(root)
        types = [a.type for a in report.anomalies]
        assert "suspicious_connection" in types


# ---------- Redcap.db detection ----------


class TestRedcapDbDetection:
    def test_finds_redcap_db(self, tmp_path):
        (tmp_path / "redcap.db").write_bytes(b"\x00" * 100)
        report = DatabaseForensics().analyze_directory(tmp_path)
        assert report.has_redcap_db is True
        assert report.critical >= 1

    def test_no_redcap_db(self, tmp_path):
        report = DatabaseForensics().analyze_directory(tmp_path)
        assert report.has_redcap_db is False

    def test_unexpected_sqlite(self, tmp_path):
        (tmp_path / "mystery.db").write_bytes(b"\x00" * 50)
        report = DatabaseForensics().analyze_directory(tmp_path)
        types = [a.type for a in report.anomalies]
        assert "unexpected_sqlite" in types
