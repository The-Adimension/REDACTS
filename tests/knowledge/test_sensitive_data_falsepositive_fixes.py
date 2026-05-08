"""Regression tests for the 7 false-positive guards added to
``threat_base.sensitive_data`` and friends.

Cross-validation of forensic scan output against upstream REDCap 16.1.1
proved 0/11 sampled CRITICAL findings were real. These tests pin the
guards so that the false positives stay suppressed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_base.ioc_database import IoCDatabase
from threat_base.sensitive_data import (
    SensitiveDataScanner,
    _is_in_base64_blob,
    _is_known_nonsecret,
    _is_password_column_context,
    _line_match_in_comment,
    _path_should_downgrade,
)


# Path allow-list / downgrade


@pytest.mark.parametrize(
    "rel_path",
    [
        "vendor/autoload.php",
        "redcap/vendor/composer/installed.php",
        "node_modules/foo/index.js",
        "install_files/setup.sh",
        "redcap/examples/ldap.example.php",
        "redcap/Resources/PDFJS/pdf.min.js",
        "redcap/Resources/build/redcap.bundle.js",
        "redcap/Resources/PDFJS/openjpeg_nowasm_fallback.js",
        "redcap/Resources/StatsAndCharts.js",
        "redcap/Resources/PDFJS/pdf.worker.min.mjs",
        "redcap/some.umd.min.js",
        "redcap/Resources/source.map",
    ],
)
def test_downgrade_paths_match(rel_path: str) -> None:
    assert _path_should_downgrade(rel_path) is True


@pytest.mark.parametrize(
    "rel_path",
    [
        "redcap/Classes/User.php",
        "redcap/index.php",
        "src/app.js",
        "main.py",
    ],
)
def test_downgrade_paths_no_match(rel_path: str) -> None:
    assert _path_should_downgrade(rel_path) is False


def test_downgrade_path_emits_info_severity(tmp_path: Path) -> None:
    """A vendored file with a CRITICAL pattern is downgraded to INFO."""
    vendor = tmp_path / "vendor" / "leak.php"
    vendor.parent.mkdir()
    vendor.write_text(
        '<?php $password = "Secret123Very!Strong";\n',
        encoding="utf-8",
    )
    report = SensitiveDataScanner().scan_directory(tmp_path)
    # Whatever fired, no CRITICAL/HIGH/MEDIUM should remain.
    for f in report.findings:
        if f.file_path.replace("\\", "/").startswith("vendor/"):
            assert f.severity not in {"CRITICAL", "HIGH", "MEDIUM"}


# Comment-aware scanning


@pytest.mark.parametrize(
    "line, span_start, expected",
    [
        ("// include 'path_to_db_conn_file.php';", 3, True),
        ("# password = 'foo'", 2, True),
        ("-- UPDATE redcap SET password = ?", 3, True),
        ("$password = 'live';", 0, False),
    ],
)
def test_line_match_in_comment(line: str, span_start: int, expected: bool) -> None:
    assert _line_match_in_comment(line, span_start) is expected


def test_commented_password_is_not_flagged(tmp_path: Path) -> None:
    f = tmp_path / "x.php"
    f.write_text(
        '<?php\n// $password = "BogusExample!2024"\n$x = 1;\n',
        encoding="utf-8",
    )
    report = SensitiveDataScanner().scan_directory(tmp_path)
    assert report.total_findings == 0


def test_validate_database_php_strips_comments() -> None:
    db = IoCDatabase()
    content = (
        "<?php\n"
        "// include 'path_to_db_conn_file.php';\n"
        "/* require_once('compat.php'); */\n"
        "$hostname = 'localhost';\n"
        "$db = 'redcap';\n"
        "$username = 'redcap';\n"
        "$password = 'x';\n"
        "$salt = 'y';\n"
    )
    violations = db.validate_database_php(content)
    forbidden = [v for v in violations if v["type"] == "forbidden_pattern"]
    assert forbidden == [], (
        "Commented-out include/require must not trigger forbidden_pattern"
    )


def test_validate_database_php_still_catches_real_include() -> None:
    db = IoCDatabase()
    content = (
        "<?php\n"
        "include 'malicious.php';\n"
        "$hostname='h';$db='d';$username='u';$password='p';$salt='s';\n"
    )
    violations = db.validate_database_php(content)
    assert any(v["type"] == "forbidden_pattern" for v in violations)


# SQL column-name gate


@pytest.mark.parametrize(
    "line",
    [
        "UPDATE redcap_auth SET password = ? WHERE id = ?",
        "UPDATE redcap_auth SET password = $newpw WHERE id = ?",
        "UPDATE redcap_auth SET password = :pw WHERE id = :id",
        "$sql = \"UPDATE auth SET password = '\" . db_escape($p) . \"'\";",
        "INSERT INTO redcap_users (username, password) VALUES (?, ?)",
    ],
)
def test_password_column_context_suppressed(line: str) -> None:
    span_start = line.lower().index("password")
    assert _is_password_column_context(line, span_start) is True


def test_password_literal_still_flagged() -> None:
    line = "$password = 'Hunter2!RealLeak';"
    span_start = line.index("password")
    assert _is_password_column_context(line, span_start) is False


# Base64 / minified gate


def test_minified_line_skipped() -> None:
    long_line = "var _0xabc=" + ("a" * 6000) + "1234567890123456;"
    span = (len(long_line) - 17, len(long_line) - 1)
    assert _is_in_base64_blob(long_line, span) is True


def test_base64_blob_context_skipped() -> None:
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 4
    cc = "4111111111111111"
    line = blob + cc + blob
    start = line.index(cc)
    assert _is_in_base64_blob(line, (start, start + len(cc))) is True


def test_normal_line_not_treated_as_base64() -> None:
    line = "$cc = '4111-1111-1111-1111';"
    span = (line.index("4111"), line.index("4111") + 19)
    assert _is_in_base64_blob(line, span) is False


# Known constant hashes


@pytest.mark.parametrize(
    "value",
    [
        "d41d8cd98f00b204e9800998ecf8427e",  # MD5("")
        "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",  # SHA-1("")
        (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),  # SHA-256("")
    ],
)
def test_known_nonsecret_hashes(value: str) -> None:
    assert _is_known_nonsecret(value) is True


def test_random_hash_not_treated_as_known() -> None:
    assert _is_known_nonsecret("a" * 32) is False


# REDCap hook whitelist contains canonical entries


def test_canonical_redcap_hooks_in_whitelist() -> None:
    from threat_base import HOOK_FUNCTION_NAMES

    must_contain = {
        "redcap_control_center",
        "redcap_custom_verify_username",
        "redcap_project_home_page",
        "redcap_survey_acknowledgement_page",
    }
    missing = must_contain - set(HOOK_FUNCTION_NAMES)
    assert not missing, f"Missing canonical REDCap hooks: {missing}"
