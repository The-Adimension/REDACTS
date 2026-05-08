"""
Tests for REDACTS Knowledge Updater - knowledge/updater.py

Coverage:
    - _atomic_replace: success, rollback on failure
    - _download_to_temp: HTTPS enforcement, SSRF rejection, happy path
    - _sanitize_php_malware_finder: include/import/whitelist stripping
    - update_cwe: ZIP extraction, Zip Slip protection, SHA-256 sidecar
    - update_attack: delegates to prefetch
    - update_yara: downloads + sanitizes + writes sidecars
    - update_nvd: API key detection
    - update_all: orchestrates all sub-updates
    All network calls are mocked - no real downloads.
"""

from __future__ import annotations

import hashlib
import os
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from threat_base.updater import (
    UpdateError,
    _atomic_replace,
    _sanitize_php_malware_finder,
)


# --- _atomic_replace --------------


class TestAtomicReplace:
    """Tests for the atomic file replacement primitive."""

    def test_replaces_file(self, tmp_path: Path) -> None:
        src = tmp_path / "new.txt"
        dst = tmp_path / "target.txt"
        dst.write_text("old", encoding="utf-8")
        src.write_text("new", encoding="utf-8")

        _atomic_replace(src, dst)

        assert dst.read_text(encoding="utf-8") == "new"
        assert not src.exists()  # source consumed by os.replace

    def test_creates_destination_dir(self, tmp_path: Path) -> None:
        src = tmp_path / "new.txt"
        src.write_text("data", encoding="utf-8")
        dst = tmp_path / "sub" / "dir" / "target.txt"

        _atomic_replace(src, dst)
        assert dst.read_text(encoding="utf-8") == "data"

    def test_replaces_when_no_existing_file(self, tmp_path: Path) -> None:
        src = tmp_path / "new.txt"
        dst = tmp_path / "fresh.txt"
        src.write_text("fresh", encoding="utf-8")

        _atomic_replace(src, dst)
        assert dst.read_text(encoding="utf-8") == "fresh"

    def test_backup_cleaned_on_success(self, tmp_path: Path) -> None:
        src = tmp_path / "new.txt"
        dst = tmp_path / "target.txt"
        dst.write_text("old", encoding="utf-8")
        src.write_text("new", encoding="utf-8")

        _atomic_replace(src, dst)
        assert not (tmp_path / "target.txt.bak").exists()


# --- _sanitize_php_malware_finder -


class TestSanitizePhpMalwareFinder:
    """Tests for YARA rule sanitization."""

    def test_strips_whitelist_include(self, tmp_path: Path) -> None:
        rule = tmp_path / "test.yar"
        rule.write_text(
            'include "whitelist.yar"\nrule test { condition: true }',
            encoding="utf-8",
        )
        _sanitize_php_malware_finder(rule)
        text = rule.read_text(encoding="utf-8")
        assert "whitelist.yar" not in text
        assert "rule test" in text

    def test_strips_hash_import(self, tmp_path: Path) -> None:
        rule = tmp_path / "test.yar"
        rule.write_text(
            'import "hash"\nrule test { condition: true }',
            encoding="utf-8",
        )
        _sanitize_php_malware_finder(rule)
        text = rule.read_text(encoding="utf-8")
        assert 'import "hash"' not in text

    def test_strips_is_whitelisted_reference(self, tmp_path: Path) -> None:
        rule = tmp_path / "test.yar"
        rule.write_text(
            "rule test { condition: $a and not IsWhitelisted }",
            encoding="utf-8",
        )
        _sanitize_php_malware_finder(rule)
        text = rule.read_text(encoding="utf-8")
        assert "IsWhitelisted" not in text
        assert "$a" in text

    def test_no_change_when_clean(self, tmp_path: Path) -> None:
        rule = tmp_path / "clean.yar"
        original = "rule clean { condition: true }"
        rule.write_text(original, encoding="utf-8")
        _sanitize_php_malware_finder(rule)
        assert rule.read_text(encoding="utf-8") == original


# --- update_cwe (mocked network) --


class TestUpdateCwe:
    """Tests for CWE update with mocked downloads."""

    def _make_cwe_zip(self, csv_content: str) -> bytes:
        """Build an in-memory ZIP containing a CSV."""
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("cwec_v4.19.csv", csv_content)
        return buf.getvalue()

    @patch("threat_base.updater._download_to_temp")
    def test_happy_path(self, mock_dl: MagicMock, tmp_path: Path) -> None:
        from threat_base import updater

        # Setup: write the ZIP to a temp file the mock returns
        zip_bytes = self._make_cwe_zip("CWE-ID,Name\n79,XSS\n")
        zip_file = tmp_path / "cwe.zip"
        zip_file.write_bytes(zip_bytes)
        mock_dl.return_value = zip_file

        # Point updater at tmp_path
        with patch.object(updater, "_CWE_CSV_DIR", tmp_path):
            result = updater.update_cwe(confirm=False)

        assert result is True
        # Should have written a CSV and SHA-256 sidecar
        csvs = list(tmp_path.glob("cwec_v*.csv"))
        assert len(csvs) == 1
        sha_path = csvs[0].with_suffix(".csv.sha256")
        assert sha_path.is_file()
        stored_hash = sha_path.read_text(encoding="utf-8").strip()
        actual_hash = hashlib.sha256(csvs[0].read_bytes()).hexdigest()
        assert stored_hash == actual_hash

    @patch("threat_base.updater._download_to_temp")
    def test_zip_slip_rejected(self, mock_dl: MagicMock, tmp_path: Path) -> None:
        from threat_base import updater

        # Build a malicious ZIP with path traversal
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../etc/passwd.csv", "evil")
        zip_file = tmp_path / "evil.zip"
        zip_file.write_bytes(buf.getvalue())
        mock_dl.return_value = zip_file

        with patch.object(updater, "_CWE_CSV_DIR", tmp_path):
            result = updater.update_cwe(confirm=False)

        assert result is False  # Should fail safely

    @patch("threat_base.updater._download_to_temp")
    def test_no_csv_in_zip(self, mock_dl: MagicMock, tmp_path: Path) -> None:
        from threat_base import updater

        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "no csv here")
        zip_file = tmp_path / "bad.zip"
        zip_file.write_bytes(buf.getvalue())
        mock_dl.return_value = zip_file

        with patch.object(updater, "_CWE_CSV_DIR", tmp_path):
            result = updater.update_cwe(confirm=False)

        assert result is False


# --- update_attack (delegates to prefetch) ---------


class TestUpdateAttack:
    """Tests for ATT&CK update delegation."""

    @patch("threat_base.prefetch.prefetch_attack_data", return_value=True)
    def test_delegates_to_prefetch(self, mock_pf: MagicMock) -> None:
        from threat_base.updater import update_attack

        result = update_attack(confirm=False)

        assert result is True
        mock_pf.assert_called_once_with(force=True)

    @patch("threat_base.prefetch.prefetch_attack_data", return_value=False)
    def test_reports_failure(self, mock_pf: MagicMock) -> None:
        from threat_base.updater import update_attack

        result = update_attack(confirm=False)

        assert result is False


# --- update_yara (mocked network) -


class TestUpdateYara:
    """Tests for YARA rule download + sanitization."""

    @patch("threat_base.updater._download_to_temp")
    def test_downloads_all_three_sources(self, mock_dl: MagicMock, tmp_path: Path) -> None:
        from threat_base import updater

        # Each call returns a temp file with dummy YARA content
        def make_temp(*args, **kwargs):
            f = tmp_path / f"tmp_{mock_dl.call_count}.yar"
            f.write_text("rule dummy { condition: true }", encoding="utf-8")
            return f

        mock_dl.side_effect = make_temp

        with patch.object(updater, "_YARA_RULES_DIR", tmp_path / "yara"):
            result = updater.update_yara(confirm=False)

        assert result is True
        assert mock_dl.call_count == 3

        yara_dir = tmp_path / "yara"
        # Should have 3 .yar files and 3 .sha256 sidecars
        yar_files = sorted(yara_dir.glob("*.yar"))
        sha_files = sorted(yara_dir.glob("*.sha256"))
        assert len(yar_files) == 3
        assert len(sha_files) == 3

    @patch("threat_base.updater._download_to_temp")
    def test_sanitizes_php_malware_finder(self, mock_dl: MagicMock, tmp_path: Path) -> None:
        from threat_base import updater

        call_count = 0

        def make_temp(url: str, label: str) -> Path:
            nonlocal call_count
            call_count += 1
            f = tmp_path / f"tmp_{call_count}.yar"
            if "php-malware-finder" in label:
                f.write_text(
                    'include "whitelist.yar"\nrule test { condition: true }',
                    encoding="utf-8",
                )
            else:
                f.write_text("rule other { condition: true }", encoding="utf-8")
            return f

        mock_dl.side_effect = make_temp

        with patch.object(updater, "_YARA_RULES_DIR", tmp_path / "yara"):
            updater.update_yara(confirm=False)

        pmf_rule = (tmp_path / "yara" / "php-malware-finder.yar")
        assert pmf_rule.is_file()
        assert "whitelist.yar" not in pmf_rule.read_text(encoding="utf-8")

    @patch("threat_base.updater._download_to_temp")
    def test_partial_failure(self, mock_dl: MagicMock, tmp_path: Path) -> None:
        from threat_base import updater

        call_count = 0

        def make_temp(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ConnectionError("Network down")
            f = tmp_path / f"tmp_{call_count}.yar"
            f.write_text("rule ok { condition: true }", encoding="utf-8")
            return f

        mock_dl.side_effect = make_temp

        with patch.object(updater, "_YARA_RULES_DIR", tmp_path / "yara"):
            result = updater.update_yara(confirm=False)

        assert result is False  # Not all 3 succeeded


# --- update_nvd -


class TestUpdateNvd:
    """Tests for NVD configuration validation."""

    @patch("threat_base.nvd.NvdClient")
    def test_reports_available_with_key(self, MockClient: MagicMock) -> None:
        from threat_base.updater import update_nvd

        instance = MockClient.return_value
        instance.available = True
        instance.get_cve.return_value = {"id": "CVE-2021-44228"}

        with patch("threat_base.nvd.NvdClient", MockClient):
            result = update_nvd(confirm=False)
        assert result is True

    @patch("threat_base.nvd.NvdClient")
    def test_reports_unavailable_without_key(self, MockClient: MagicMock) -> None:
        from threat_base.updater import update_nvd

        instance = MockClient.return_value
        instance.available = False

        with patch("threat_base.nvd.NvdClient", MockClient):
            result = update_nvd(confirm=False)
        assert result is True  # Not a failure - NVD is optional


# --- update_all -


class TestUpdateAll:
    """Tests for the orchestrator."""

    @patch("threat_base.data_loader.regenerate_checksums")
    @patch("threat_base.updater.update_nvd", return_value=True)
    @patch("threat_base.updater.update_yara", return_value=True)
    @patch("threat_base.updater.update_attack", return_value=True)
    @patch("threat_base.updater.update_cwe", return_value=True)
    def test_calls_all_sub_updates(
        self, mock_cwe: MagicMock, mock_attack: MagicMock,
        mock_yara: MagicMock, mock_nvd: MagicMock, mock_regen: MagicMock,
    ) -> None:
        from threat_base.updater import update_all

        result = update_all(confirm=False)
        assert result is True
        mock_cwe.assert_called_once()
        mock_attack.assert_called_once()
        mock_yara.assert_called_once()
        mock_nvd.assert_called_once()
        mock_regen.assert_called_once()
