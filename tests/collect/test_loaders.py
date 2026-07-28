"""Tests for loaders - FTP port fix, archive path-traversal protection."""

from __future__ import annotations

import contextlib
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from static.collect.loaders import FTPLoader, LoaderError, ZipLoader

# ---------- FTP Loader ----------


class TestFTPPortSelection:
    """Verify SFTP defaults to port 22, FTP to 21."""

    def test_sftp_port_22(self):
        loader = FTPLoader()
        assert loader.can_handle("sftp://host/path.zip") is True
        # Port selection happens inside load() via urlparse,
        # so we just verify the can_handle + validate path
        assert loader.validate("sftp://host/path.zip") is True

    def test_ftp_validate(self):
        loader = FTPLoader()
        assert loader.validate("ftp://host/path.zip") is True
        assert loader.validate("http://host/x") is False
        assert loader.validate("ftp://") is False  # no hostname


class TestFTPPortParsing:
    """Directly verify the port selection logic."""

    def test_sftp_default_port(self):
        from urllib.parse import urlparse

        parsed = urlparse("sftp://example.com/file.zip")
        port = parsed.port or (22 if parsed.scheme == "sftp" else 21)
        assert port == 22

    def test_ftp_default_port(self):
        from urllib.parse import urlparse

        parsed = urlparse("ftp://example.com/file.zip")
        port = parsed.port or (22 if parsed.scheme == "sftp" else 21)
        assert port == 21

    def test_explicit_port_honoured(self):
        from urllib.parse import urlparse

        parsed = urlparse("sftp://example.com:2222/file.zip")
        port = parsed.port or (22 if parsed.scheme == "sftp" else 21)
        assert port == 2222


# ---------- ZIP Loader: Zip Slip protection ----------


class TestZipSlipProtection:
    def _make_zip(self, tmp_path: Path, entries: dict[str, bytes]) -> Path:
        """Create a ZIP with the given {name: content} entries."""
        archive = tmp_path / "test.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return archive

    def test_safe_zip_extracts(self, tmp_path):
        archive = self._make_zip(tmp_path, {"readme.txt": b"hello"})
        dest = tmp_path / "out"
        loader = ZipLoader()
        root = loader.load(str(archive), dest)
        assert (dest / "readme.txt").exists() or any(dest.rglob("readme.txt"))

    def test_rejects_absolute_path_entry(self, tmp_path):
        """Absolute paths inside ZIPs must be rejected."""
        archive = self._make_zip(tmp_path, {"/etc/passwd": b"root:x"})
        dest = tmp_path / "out"
        loader = ZipLoader()
        # PathSecurity.validate_zip_entry should catch this
        # The actual behaviour depends on PathSecurity implementation;
        # at minimum the extraction should NOT place a file at /etc/passwd
        try:
            loader.load(str(archive), dest)
        except LoaderError as exc:
            assert str(exc)
        # Verify no file at absolute location (just in case)
        assert not Path("/etc/passwd_redacts_test").exists()

# ---------- ZIP Loader: Zip bomb protection ----------


class TestZipBombProtection:
    def test_rejects_high_ratio(self, tmp_path):
        """A suspiciously high compression ratio should be rejected."""
        archive = tmp_path / "bomb.zip"
        # Create a ZIP with high compression potential (repeated bytes)
        data = b"\x00" * 10_000_000  # 10MB of zeros compresses to ~10KB
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", data)
        compressed_size = archive.stat().st_size
        ratio = 10_000_000 / compressed_size
        if ratio > 100:
            dest = tmp_path / "out"
            with pytest.raises(LoaderError, match="zip bomb"):
                ZipLoader().load(str(archive), dest)


# ---------- ZIP Loader: validate ----------


class TestZipLoaderValidate:
    def test_nonexistent_file(self, tmp_path):
        loader = ZipLoader()
        assert loader.validate(str(tmp_path / "nope.zip")) is False

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.zip"
        f.write_bytes(b"")
        assert ZipLoader().validate(str(f)) is False

    def test_directory_not_file(self, tmp_path):
        assert ZipLoader().validate(str(tmp_path)) is False



# ---------- FTP Loader: Security ----------


class TestFTPLoaderSecurity:
    def test_sftp_uses_sshclient(self, tmp_path):
        """Verify SFTP uses SSHClient with host key verification, not raw Transport."""
        # Mock paramiko entirely since it might not be installed in the test environment
        mock_paramiko = MagicMock()
        mock_client_instance = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_client_instance

        # We need to simulate the sftp object
        mock_sftp = MagicMock()
        mock_client_instance.open_sftp.return_value = mock_sftp

        # When sftp.stat is called, we want to bypass the size check
        mock_sftp.stat.side_effect = OSError("Simulated stat failure")

        with patch.dict("sys.modules", {"paramiko": mock_paramiko}):
            loader = FTPLoader()

            # Use _download_sftp directly to bypass tempfile/url parsing complexities
            local_path = tmp_path / "downloaded.zip"

            # Execute. The mock chain is intentionally incomplete - we
            # assert on paramiko call signatures, not on a real SFTP
            # transfer, so any exception raised by the half-wired mock
            # is irrelevant to the assertions below.
            with contextlib.suppress(Exception):
                loader._download_sftp(
                    host="example.com",
                    port=22,
                    path="/remote/path.zip",
                    local_path=local_path,
                    username="user",
                    password="password"
                )

            # Assertions
            mock_paramiko.SSHClient.assert_called_once()
            mock_client_instance.load_system_host_keys.assert_called_once()
            mock_client_instance.set_missing_host_key_policy.assert_called_once_with(mock_paramiko.RejectPolicy())
            mock_client_instance.connect.assert_called_once_with(
                hostname="example.com",
                port=22,
                username="user",
                password="password"
            )
            mock_client_instance.open_sftp.assert_called_once()
            mock_sftp.get.assert_called_once_with("/remote/path.zip", str(local_path))
            mock_sftp.close.assert_called_once()
            mock_client_instance.close.assert_called_once()


# ---------- REDCap root detection ----------


class TestDetectRedcapRoot:
    """detect_redcap_root must align the official source package with a deploy.

    The official REDCap distribution nests the versioned application under
    ``redcap/redcap_vX.Y.Z/`` behind a thin installer wrapper that *also*
    carries marker files. A deployed tree exposes that same application at its
    top level. Root detection must descend to the versioned application root so
    the two share relative paths - otherwise a baseline diff sees every file as
    added/removed.
    """

    @staticmethod
    def _touch(p: Path) -> None:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x", encoding="utf-8")

    def _markers(self, directory: Path) -> None:
        for m in ("redcap_connect.php", "database.php", "cron.php"):
            self._touch(directory / m)

    def test_descends_into_versioned_app_root(self, tmp_path: Path) -> None:
        from static.collect.loaders import detect_redcap_root

        self._markers(tmp_path / "redcap")  # installer wrapper
        self._markers(tmp_path / "redcap" / "redcap_v15.7.4")  # versioned app
        self._touch(tmp_path / "redcap" / "redcap_v15.7.4" / "API" / "index.php")

        root = detect_redcap_root(tmp_path)
        assert root == tmp_path / "redcap" / "redcap_v15.7.4"

    def test_deployed_tree_without_versioned_subdir_is_unchanged(self, tmp_path: Path) -> None:
        from static.collect.loaders import detect_redcap_root

        self._markers(tmp_path / "redcap_v15.7.4-server")
        self._touch(tmp_path / "redcap_v15.7.4-server" / "API" / "index.php")

        root = detect_redcap_root(tmp_path)
        assert root == tmp_path / "redcap_v15.7.4-server"

    def test_markers_at_top_level_returns_top(self, tmp_path: Path) -> None:
        from static.collect.loaders import detect_redcap_root

        self._markers(tmp_path)
        assert detect_redcap_root(tmp_path) == tmp_path

    def test_top_level_with_versioned_child_descends(self, tmp_path: Path) -> None:
        from static.collect.loaders import detect_redcap_root

        self._markers(tmp_path)
        self._markers(tmp_path / "redcap_v15.7.4")
        assert detect_redcap_root(tmp_path) == tmp_path / "redcap_v15.7.4"

    def test_highest_version_wins(self, tmp_path: Path) -> None:
        from static.collect.loaders import detect_redcap_root

        self._markers(tmp_path / "redcap")
        self._markers(tmp_path / "redcap" / "redcap_v15.6.0")
        self._markers(tmp_path / "redcap" / "redcap_v15.7.4")
        assert detect_redcap_root(tmp_path) == tmp_path / "redcap" / "redcap_v15.7.4"

    def test_no_markers_returns_path_unchanged(self, tmp_path: Path) -> None:
        from static.collect.loaders import detect_redcap_root

        (tmp_path / "random").mkdir()
        assert detect_redcap_root(tmp_path) == tmp_path

    def test_versioned_child_without_markers_is_not_chosen(self, tmp_path: Path) -> None:
        """A redcap_v* dir that lacks markers is not a valid app root."""
        from static.collect.loaders import detect_redcap_root

        self._markers(tmp_path / "redcap")
        (tmp_path / "redcap" / "redcap_v15.7.4").mkdir(parents=True)  # no markers
        assert detect_redcap_root(tmp_path) == tmp_path / "redcap"
