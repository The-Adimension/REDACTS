"""
Tests for REDACTS ATT&CK Prefetch - knowledge/prefetch.py

Coverage:
    - prefetch_attack_data: cache hit, force re-download, download failure
    - _verify_bundle: valid hash, invalid hash, missing sidecar
    - is_attack_data_available: present + valid, missing, tampered
    All network calls are mocked - no real downloads.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from threat_base.prefetch import (
    _verify_bundle,
    is_attack_data_available,
    prefetch_attack_data,
)


# --- _verify_bundle ---------------


class TestVerifyBundle:
    """Tests for SHA-256 sidecar verification."""

    def test_valid_hash(self, tmp_path: Path) -> None:
        bundle = tmp_path / "bundle.json"
        bundle.write_text('{"objects":[]}', encoding="utf-8")
        sha = tmp_path / "bundle.json.sha256"
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        sha.write_text(digest + "\n", encoding="utf-8")

        assert _verify_bundle(bundle, sha) is True

    def test_invalid_hash(self, tmp_path: Path) -> None:
        bundle = tmp_path / "bundle.json"
        bundle.write_text('{"objects":[]}', encoding="utf-8")
        sha = tmp_path / "bundle.json.sha256"
        sha.write_text("0" * 64 + "\n", encoding="utf-8")

        assert _verify_bundle(bundle, sha) is False

    def test_missing_sidecar(self, tmp_path: Path) -> None:
        bundle = tmp_path / "bundle.json"
        bundle.write_text('{"objects":[]}', encoding="utf-8")
        sha = tmp_path / "bundle.json.sha256"  # does not exist

        assert _verify_bundle(bundle, sha) is False


# --- is_attack_data_available -----


class TestIsAttackDataAvailable:
    """Tests for cache availability check."""

    def test_available_when_valid(self, tmp_path: Path) -> None:
        bundle = tmp_path / "enterprise-attack.json"
        bundle.write_text('{"objects":[]}', encoding="utf-8")
        sha = tmp_path / "enterprise-attack.json.sha256"
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        sha.write_text(digest, encoding="utf-8")

        assert is_attack_data_available(data_dir=tmp_path) is True

    def test_unavailable_when_missing(self, tmp_path: Path) -> None:
        assert is_attack_data_available(data_dir=tmp_path) is False

    def test_unavailable_when_tampered(self, tmp_path: Path) -> None:
        bundle = tmp_path / "enterprise-attack.json"
        bundle.write_text('{"objects":[]}', encoding="utf-8")
        sha = tmp_path / "enterprise-attack.json.sha256"
        sha.write_text("bad_hash", encoding="utf-8")

        assert is_attack_data_available(data_dir=tmp_path) is False


# --- prefetch_attack_data ---------


class TestPrefetchAttackData:
    """Tests for the download function with mocked network."""

    def test_returns_true_when_cached_and_valid(self, tmp_path: Path) -> None:
        """Should not download if valid cache exists."""
        bundle = tmp_path / "enterprise-attack.json"
        content = json.dumps({"objects": [{"type": "attack-pattern"}]})
        bundle.write_text(content, encoding="utf-8")
        sha = tmp_path / "enterprise-attack.json.sha256"
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        sha.write_text(digest, encoding="utf-8")

        result = prefetch_attack_data(dest_dir=tmp_path, force=False)
        assert result is True

    def test_force_redownloads(self, tmp_path: Path) -> None:
        """force=True should attempt download even with cache."""
        bundle = tmp_path / "enterprise-attack.json"
        content = json.dumps({"objects": [{"type": "attack-pattern"}]})
        bundle.write_text(content, encoding="utf-8")
        sha = tmp_path / "enterprise-attack.json.sha256"
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        sha.write_text(digest, encoding="utf-8")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        new_content = json.dumps({"objects": [{"type": "attack-pattern"}, {"type": "malware"}]})
        mock_resp.iter_content.return_value = [new_content.encode()]
        mock_resp.raise_for_status = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        import requests as requests_mod

        with patch.object(requests_mod, "get", return_value=mock_resp) as mock_get:
            result = prefetch_attack_data(dest_dir=tmp_path, force=True)

        assert result is True
        mock_get.assert_called_once()

    def test_returns_false_without_requests(self, tmp_path: Path) -> None:
        """Should gracefully return False if requests is not importable."""
        import threat_base.prefetch as pf

        with patch.dict("sys.modules", {"requests": None}):
            # Force re-evaluation of the import
            with patch.object(pf, "requests", None, create=True):
                # The function does `import requests` internally, so we need
                # to make the import fail
                import builtins
                real_import = builtins.__import__

                def fail_requests(name, *args, **kwargs):
                    if name == "requests":
                        raise ImportError("No module named 'requests'")
                    return real_import(name, *args, **kwargs)

                with patch("builtins.__import__", side_effect=fail_requests):
                    result = prefetch_attack_data(dest_dir=tmp_path, force=True)
                    assert result is False

    def test_cleans_up_on_failure(self, tmp_path: Path) -> None:
        """Should not leave partial files on download failure."""
        import requests as requests_mod

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = ConnectionError("Network down")
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(requests_mod, "get", return_value=mock_resp):
            result = prefetch_attack_data(dest_dir=tmp_path, force=True)

        assert result is False
        assert not (tmp_path / "enterprise-attack.json").exists()
        assert not (tmp_path / "enterprise-attack.json.sha256").exists()
