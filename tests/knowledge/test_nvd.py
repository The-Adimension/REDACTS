"""
Tests for REDACTS NVD sub-package - knowledge/nvd/cache.py and client.py

Coverage:
    - NvdCache: put/get, TTL expiry, stale fallback, eviction
    - NvdClient: cache-first lookup, API key detection, batch fetch
    - No network calls - all API interactions are mocked
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from threat_base.nvd import NvdCache, NvdClient


# NvdCache Tests


class TestNvdCache:
    """Tests for the SQLite-backed CVE cache."""

    @pytest.fixture
    def cache(self, tmp_path: Path) -> NvdCache:
        return NvdCache(db_path=tmp_path / "test_nvd.db", ttl_seconds=60)

    def test_put_and_get(self, cache: NvdCache) -> None:
        data = {"id": "CVE-2024-1234", "descriptions": [{"value": "Test"}]}
        cache.put("CVE-2024-1234", data)
        result = cache.get("CVE-2024-1234")
        assert result is not None
        assert result["id"] == "CVE-2024-1234"

    def test_get_miss(self, cache: NvdCache) -> None:
        assert cache.get("CVE-9999-0000") is None

    def test_ttl_expiry(self, tmp_path: Path) -> None:
        cache = NvdCache(db_path=tmp_path / "ttl.db", ttl_seconds=1)
        cache.put("CVE-2024-0001", {"id": "CVE-2024-0001"})

        # Patch time so the entry appears expired
        with patch("threat_base.nvd.time") as mock_time:
            mock_time.time.return_value = time.time() + 10
            assert cache.get("CVE-2024-0001") is None

    def test_stale_fallback(self, tmp_path: Path) -> None:
        cache = NvdCache(db_path=tmp_path / "stale.db", ttl_seconds=1)
        cache.put("CVE-2024-0002", {"id": "CVE-2024-0002"})

        with patch("threat_base.nvd.time") as mock_time:
            mock_time.time.return_value = time.time() + 10
            # Without allow_stale: returns None
            assert cache.get("CVE-2024-0002") is None
            # With allow_stale: returns data
            result = cache.get("CVE-2024-0002", allow_stale=True)
            assert result is not None
            assert result["id"] == "CVE-2024-0002"

    def test_overwrite(self, cache: NvdCache) -> None:
        cache.put("CVE-2024-0003", {"version": 1})
        cache.put("CVE-2024-0003", {"version": 2})
        result = cache.get("CVE-2024-0003")
        assert result is not None
        assert result["version"] == 2

    def test_evict_expired(self, tmp_path: Path) -> None:
        cache = NvdCache(db_path=tmp_path / "evict.db", ttl_seconds=1)
        cache.put("CVE-2024-0004", {"id": "old"})
        cache.put("CVE-2024-0005", {"id": "old2"})

        with patch("threat_base.nvd.time") as mock_time:
            mock_time.time.return_value = time.time() + 10
            evicted = cache.evict_expired()
            assert evicted == 2


# NvdClient Tests


class TestNvdClient:
    """Tests for the NVD API client with mocked network."""

    @pytest.fixture
    def cache(self, tmp_path: Path) -> NvdCache:
        return NvdCache(db_path=tmp_path / "client_cache.db")

    def test_no_api_key_unavailable(self, cache: NvdCache) -> None:
        client = NvdClient(api_key="", cache=cache)
        assert client.available is False

    def test_api_key_available(self, cache: NvdCache) -> None:
        client = NvdClient(api_key="test-key-123", cache=cache)
        assert client.available is True

    def test_cache_hit_skips_api(self, cache: NvdCache) -> None:
        cache.put("CVE-2024-9999", {"id": "CVE-2024-9999", "cached": True})
        client = NvdClient(api_key="key", cache=cache)
        result = client.get_cve("CVE-2024-9999")
        assert result is not None
        assert result["cached"] is True

    def test_no_key_stale_fallback(self, cache: NvdCache) -> None:
        """Without API key, falls back to stale cache."""
        # Put data then expire it
        cache.put("CVE-2024-0010", {"id": "stale-data"})
        cache._ttl = 0  # Force all entries to be "expired"

        client = NvdClient(api_key="", cache=cache)
        result = client.get_cve("CVE-2024-0010")
        assert result is not None
        assert result["id"] == "stale-data"

    def test_no_key_no_cache_returns_none(self, cache: NvdCache) -> None:
        client = NvdClient(api_key="", cache=cache)
        assert client.get_cve("CVE-2024-0099") is None

    @patch("threat_base.nvd.NvdClient._fetch_from_api")
    def test_api_success_caches_result(
        self, mock_fetch: MagicMock, cache: NvdCache
    ) -> None:
        mock_fetch.return_value = {"id": "CVE-2024-1111"}

        client = NvdClient(api_key="key", cache=cache)
        result = client.get_cve("CVE-2024-1111")
        assert result is not None
        assert result["id"] == "CVE-2024-1111"

        # Verify it was cached
        cached = cache.get("CVE-2024-1111")
        assert cached is not None

    def test_batch_fetch(self, cache: NvdCache) -> None:
        cache.put("CVE-A", {"id": "CVE-A"})
        cache.put("CVE-B", {"id": "CVE-B"})
        client = NvdClient(api_key="key", cache=cache)
        results = client.get_cves(["CVE-A", "CVE-B", "CVE-MISSING"])
        assert "CVE-A" in results
        assert "CVE-B" in results
        assert "CVE-MISSING" not in results
