"""NVD CVE enrichment with on-disk cache.

Why a cache: most REDACTS runs happen on hospital networks where outbound
HTTP to nvd.nist.gov may be filtered, throttled, or absent. The SQLite
cache (``~/.redacts/nvd_cache.db``, 7-day TTL) keeps recent CVE detail
available, and on lookup failure we serve a stale entry rather than
dropping the enrichment - partial truth beats none for an analyst.

What it will not catch: CVEs that have not yet appeared in NVD (typical
for REDCap-specific issues until they get assigned), and CVEs whose CPE
strings do not match REDCap's vendor/product naming. Treat absence of an
entry as 'unknown', not 'safe'.

NVD 2.0 rate limits: 5/30s anonymous, 50/30s with API key (see
https://nvd.nist.gov/developers/vulnerabilities).

Copyright 2024-2026 The Adimension / Shehab Anwer
Apache-2.0.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from .sources import nvd_api_key, nvd_base_url

logger = logging.getLogger(__name__)

# --- Cache constants --------------


def _default_db_dir() -> Path:
    """Resolved at call-time so REDACTS_HOME / REDACTS_CACHE_DIR overrides apply."""
    from static.core.paths import cache_dir
    return cache_dir()


_DEFAULT_DB_NAME = "nvd_cache.db"
_DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days

# --- Client constants -------------

# NVD REST endpoint and API key are sourced from the active
# FrozenCaseContract via :mod:`threat_base.sources`. No
# module-level URL constant or environment-variable fallback exists.

# Rate-limit guardrail (seconds between requests)
_RATE_LIMIT_NO_KEY = 6.0  # 5 req / 30s
_RATE_LIMIT_WITH_KEY = 0.6  # 50 req / 30s

__all__ = ["NvdCache", "NvdClient"]


# --- NvdCache ---


class NvdCache:
    """SQLite-backed CVE lookup cache with TTL and stale fallback.

    Usage::

        cache = NvdCache()
        hit = cache.get("CVE-2024-1234")
        if hit is None:
            data = ...  # fetch from NVD API
            cache.put("CVE-2024-1234", data)
    """

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._ttl = ttl_seconds
        if db_path is None:
            db_dir = _default_db_dir()
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = db_dir / _DEFAULT_DB_NAME
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Create the cache table if it does not exist."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cve_id    TEXT PRIMARY KEY,
                    data      TEXT NOT NULL,
                    fetched   REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db_path), timeout=5)

    def get(
        self, cve_id: str, *, allow_stale: bool = False
    ) -> dict[str, Any] | None:
        """Retrieve a cached CVE entry.

        Args:
            cve_id: CVE identifier (e.g. ``"CVE-2024-1234"``).
            allow_stale: If ``True``, return expired entries as fallback.

        Returns:
            Parsed CVE data dict, or ``None`` if not cached (or expired
            when *allow_stale* is ``False``).
        """
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT data, fetched FROM nvd_cache WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()
        except sqlite3.Error as exc:
            logger.debug("Cache read error for %s: %s", cve_id, exc)
            return None

        if row is None:
            return None

        data_json, fetched = row
        age = time.time() - fetched
        if age > self._ttl and not allow_stale:
            return None

        try:
            return json.loads(data_json)
        except json.JSONDecodeError:
            return None

    def put(self, cve_id: str, data: dict[str, Any]) -> None:
        """Store a CVE entry in the cache."""
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO nvd_cache (cve_id, data, fetched)
                    VALUES (?, ?, ?)
                    """,
                    (cve_id, json.dumps(data, default=str), time.time()),
                )
        except sqlite3.Error as exc:
            logger.debug("Cache write error for %s: %s", cve_id, exc)

    def evict_expired(self) -> int:
        """Remove entries older than TTL. Returns count of evicted rows."""
        cutoff = time.time() - self._ttl
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM nvd_cache WHERE fetched < ?", (cutoff,)
                )
                return cursor.rowcount
        except sqlite3.Error as exc:
            logger.debug("Cache eviction error: %s", exc)
            return 0


# --- NvdClient --


class NvdClient:
    """Optional NVD 2.0 API client with transparent SQLite cache.

    Usage::

        client = NvdClient()
        if client.available:
            cve = client.get_cve("CVE-2024-1234")
    """

    def __init__(
        self,
        api_key: str | None = None,
        *,
        cache: NvdCache | None = None,
    ) -> None:
        self._api_key = api_key if api_key is not None else nvd_api_key()
        self._last_request_time = 0.0
        self._rate_limit = (
            _RATE_LIMIT_WITH_KEY if self._api_key else _RATE_LIMIT_NO_KEY
        )
        self._cache = cache or NvdCache()

    @property
    def available(self) -> bool:
        """Whether the NVD client is configured (has an API key)."""
        return bool(self._api_key)

    def get_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Fetch CVE details, checking cache first.

        Returns cached data if fresh.  Falls back to stale cache
        on API failure (air-gapped mode).
        """
        # 1. Check cache (fresh)
        cached = self._cache.get(cve_id)
        if cached is not None:
            return cached

        # 2. Try API
        if not self._api_key:
            # No API key - try stale cache as last resort
            stale = self._cache.get(cve_id, allow_stale=True)
            if stale is not None:
                logger.debug("NVD cache stale hit for %s (no API key)", cve_id)
                return stale
            logger.debug("NVD API key not set - skipping CVE lookup for %s", cve_id)
            return None

        result = self._fetch_from_api(cve_id)
        if result is not None:
            self._cache.put(cve_id, result)
            return result

        # 3. API failed - fall back to stale cache
        stale = self._cache.get(cve_id, allow_stale=True)
        if stale is not None:
            logger.debug("NVD API failed for %s - serving stale cache", cve_id)
            return stale

        return None

    def get_cves(self, cve_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Batch-fetch multiple CVEs.

        Returns:
            Dict of ``cve_id -> data`` for each successfully resolved CVE.
        """
        results: dict[str, dict[str, Any]] = {}
        for cve_id in cve_ids:
            data = self.get_cve(cve_id)
            if data is not None:
                results[cve_id] = data
        return results

    def _fetch_from_api(self, cve_id: str) -> dict[str, Any] | None:
        """Hit the NVD REST API for a single CVE."""
        try:
            import requests
        except ImportError:
            logger.debug("requests not available for NVD client")
            return None

        self._rate_limit_wait()

        try:
            headers = {"apiKey": self._api_key}
            params = {"cveId": cve_id}
            resp = requests.get(
                nvd_base_url(),
                headers=headers,
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                return vulnerabilities[0].get("cve")
            return None
        except Exception as exc:
            logger.debug("NVD API error for %s: %s", cve_id, exc)
            return None

    def _rate_limit_wait(self) -> None:
        """Enforce rate limiting between requests."""
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit:
            time.sleep(self._rate_limit - elapsed)
        self._last_request_time = time.monotonic()
