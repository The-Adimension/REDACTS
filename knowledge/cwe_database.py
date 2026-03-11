"""
REDACTS CWE Knowledge Base — Offline CSV-backed CWE enrichment data.

**OFFLINE ONLY** — this module contains zero network code.  All data is
loaded from a bundled CSV file (``knowledge/data/cwec_v4.19.csv``)
that was downloaded from MITRE's official CWE website and committed to
the repository with a SHA-256 checksum.

Provides structured CWE weakness data for finding enrichment,
report generation, and recommendation backfill.

Architecture
~~~~~~~~~~~~
*   ``CweEntry`` — frozen dataclass describing one weakness.
*   ``CweDatabase`` — accessor class (Strategy pattern plug-in for the
    investigation pipeline), reads from the bundled CSV file.
*   ``IntegrityReport`` — structured audit of the data file's integrity.

Integration points
~~~~~~~~~~~~~~~~~~
*   ``investigation/steps/cwe_enrichment_step.py`` — post-step that
    enriches ``InvestigationFinding`` instances.
*   ``core/models.py`` — ``UnifiedFinding.cwe_name`` for SARIF taxa.
*   ``orchestration/tool_orchestrator.py`` — ``_enrich_cwe()`` for
    UnifiedFinding enrichment after all phases.

Update procedure
~~~~~~~~~~~~~~~~
The bundled CSV is **pinned** — it is never updated automatically.
To update, run ``python -m REDACTS.knowledge.cwe_updater`` manually.
That script requires explicit user confirmation at every step.

────────────────────────────────────────────────────────────────────────
CWE™ content is derived from the Common Weakness Enumeration, which is
managed by The MITRE Corporation and sponsored by the U.S. Department
of Homeland Security (DHS) Cybersecurity and Infrastructure Security
Agency (CISA).

Copyright © 2006–2026, The MITRE Corporation.  CWE, CWSS, CWRAF, and
the CWE logo are trademarks of The MITRE Corporation.

This data is used under the CWE Terms of Use:
https://cwe.mitre.org/about/termsofuse.html

Non-exclusive, royalty-free license for research, development, and
commercial purposes.
────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import csv
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# Constants — config-driven, overridable
# ═══════════════════════════════════════════════════════════════════════════

_DATA_DIR: Path = Path(__file__).resolve().parent / "data"
CWE_CSV_FILENAME: str = "cwec_v4.19.csv"
CWE_CHECKSUM_FILENAME: str = "cwec_v4.19.csv.sha256"
CWE_VERSION: str = "4.19"
CWE_RELEASE_DATE: str = "2025-02-13"
CWE_SOURCE_URL: str = "https://cwe.mitre.org/data/csv/1000.csv.zip"
CWE_ATTRIBUTION: str = (
    "CWE™ content © 2006–2026 The MITRE Corporation. "
    "Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html)."
)


# ═══════════════════════════════════════════════════════════════════════════
# Data model
# ═══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class CweEntry:
    """Immutable record describing a single CWE weakness."""

    cwe_id: str  # e.g. "CWE-89"
    name: str  # Official short name
    description: str  # One-sentence summary (truncated to 500 chars)
    mitigation: str  # First recommended mitigation from MITRE data
    likelihood: str  # "High", "Medium", "Low", "" (unknown)


@dataclass(frozen=True)
class IntegrityReport:
    """Structured audit of the CWE data file's integrity.

    Every field is populated — nothing is hidden, nothing is assumed.
    """

    csv_path: str
    csv_exists: bool
    csv_size_bytes: int
    checksum_path: str
    checksum_exists: bool
    expected_sha256: str
    actual_sha256: str
    match: bool
    cwe_entry_count: int
    load_timestamp: str  # ISO 8601
    status: str  # "VERIFIED", "MISMATCH", "MISSING_CSV", "MISSING_CHECKSUM"


# ═══════════════════════════════════════════════════════════════════════════
# CSV parsing helpers
# ═══════════════════════════════════════════════════════════════════════════


def _extract_first_mitigation(raw: str) -> str:
    """Extract the first mitigation description from MITRE's serialized format.

    The Potential Mitigations column uses ``::PHASE:...:DESCRIPTION:text::``
    blocks.  We extract the first DESCRIPTION value.
    """
    if not raw:
        return ""
    marker = "DESCRIPTION:"
    idx = raw.find(marker)
    if idx == -1:
        return ""
    start = idx + len(marker)
    # End at next :: delimiter or end of string
    end = raw.find("::", start)
    if end == -1:
        return raw[start:].strip()
    return raw[start:end].strip()


def _compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 of a file using chunked reading."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_csv(csv_path: Path) -> dict[str, CweEntry]:
    """Parse the MITRE CWE CSV into a dict of CWE-ID → CweEntry.

    Skips deprecated entries.  Returns empty dict if file is missing.
    """
    if not csv_path.is_file():
        logger.error("CWE CSV not found: %s", csv_path)
        return {}

    entries: dict[str, CweEntry] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            status = row.get("Status", "")
            if status == "Deprecated":
                continue

            raw_id = row.get("CWE-ID", "").strip()
            if not raw_id:
                continue

            cwe_id = f"CWE-{raw_id}"
            name = row.get("Name", "").strip()
            desc = row.get("Description", "").strip()[:500]
            mitigation = _extract_first_mitigation(
                row.get("Potential Mitigations", "")
            )
            likelihood = row.get("Likelihood of Exploit", "").strip()

            entries[cwe_id] = CweEntry(
                cwe_id=cwe_id,
                name=name,
                description=desc,
                mitigation=mitigation,
                likelihood=likelihood,
            )

    logger.info("CWE database loaded: %d entries from %s", len(entries), csv_path.name)
    return entries


def _read_expected_checksum(checksum_path: Path) -> str:
    """Read the expected SHA-256 from the .sha256 file."""
    if not checksum_path.is_file():
        return ""
    content = checksum_path.read_text(encoding="utf-8").strip()
    # Format: "hash  filename" (standard sha256sum format)
    return content.split()[0] if content else ""


# ═══════════════════════════════════════════════════════════════════════════
# Database accessor
# ═══════════════════════════════════════════════════════════════════════════


class CweDatabase:
    """Read-only accessor for the MITRE CWE knowledge base.

    Backed by a bundled CSV file with SHA-256 integrity verification.
    Follows the same strategy/plug-in pattern as
    :class:`knowledge.IoCDatabase` and :class:`knowledge.AttackVectorDatabase`.

    **Offline only** — no network code, no dynamic downloads.
    """

    def __init__(self, *, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir or _DATA_DIR
        self._csv_path = self._data_dir / CWE_CSV_FILENAME
        self._checksum_path = self._data_dir / CWE_CHECKSUM_FILENAME

        # Verify integrity FIRST — fail loudly, never silently
        self._integrity = self._build_integrity_report()
        if self._integrity.status == "VERIFIED":
            logger.info(
                "CWE data integrity VERIFIED: %s (%d entries, SHA-256 %s)",
                self._csv_path.name,
                self._integrity.cwe_entry_count,
                self._integrity.actual_sha256[:16] + "...",
            )
        elif self._integrity.status == "MISSING_CSV":
            logger.warning(
                "CWE CSV not found at %s — CWE enrichment will be unavailable. "
                "Run 'python -m REDACTS.knowledge.cwe_updater' to download.",
                self._csv_path,
            )
        elif self._integrity.status == "MISSING_CHECKSUM":
            logger.warning(
                "CWE checksum file not found at %s — integrity cannot be verified. "
                "Data will be loaded but integrity is UNVERIFIED.",
                self._checksum_path,
            )
        else:
            raise ValueError(
                f"CWE data integrity check FAILED. "
                f"Expected SHA-256: {self._integrity.expected_sha256}, "
                f"Actual SHA-256: {self._integrity.actual_sha256}. "
                f"The file at {self._csv_path} may have been tampered with. "
                f"Run 'python -m REDACTS.knowledge.cwe_updater' to re-download."
            )

        self._data = _load_csv(self._csv_path)

    # ── Integrity ─────────────────────────────────────────────────────

    def _build_integrity_report(self) -> IntegrityReport:
        """Build a complete, transparent integrity report."""
        timestamp = datetime.now(timezone.utc).isoformat()
        csv_exists = self._csv_path.is_file()
        checksum_exists = self._checksum_path.is_file()

        if not csv_exists:
            return IntegrityReport(
                csv_path=str(self._csv_path),
                csv_exists=False,
                csv_size_bytes=0,
                checksum_path=str(self._checksum_path),
                checksum_exists=checksum_exists,
                expected_sha256="",
                actual_sha256="",
                match=False,
                cwe_entry_count=0,
                load_timestamp=timestamp,
                status="MISSING_CSV",
            )

        csv_size = self._csv_path.stat().st_size
        actual_hash = _compute_file_sha256(self._csv_path)

        if not checksum_exists:
            # Load data to count entries even without checksum
            data = _load_csv(self._csv_path)
            return IntegrityReport(
                csv_path=str(self._csv_path),
                csv_exists=True,
                csv_size_bytes=csv_size,
                checksum_path=str(self._checksum_path),
                checksum_exists=False,
                expected_sha256="",
                actual_sha256=actual_hash,
                match=False,
                cwe_entry_count=len(data),
                load_timestamp=timestamp,
                status="MISSING_CHECKSUM",
            )

        expected_hash = _read_expected_checksum(self._checksum_path)
        match = actual_hash == expected_hash

        # Count entries from CSV
        data = _load_csv(self._csv_path)

        return IntegrityReport(
            csv_path=str(self._csv_path),
            csv_exists=True,
            csv_size_bytes=csv_size,
            checksum_path=str(self._checksum_path),
            checksum_exists=True,
            expected_sha256=expected_hash,
            actual_sha256=actual_hash,
            match=match,
            cwe_entry_count=len(data),
            load_timestamp=timestamp,
            status="VERIFIED" if match else "MISMATCH",
        )

    @property
    def integrity_report(self) -> IntegrityReport:
        """Full integrity audit — nothing hidden, nothing assumed."""
        return self._integrity

    def verify_integrity(self) -> bool:
        """Re-compute and verify.  Returns True only on exact match."""
        if not self._csv_path.is_file() or not self._checksum_path.is_file():
            return False
        actual = _compute_file_sha256(self._csv_path)
        expected = _read_expected_checksum(self._checksum_path)
        return actual == expected

    # ── Lookups ───────────────────────────────────────────────────────

    @staticmethod
    def _normalize_id(cwe_id: str) -> str:
        """Normalize a CWE identifier to canonical 'CWE-NNN' form."""
        raw = cwe_id.strip().upper()
        if raw.startswith("CWE-"):
            return raw
        # Handle bare numbers: "89" → "CWE-89"
        digits = "".join(c for c in raw if c.isdigit())
        return f"CWE-{digits}" if digits else ""

    def get(self, cwe_id: str) -> CweEntry | None:
        """Look up a CWE entry by ID.  Returns ``None`` for unknown IDs."""
        key = self._normalize_id(cwe_id)
        return self._data.get(key)

    def get_name(self, cwe_id: str) -> str:
        """Return the weakness name, or empty string if unknown."""
        entry = self.get(cwe_id)
        return entry.name if entry else ""

    def get_recommendation(self, cwe_id: str) -> str:
        """Return the generic mitigation, or empty string if unknown."""
        entry = self.get(cwe_id)
        return entry.mitigation if entry else ""

    def contains(self, cwe_id: str) -> bool:
        """Check whether the database has an entry for this CWE."""
        return self.get(cwe_id) is not None

    # ── Enrichment helper ─────────────────────────────────────────────

    def enrich_name(self, cwe_id: str) -> str:
        """Return 'CWE-NNN: Name' display string, or raw *cwe_id* if unknown."""
        entry = self.get(cwe_id)
        if entry:
            return f"{entry.cwe_id}: {entry.name}"
        return cwe_id

    # ── Metadata ──────────────────────────────────────────────────────

    @property
    def version(self) -> str:
        return CWE_VERSION

    @property
    def release_date(self) -> str:
        return CWE_RELEASE_DATE

    @property
    def attribution(self) -> str:
        return CWE_ATTRIBUTION

    @property
    def entry_count(self) -> int:
        return len(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return (
            f"CweDatabase(version={CWE_VERSION!r}, entries={len(self._data)}, "
            f"integrity={self._integrity.status!r})"
        )
