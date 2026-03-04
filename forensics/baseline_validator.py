"""
REDACTS Baseline Validator — Compare target installation against a
known-good reference (the official REDCap archive ZIP extract).

Phase model
-----------
Phase 1  Build SHA-256 manifest from reference (clean ZIP extract).
Phase 2  Structural diff — report added / removed / matched files.
Phase 3  Integrity check — SHA-256 compare on *matched* files.
         Files with identical hashes are CLEAN (skip deep analysis).
         Files with hash mismatch are MODIFIED → feed to deep analysis.
Phase 4  (external) Deep forensic analysis scoped to delta set only.

The ``delta_files`` produced by :py:meth:`BaselineValidator.diff` is the
**only** file set that downstream scanners (security, IoC, sensitive data,
external tools) need to inspect.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..core.hashing import hash_tree as _canonical_hash_tree

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ChecksumBaseline:
    """SHA-256 manifest for every file in a reference REDCap tree."""

    version: str  # e.g. "15.7.4"
    files: dict[str, str] = field(default_factory=dict)  # relpath → sha256
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = ""  # "zip_extract", "local_installation", …
    timestamp: str = ""

    # ── persistence ──────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """Persist baseline to JSON."""
        data = {
            "version": self.version,
            "source": self.source,
            "timestamp": self.timestamp,
            "file_count": len(self.files),
            "files": self.files,
            "metadata": self.metadata,
        }
        path.write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: Path) -> "ChecksumBaseline":
        """Load baseline from JSON."""
        data = json.loads(path.read_text())
        baseline = cls(version=data["version"])
        baseline.files = data.get("files", {})
        baseline.metadata = data.get("metadata", {})
        baseline.source = data.get("source", "")
        baseline.timestamp = data.get("timestamp", "")
        return baseline


@dataclass
class BaselineIntegrityFinding:
    """A single deviation from baseline."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    type: str  # added, removed, modified
    path: str
    message: str
    current_hash: str = ""
    baseline_hash: str = ""
    file_size: int = 0
    current_mtime: str = ""
    recommendation: str = ""


@dataclass
class StructuralDiffResult:
    """Output of Phase 2 + 3: what changed between reference and target."""

    version: str = ""
    reference_source: str = ""
    reference_file_count: int = 0
    target_file_count: int = 0

    # Phase 2 — structural
    files_added: list[str] = field(default_factory=list)
    files_removed: list[str] = field(default_factory=list)
    files_matched: list[str] = field(default_factory=list)

    # Phase 3 — integrity
    files_identical: list[str] = field(default_factory=list)
    files_modified: list[str] = field(default_factory=list)

    # Detailed findings (per-file)
    findings: list[BaselineIntegrityFinding] = field(default_factory=list)

    # Convenience
    @property
    def delta_files(self) -> set[str]:
        """The union of *added* + *modified* — the files that need deep analysis."""
        return set(self.files_added) | set(self.files_modified)

    @property
    def is_clean(self) -> bool:
        return not self.files_added and not self.files_modified and not self.files_removed

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        d = asdict(self)
        d["delta_files"] = sorted(self.delta_files)
        d["delta_count"] = len(self.delta_files)
        d["is_clean"] = self.is_clean
        return d


@dataclass
class BaselineValidationReport:
    """Legacy wrapper — kept for back-compat.  Prefer ``StructuralDiffResult``."""

    version: str = ""
    baseline_source: str = ""
    files_checked: int = 0
    files_in_baseline: int = 0
    files_matched: int = 0
    files_added: int = 0
    files_removed: int = 0
    files_modified: int = 0

    critical_findings: list[BaselineIntegrityFinding] = field(default_factory=list)
    high_findings: list[BaselineIntegrityFinding] = field(default_factory=list)
    medium_findings: list[BaselineIntegrityFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)

    @property
    def is_clean(self) -> bool:
        """True if installation matches baseline exactly."""
        return (
            self.files_added == 0
            and self.files_removed == 0
            and self.files_modified == 0
        )


class BaselineValidator:
    """
    Validates a target REDCap installation against a known-good reference.

    The reference is typically an official REDCap archive ZIP extract — the
    user supplies the exact version they claim to run.

    Two main entry points:

    * :py:meth:`diff` — the new 4-phase audit diffing (preferred)
    * :py:meth:`validate_installation` — legacy full-report approach
    """

    # Directories / files that are expected to differ per-instance.
    # Files matching these prefixes are *not* flagged as "added".
    EXPECTED_ADDITIONS = {
        # Data / upload directories — populated at runtime
        "edocs/",
        "temp/",
        "modules/",          # External Modules are optional add-ons
        "languages/",        # Community translation packs
        # Runtime/cache files
        "__pycache__/",
        "node_modules/",
        ".git/",
        ".svn/",
    }

    # Files whose content is *expected* to change per-instance (credentials,
    # site-specific config).  They still get flagged, but at MEDIUM not CRITICAL.
    EXPECTED_MODIFICATIONS = {
        "database.php",
        "webdav.php",
        "webdav_module.xml",
        "redcap_connect.php",
        ".htaccess",
        ".user.ini",
        "hooks.php",
    }

    # Files to skip entirely during hashing (OS / IDE artefacts).
    _SKIP_NAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
    _SKIP_DIRS = {"__pycache__", ".git", ".svn", "node_modules"}

    def __init__(self) -> None:
        self.baselines_cache: dict[str, ChecksumBaseline] = {}

    # ==================================================================
    # Phase 1–3: diff()  — the PREFERRED entry point for audit mode
    # ==================================================================

    def diff(
        self,
        reference_root: Path,
        target_root: Path,
        version: str = "",
    ) -> StructuralDiffResult:
        """
        Compare *target* installation against *reference* (the clean ZIP extract).

        Returns a :class:`StructuralDiffResult` whose ``.delta_files`` property
        gives exactly the files that need deep forensic analysis.

        Phase 1  Build SHA-256 manifests for both trees.
        Phase 2  Structural diff — added / removed / matched.
        Phase 3  Integrity check — hash compare on matched files.
        """
        result = StructuralDiffResult(version=version, reference_source="local_archive")

        # ── Phase 1: hash both trees ─────────────────────────────────
        logger.info("Phase 1 — hashing reference tree: %s", reference_root)
        ref_hashes = self._hash_tree(reference_root)
        result.reference_file_count = len(ref_hashes)

        logger.info("Phase 1 — hashing target tree: %s", target_root)
        tgt_hashes = self._hash_tree(target_root)
        result.target_file_count = len(tgt_hashes)

        ref_set = set(ref_hashes.keys())
        tgt_set = set(tgt_hashes.keys())

        # ── Phase 2: structural diff ─────────────────────────────────
        result.files_matched = sorted(ref_set & tgt_set)
        raw_added = sorted(tgt_set - ref_set)
        result.files_removed = sorted(ref_set - tgt_set)

        # Filter out expected additions (modules/, edocs/, etc.)
        for rel in raw_added:
            if self._is_expected_addition(rel):
                continue
            result.files_added.append(rel)

        for rel in result.files_added:
            target_file = target_root / rel
            size = target_file.stat().st_size if target_file.exists() else 0
            mtime = ""
            try:
                mtime = datetime.fromtimestamp(
                    target_file.stat().st_mtime, tz=timezone.utc
                ).isoformat()
            except Exception:
                pass
            result.findings.append(
                BaselineIntegrityFinding(
                    severity=self._severity_for_addition(rel),
                    type="added",
                    path=rel,
                    message="File not present in reference archive — possible injection or custom addition.",
                    file_size=size,
                    current_mtime=mtime,
                    recommendation="Verify origin: external module, institutional patch, or unauthorised code.",
                )
            )

        for rel in result.files_removed:
            result.findings.append(
                BaselineIntegrityFinding(
                    severity="HIGH",
                    type="removed",
                    path=rel,
                    message="File present in reference archive but missing from target.",
                    recommendation="May indicate cleanup after compromise or intentional removal.",
                )
            )

        # ── Phase 3: integrity check (hash compare on matched) ───────
        for rel in result.files_matched:
            ref_hash = ref_hashes[rel]
            tgt_hash = tgt_hashes[rel]
            if ref_hash == tgt_hash:
                result.files_identical.append(rel)
            else:
                result.files_modified.append(rel)
                sev, rec = self._classify_modification(rel)
                target_file = target_root / rel
                mtime = ""
                try:
                    mtime = datetime.fromtimestamp(
                        target_file.stat().st_mtime, tz=timezone.utc
                    ).isoformat()
                except Exception:
                    pass
                result.findings.append(
                    BaselineIntegrityFinding(
                        severity=sev,
                        type="modified",
                        path=rel,
                        message=f"Hash mismatch — ref {ref_hash[:12]}… ≠ target {tgt_hash[:12]}…",
                        baseline_hash=ref_hash,
                        current_hash=tgt_hash,
                        current_mtime=mtime,
                        recommendation=rec,
                    )
                )

        logger.info(
            "Baseline diff complete — %d identical, %d modified, %d added, %d removed (%d delta for deep analysis)",
            len(result.files_identical),
            len(result.files_modified),
            len(result.files_added),
            len(result.files_removed),
            len(result.delta_files),
        )
        return result

    # ==================================================================
    # Legacy entry point (kept for backward compatibility)
    # ==================================================================

    def validate_installation(
        self,
        redcap_root: Path,
        version: str,
        baseline: Optional[ChecksumBaseline] = None,
    ) -> BaselineValidationReport:
        """Validate an installation against a stored baseline."""
        report = BaselineValidationReport(version=version)

        if baseline is None:
            baseline = self._fetch_or_cache_baseline(version)
            if baseline is None:
                logger.error("Could not obtain baseline for REDCap %s", version)
                return report

        report.baseline_source = baseline.source
        report.files_in_baseline = len(baseline.files)

        current_hashes = self._hash_tree(redcap_root)
        report.files_checked = len(current_hashes)

        baseline_set = set(baseline.files.keys())
        current_set = set(current_hashes.keys())

        for rel_path in sorted(baseline_set):
            baseline_hash = baseline.files[rel_path]
            if rel_path in current_hashes:
                if baseline_hash == current_hashes[rel_path]:
                    report.files_matched += 1
                else:
                    report.files_modified += 1
                    sev, rec = self._classify_modification(rel_path)
                    finding = BaselineIntegrityFinding(
                        severity=sev,
                        type="modified",
                        path=rel_path,
                        message=f"Hash mismatch: {baseline_hash[:8]}… ≠ {current_hashes[rel_path][:8]}…",
                        current_hash=current_hashes[rel_path],
                        baseline_hash=baseline_hash,
                        recommendation=rec,
                    )
                    if sev == "CRITICAL":
                        report.critical_findings.append(finding)
                    elif sev == "HIGH":
                        report.high_findings.append(finding)
                    else:
                        report.medium_findings.append(finding)
            else:
                report.files_removed += 1
                report.high_findings.append(
                    BaselineIntegrityFinding(
                        severity="HIGH",
                        type="removed",
                        path=rel_path,
                        message="File removed from baseline",
                        recommendation="Verify this file was intentionally removed.",
                    )
                )

        for rel_path in sorted(current_set - baseline_set):
            if self._is_expected_addition(rel_path):
                continue
            report.files_added += 1
            file_size = 0
            try:
                file_size = (redcap_root / rel_path).stat().st_size
            except OSError:
                pass
            report.high_findings.append(
                BaselineIntegrityFinding(
                    severity="HIGH",
                    type="added",
                    path=rel_path,
                    message="File added (not in baseline)",
                    file_size=file_size,
                    recommendation="Verify this file is legitimate.",
                )
            )
        return report

    # ==================================================================
    # Baseline creation helpers
    # ==================================================================

    def create_baseline_from_source(
        self,
        redcap_root: Path,
        version: str,
    ) -> ChecksumBaseline:
        """Create a :class:`ChecksumBaseline` from an extracted archive."""
        hashes = self._hash_tree(redcap_root)
        baseline = ChecksumBaseline(
            version=version,
            source="local_installation",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        baseline.files = hashes
        return baseline

    # ==================================================================
    # Internal helpers
    # ==================================================================

    def _hash_tree(self, root: Path) -> dict[str, str]:
        """Build ``{relative_path: sha256}`` for every file under *root*.

        Delegates to :func:`core.hashing.hash_tree` (canonical
        implementation, DUP-001).
        """
        return _canonical_hash_tree(
            root, skip_predicate=self._should_skip
        )

    def _should_skip(self, rel_path: str) -> bool:
        """Skip OS artefacts and VCS directories."""
        parts = rel_path.split("/")
        if any(p in self._SKIP_DIRS for p in parts):
            return True
        if parts[-1] in self._SKIP_NAMES:
            return True
        return False

    def _is_expected_addition(self, rel_path: str) -> bool:
        """Check if an added file falls in expected-addition directories."""
        for prefix in self.EXPECTED_ADDITIONS:
            if prefix.endswith("/") and rel_path.startswith(prefix):
                return True
        return False

    @staticmethod
    def _severity_for_addition(rel_path: str) -> str:
        """Determine severity for an added file based on extension/location."""
        lower = rel_path.lower()
        # Executable extensions in unexpected places
        if lower.endswith((".php", ".phtml", ".phar", ".php5", ".php7")):
            return "CRITICAL"
        if lower.endswith((".js",)):
            return "HIGH"
        if lower.endswith((".sh", ".bash", ".bat", ".cmd", ".ps1")):
            return "HIGH"
        # Config / htaccess
        if ".htaccess" in lower or ".user.ini" in lower:
            return "CRITICAL"
        return "MEDIUM"

    @staticmethod
    def _classify_modification(rel_path: str) -> tuple[str, str]:
        """Classify the severity of a modified (hash-mismatched) file."""
        lower = rel_path.lower()
        name = lower.rsplit("/", 1)[-1]

        # Known persistence / attack-surface files
        if name == "hooks.php":
            return "CRITICAL", "hooks.php modified — primary INFINITERED persistence target."
        if name == "upgrade.php":
            return "CRITICAL", "upgrade.php modified — persistent compromise indicator."
        if name in ("authentication.php", "auth_functions.php"):
            return "CRITICAL", "Authentication file modified — credential-theft risk."
        if ".htaccess" in name:
            return "CRITICAL", ".htaccess changed — check for auto_prepend_file persistence."
        if ".user.ini" in name:
            return "CRITICAL", ".user.ini changed — PHP runtime persistence."
        if name == "database.php":
            return "MEDIUM", "database.php differs — expected (contains local credentials)."
        if name in ("webdav.php", "webdav_module.xml", "redcap_connect.php"):
            return "MEDIUM", "Instance-specific config file — expected to differ."

        # General PHP modification
        if lower.endswith(".php"):
            return "HIGH", "Core PHP file modified — manual verification required."

        return "MEDIUM", "File modified — determine if intentional."

    def _fetch_or_cache_baseline(self, version: str) -> Optional[ChecksumBaseline]:
        """Fetch baseline from cache (remote not implemented yet)."""
        if version in self.baselines_cache:
            return self.baselines_cache[version]
        logger.warning("No baseline available for REDCap %s", version)
        return None
