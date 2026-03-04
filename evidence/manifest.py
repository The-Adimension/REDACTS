"""
REDACTS Evidence Manifest — Per-file forensic metadata.

Every file in the evidence source is catalogued with:
    - Cryptographic hashes (MD5, SHA-256, SHA-512)
    - Timestamps (created, modified, accessed)
    - Permissions and ownership
    - MIME type and size
    - Classification (known REDCap, external module, unknown/orphan)
    - Anomaly flags (unexpected file type, location, or presence)
"""

from __future__ import annotations

import json
import logging
import math
import mimetypes
import os
import stat
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..core.constants import VERSION, get_category_map, get_language_map

# ---------------------------------------------------------------------------
# Entropy assessment thresholds
# ---------------------------------------------------------------------------
# These intentionally diverge from core.constants.DEFAULT_ENTROPY_THRESHOLD
# (7.5) and ELEVATED_ENTROPY_THRESHOLD (6.0).  The manifest uses lower
# thresholds because, as an evidence collector, it should flag a broader
# set of files for forensic review.  A future config-expansion step may
# unify them under EvidenceConfig.entropy_threshold.
_SUSPICIOUS_ENTROPY: float = 7.0
"""Entropy above which a file is flagged *suspicious* in the manifest."""

_ELEVATED_ENTROPY: float = 5.5
"""Entropy above which a file is flagged *elevated* in the manifest."""
from ..core.file_utils import detect_category, human_size
from ..core.hashing import compute_hashes
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class FileManifestEntry:
    """Forensic manifest entry for a single file."""

    # Identity
    relative_path: str
    filename: str
    extension: str

    # Hashes
    md5: str = ""
    sha256: str = ""
    sha512: str = ""

    # Metadata
    size_bytes: int = 0
    mime_type: str = ""
    is_binary: bool = False
    is_symlink: bool = False
    symlink_target: str = ""
    permissions: str = ""

    # Timestamps (ISO 8601)
    created_at: str = ""
    modified_at: str = ""
    accessed_at: str = ""

    # Classification
    classification: str = (
        "unknown"  # known_redcap, external_module, config, unknown, orphan
    )
    category: str = ""  # code, markup, config, data, binary, doc
    language: str = ""

    # Entropy
    entropy: float = 0.0
    entropy_assessment: str = ""  # normal, elevated, suspicious

    # AI content-type detection (Google Magika)
    magika_label: str = ""  # What the file ACTUALLY is (e.g. "php", "sqlite")
    magika_group: str = ""  # Content group (e.g. "code", "document")
    magika_mime_type: str = ""  # True MIME type from content analysis
    magika_score: float = 0.0  # Confidence 0.0–1.0
    content_type_mismatch: bool = False  # Extension disagrees with content

    # Anomaly flags
    anomalies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceManifest:
    """Complete forensic manifest for an evidence source."""

    # Manifest metadata
    manifest_version: str = "1.0.0"
    created_at: str = ""
    tool_version: str = VERSION

    # Source info
    source_uri: str = ""
    source_label: str = ""
    root_path: str = ""

    # Summary counts
    total_files: int = 0
    total_directories: int = 0
    total_size_bytes: int = 0

    # Breakdowns
    files_by_extension: dict[str, int] = field(default_factory=dict)
    files_by_classification: dict[str, int] = field(default_factory=dict)
    files_by_category: dict[str, int] = field(default_factory=dict)

    # Anomaly summary
    total_anomalies: int = 0
    anomalies_by_type: dict[str, int] = field(default_factory=dict)

    # All file entries
    entries: list[FileManifestEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def save(self, output_path: Path) -> None:
        """Save manifest to JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        logger.info(f"Manifest saved: {output_path} ({self.total_files} files)")


# Language detection by extension (canonical — core.constants)
LANGUAGE_MAP: dict[str, str] = get_language_map()

# Category detection (canonical — core.constants)
CATEGORY_MAP: dict[str, frozenset[str]] = get_category_map()

# ---------------------------------------------------------------------------
# Anomaly-detection constants — re-exported from dedicated module
# ---------------------------------------------------------------------------
from .anomaly_detector import (  # noqa: E402
    ANOMALOUS_EXTENSIONS,
    ANOMALOUS_FILES,
    SQLITE_SIDECAR_EXTENSIONS,
    SUSPICIOUS_FILENAMES,
    AnomalyDetector,
)


class ManifestBuilder:
    """Builds an evidence manifest from a directory tree."""

    def __init__(
        self,
        hash_algorithms: list[str] | None = None,
        *,
        magika: Any | None = None,
        anomaly_detector: AnomalyDetector | None = None,
    ):
        self.hash_algorithms = hash_algorithms or ["md5", "sha256", "sha512"]
        if magika is not None:
            self._magika = magika
        else:
            from ..forensics.magika_analyzer import MagikaAnalyzer

            self._magika = (
                MagikaAnalyzer()
            )  # raises ImportError / RuntimeError on failure
        self._anomaly_detector = anomaly_detector or AnomalyDetector()

    def build(
        self,
        root: Path,
        label: str = "",
        source_uri: str = "",
    ) -> EvidenceManifest:
        """
        Walk the directory tree and build a complete manifest.

        Args:
            root: Root directory to scan
            label: Human-readable label for this evidence package
            source_uri: Original source URI (ZIP path, URL, etc.)

        Returns:
            EvidenceManifest with all file entries and anomaly flags
        """
        manifest = EvidenceManifest(
            created_at=datetime.now(timezone.utc).isoformat(),
            source_uri=source_uri or str(root),
            source_label=label,
            root_path=str(root),
        )

        ext_counts: Counter[str] = Counter()
        class_counts: Counter[str] = Counter()
        cat_counts: Counter[str] = Counter()
        anomaly_counts: Counter[str] = Counter()
        dir_count = 0

        for item in sorted(root.rglob("*")):
            if item.is_dir():
                dir_count += 1
                # Check for anomalous directories
                if item.name == ".git":
                    anomaly_counts["git_directory_in_webroot"] += 1
                continue

            if not item.is_file() and not item.is_symlink():
                continue

            entry = self._build_entry(item, root)
            manifest.entries.append(entry)

            ext_counts[entry.extension or "(none)"] += 1
            class_counts[entry.classification] += 1
            cat_counts[entry.category or "unknown"] += 1
            manifest.total_size_bytes += entry.size_bytes

            for anomaly in entry.anomalies:
                anomaly_counts[anomaly] += 1

        manifest.total_files = len(manifest.entries)
        manifest.total_directories = dir_count
        manifest.files_by_extension = dict(ext_counts.most_common())
        manifest.files_by_classification = dict(class_counts.most_common())
        manifest.files_by_category = dict(cat_counts.most_common())
        manifest.total_anomalies = sum(anomaly_counts.values())
        manifest.anomalies_by_type = dict(anomaly_counts.most_common())

        logger.info(
            f"Manifest built: {manifest.total_files} files, "
            f"{manifest.total_anomalies} anomalies, "
            f"{self._human_size(manifest.total_size_bytes)}"
        )

        return manifest

    def _build_entry(self, file_path: Path, root: Path) -> FileManifestEntry:
        """Build a manifest entry for a single file."""
        try:
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path)

        entry = FileManifestEntry(
            relative_path=rel_path,
            filename=file_path.name,
            extension=file_path.suffix.lower(),
        )

        try:
            # Symlink detection
            if file_path.is_symlink():
                entry.is_symlink = True
                try:
                    target = os.readlink(file_path)
                    entry.symlink_target = str(target)
                    # Anomaly: symlink pointing outside the root
                    try:
                        resolved = file_path.resolve()
                        if not str(resolved).startswith(str(root.resolve())):
                            entry.anomalies.append("symlink_escapes_root")
                    except (OSError, ValueError):
                        entry.anomalies.append("symlink_unresolvable")
                except OSError:
                    entry.symlink_target = "(unreadable)"
                    entry.anomalies.append("symlink_unreadable")

            # File stats
            st = file_path.stat()
            entry.size_bytes = st.st_size
            entry.permissions = stat.filemode(st.st_mode)

            # Timestamps
            entry.created_at = datetime.fromtimestamp(
                st.st_ctime, tz=timezone.utc
            ).isoformat()
            entry.modified_at = datetime.fromtimestamp(
                st.st_mtime, tz=timezone.utc
            ).isoformat()
            entry.accessed_at = datetime.fromtimestamp(
                st.st_atime, tz=timezone.utc
            ).isoformat()

            # MIME type
            mime, _ = mimetypes.guess_type(file_path.name)
            entry.mime_type = mime or "application/octet-stream"

            # Classification
            entry.language = LANGUAGE_MAP.get(entry.extension, "")
            entry.category = self._detect_category(entry.extension)
            entry.is_binary = (
                entry.category == "binary"
                or entry.extension in CATEGORY_MAP.get("binary", set())
            )

            # Hashes (skip for very large binaries)
            if entry.size_bytes <= 100_000_000:  # 100MB limit
                self._compute_hashes(file_path, entry)

            # Entropy (text files only, <10MB)
            if not entry.is_binary and entry.size_bytes <= 10_000_000:
                self._compute_entropy(file_path, entry)

            # Anomaly detection
            self._detect_anomalies(entry, file_path, root)

            # AI content-type detection (Magika)
            self._run_magika(entry, file_path)

        except PermissionError:
            entry.anomalies.append("permission_denied")
        except OSError as e:
            entry.anomalies.append(f"os_error:{e.errno}")

        return entry

    def _compute_hashes(self, file_path: Path, entry: FileManifestEntry) -> None:
        """Compute cryptographic hashes for a file.

        Delegates to :func:`core.hashing.compute_hashes` (canonical
        implementation, DUP-001).  Preserves original error-handling
        semantics: hashes left as ``""`` on I/O failure.
        """
        try:
            digests = compute_hashes(file_path, algorithms=self.hash_algorithms)
            if "md5" in digests:
                entry.md5 = digests["md5"]
            if "sha256" in digests:
                entry.sha256 = digests["sha256"]
            if "sha512" in digests:
                entry.sha512 = digests["sha512"]
        except (OSError, PermissionError) as e:
            logger.warning(f"Hash computation failed for {file_path}: {e}")

    def _compute_entropy(self, file_path: Path, entry: FileManifestEntry) -> None:
        """Compute Shannon entropy for text files."""
        try:
            content = file_path.read_bytes()
            if len(content) < 50:
                return

            counts = Counter(content)
            total = len(content)
            entropy = 0.0
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * math.log2(p)

            entry.entropy = round(entropy, 4)

            if entropy > _SUSPICIOUS_ENTROPY:
                entry.entropy_assessment = "suspicious"
            elif entropy > _ELEVATED_ENTROPY:
                entry.entropy_assessment = "elevated"
            else:
                entry.entropy_assessment = "normal"
        except (OSError, PermissionError):
            pass

    def _detect_anomalies(
        self, entry: FileManifestEntry, file_path: Path, root: Path
    ) -> None:
        """Detect filesystem anomalies that indicate potential compromise.

        Delegates to :class:`~evidence.anomaly_detector.AnomalyDetector`
        which implements the 14 anomaly checks as a pluggable Strategy.
        """
        self._anomaly_detector.detect(entry, file_path, root)

    def _run_magika(self, entry: FileManifestEntry, file_path: Path) -> None:
        """Run Magika AI content-type detection and flag mismatches.

        Raises on Magika failure — no silent degradation.
        """
        from ..forensics.magika_analyzer import (
            ANOMALY_ACTIVE_CONTENT_HIDDEN,
            ANOMALY_CONTENT_TYPE_MISMATCH_CRITICAL,
            ANOMALY_CONTENT_TYPE_MISMATCH_SUSPICIOUS,
            ANOMALY_PHP_DISGUISED,
            ANOMALY_SQLITE_DISGUISED,
        )

        result = self._magika.identify(file_path)
        if not result.label:
            raise RuntimeError(
                f"Magika returned empty label for '{file_path}' — "
                f"content-type detection incomplete"
            )

        entry.magika_label = result.label
        entry.magika_group = result.group
        entry.magika_mime_type = result.mime_type
        entry.magika_score = result.score
        entry.content_type_mismatch = not result.content_type_match

        if not result.content_type_match:
            sev = result.mismatch_severity
            if sev == "critical":
                entry.anomalies.append(ANOMALY_CONTENT_TYPE_MISMATCH_CRITICAL)
            elif sev == "suspicious":
                entry.anomalies.append(ANOMALY_CONTENT_TYPE_MISMATCH_SUSPICIOUS)

            # Specific anomaly subtypes
            if result.label == "php" and entry.extension not in (
                ".php",
                ".inc",
                ".phtml",
                ".php5",
                ".php7",
                ".module",
            ):
                entry.anomalies.append(ANOMALY_PHP_DISGUISED)
            elif result.label == "sqlite" and entry.extension not in (
                ".db",
                ".sqlite",
                ".sqlite3",
            ):
                entry.anomalies.append(ANOMALY_SQLITE_DISGUISED)
            elif result.label in {
                "python",
                "perl",
                "ruby",
                "shell",
                "batch",
                "powershell",
            }:
                entry.anomalies.append(ANOMALY_ACTIVE_CONTENT_HIDDEN)

    def _detect_category(self, ext: str) -> str:
        """Detect file category from extension."""
        return detect_category(ext, default="unknown")

    @staticmethod
    def _human_size(size: int) -> str:
        """Convert bytes to human-readable size."""
        return human_size(size)
