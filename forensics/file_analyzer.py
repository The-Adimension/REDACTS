"""
REDACTS File Analyzer - File-level analysis.

Produces per-file profiles:
    - Cryptographic hashes (MD5, SHA-256, SHA-512)
    - File size, permissions, timestamps
    - MIME type and encoding detection
    - Binary vs text classification
    - Line/character/word/token counts
    - Entropy analysis (detect packed/encrypted content)
"""

from __future__ import annotations

import logging
import math
import mimetypes
import os
import stat
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from ..core import AnalysisConfig
from ..core.constants import (
    BINARY_DETECTION_THRESHOLD,
    DEFAULT_ENTROPY_THRESHOLD,
    ELEVATED_ENTROPY_THRESHOLD,
    get_category_map,
    get_language_map,
    get_skip_dirs,
)
from ..core.file_utils import detect_category, human_size
from ..core.hashing import compute_hashes

logger = logging.getLogger(__name__)


@dataclass
class FileProfile:
    """Profile of a single file."""

    path: str  # Relative path from root
    absolute_path: str  # Absolute path
    filename: str  # Just the filename
    extension: str  # File extension
    size_bytes: int = 0  # File size
    size_human: str = ""  # Human-readable size

    # Hashes
    md5: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None

    # File metadata
    mime_type: str = ""
    encoding: str = ""
    is_binary: bool = False
    is_symlink: bool = False
    permissions: str = ""
    created_at: str = ""
    modified_at: str = ""
    accessed_at: str = ""

    # Content metrics (text files only)
    line_count: int = 0
    blank_lines: int = 0
    comment_lines: int = 0
    code_lines: int = 0
    char_count: int = 0
    word_count: int = 0
    max_line_length: int = 0
    avg_line_length: float = 0.0

    # Entropy analysis
    entropy: float = 0.0  # Shannon entropy (0-8 for bytes)
    entropy_assessment: str = ""  # "normal", "high", "suspicious"

    # AI content-type detection (Google Magika)
    magika_label: str = ""  # What the file ACTUALLY is
    magika_group: str = ""  # Content group
    magika_mime_type: str = ""  # True MIME from content analysis
    magika_score: float = 0.0  # Confidence 0.0–1.0
    content_type_mismatch: bool = False  # Extension contradicts content
    content_type_mismatch_detail: str = ""  # Explanation

    # Classification
    category: str = ""  # "code", "config", "data", "binary", "doc"
    language: str = ""  # Detected language

    # Error
    error: Optional[str] = None


@dataclass
class DirectoryProfile:
    """Profile of an entire directory tree."""

    root_path: str
    total_files: int = 0
    total_dirs: int = 0
    total_size_bytes: int = 0
    total_size_human: str = ""
    total_lines: int = 0
    total_code_lines: int = 0
    total_blank_lines: int = 0
    total_comment_lines: int = 0

    # Breakdowns
    files_by_extension: dict[str, int] = field(default_factory=dict)
    files_by_category: dict[str, int] = field(default_factory=dict)
    size_by_extension: dict[str, int] = field(default_factory=dict)
    lines_by_extension: dict[str, int] = field(default_factory=dict)

    # Top files
    largest_files: list[dict] = field(default_factory=list)
    highest_entropy: list[dict] = field(default_factory=list)

    # All file profiles
    files: list[FileProfile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict (excluding full file profiles for summary)."""
        from dataclasses import asdict

        d = asdict(self)
        d["files"] = [asdict(f) for f in self.files]
        return d


class FileAnalyzer:
    """Analyze files."""

    # Comment markers by language
    COMMENT_MARKERS = {
        ".php": ("//", "/*", "*/", "#"),
        ".js": ("//", "/*", "*/"),
        ".css": ("/*", "*/"),
        ".py": ("#",),
        ".sh": ("#",),
        ".bat": ("REM", "::"),
        ".sql": ("--", "/*", "*/"),
        ".html": ("<!--", "-->"),
        ".xml": ("<!--", "-->"),
        ".yml": ("#",),
        ".yaml": ("#",),
        ".ini": (";", "#"),
        ".conf": ("#",),
    }

    # Language detection by extension (canonical — core.constants)
    LANGUAGE_MAP = get_language_map()

    # Category detection (canonical — core.constants)
    CATEGORY_MAP = get_category_map()

    def __init__(
        self,
        config: Optional[AnalysisConfig] = None,
        *,
        magika: Any | None = None,
    ):
        self.config = config or AnalysisConfig()
        if magika is not None:
            self._magika = magika
        else:
            from .magika_analyzer import MagikaAnalyzer

            self._magika = (
                MagikaAnalyzer()
            )  # raises ImportError / RuntimeError on failure

    def analyze_file(self, file_path: Path, root: Path) -> FileProfile:
        """
        Create profile of a single file.

        Args:
            file_path: Absolute path to the file
            root: Root directory for relative path computation
        """
        try:
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path)

        profile = FileProfile(
            path=rel_path,
            absolute_path=str(file_path),
            filename=file_path.name,
            extension=file_path.suffix.lower(),
        )

        try:
            # File metadata
            st = file_path.stat()
            profile.size_bytes = st.st_size
            profile.size_human = self._human_size(st.st_size)
            profile.is_symlink = file_path.is_symlink()
            profile.permissions = stat.filemode(st.st_mode)
            profile.modified_at = datetime.fromtimestamp(st.st_mtime).isoformat()
            profile.accessed_at = datetime.fromtimestamp(st.st_atime).isoformat()
            try:
                profile.created_at = datetime.fromtimestamp(st.st_ctime).isoformat()
            except (OSError, AttributeError):
                pass

            # Skip oversized files
            if st.st_size > self.config.max_file_size_mb * 1_000_000:
                profile.error = f"Skipped: file too large ({profile.size_human})"
                profile.is_binary = True
                return profile

            # MIME type
            mime, _ = mimetypes.guess_type(str(file_path))
            profile.mime_type = mime or "application/octet-stream"

            # Detect binary
            profile.is_binary = self._is_binary(file_path, profile.extension)

            # Language and category
            profile.language = self.LANGUAGE_MAP.get(profile.extension, "")
            profile.category = self._detect_category(profile.extension)

            # Hashes
            hashes = self._compute_hashes(file_path)
            profile.md5 = hashes.get("md5")
            profile.sha256 = hashes.get("sha256")
            profile.sha512 = hashes.get("sha512")

            # Entropy
            profile.entropy = self._compute_entropy(file_path)
            if profile.entropy > DEFAULT_ENTROPY_THRESHOLD:
                profile.entropy_assessment = "suspicious"
            elif profile.entropy > ELEVATED_ENTROPY_THRESHOLD:
                profile.entropy_assessment = "high"
            else:
                profile.entropy_assessment = "normal"

            # Content analysis for text files
            if not profile.is_binary:
                self._analyze_content(file_path, profile)

            # AI content-type detection (Magika)
            mr = self._magika.identify(file_path)
            if not mr.label:
                raise RuntimeError(
                    f"Magika returned empty label for '{file_path}' — "
                    f"content-type detection incomplete"
                )
            profile.magika_label = mr.label
            profile.magika_group = mr.group
            profile.magika_mime_type = mr.mime_type
            profile.magika_score = mr.score
            profile.content_type_mismatch = not mr.content_type_match
            profile.content_type_mismatch_detail = mr.mismatch_detail

        except PermissionError:
            profile.error = "Permission denied"
        except OSError as e:
            profile.error = f"OS error: {e}"

        return profile

    def analyze_directory(self, root: Path) -> DirectoryProfile:
        """
        Create profile of a directory tree.

        Args:
            root: Root directory to analyze
        """
        root = root.resolve()
        profile = DirectoryProfile(root_path=str(root))

        ext_counts: Counter = Counter()
        ext_sizes: Counter = Counter()
        ext_lines: Counter = Counter()
        cat_counts: Counter = Counter()

        _skip = get_skip_dirs()
        for dirpath, dirnames, filenames in os.walk(root):
            # Filter out ignored directories (canonical set + dot-dirs)
            dirnames[:] = [
                d for d in dirnames if d not in _skip and not d.startswith(".")
            ]
            profile.total_dirs += 1

            for filename in filenames:
                file_path = Path(dirpath) / filename

                # Skip binary extensions for speed
                ext = file_path.suffix.lower()
                if ext in self.config.binary_extensions:
                    # Still count it but don't deep-analyze
                    profile.total_files += 1
                    try:
                        size = file_path.stat().st_size
                        profile.total_size_bytes += size
                        ext_counts[ext] += 1
                        ext_sizes[ext] += size
                        cat_counts["binary"] += 1
                    except OSError:
                        pass
                    continue

                file_profile = self.analyze_file(file_path, root)
                profile.files.append(file_profile)
                profile.total_files += 1
                profile.total_size_bytes += file_profile.size_bytes
                profile.total_lines += file_profile.line_count
                profile.total_code_lines += file_profile.code_lines
                profile.total_blank_lines += file_profile.blank_lines
                profile.total_comment_lines += file_profile.comment_lines

                ext_counts[ext] += 1
                ext_sizes[ext] += file_profile.size_bytes
                ext_lines[ext] += file_profile.line_count
                cat_counts[file_profile.category] += 1

        profile.total_size_human = self._human_size(profile.total_size_bytes)
        profile.files_by_extension = dict(ext_counts.most_common())
        profile.size_by_extension = dict(ext_sizes.most_common())
        profile.lines_by_extension = dict(ext_lines.most_common())
        profile.files_by_category = dict(cat_counts.most_common())

        # Top 20 largest files
        sorted_by_size = sorted(profile.files, key=lambda f: f.size_bytes, reverse=True)
        profile.largest_files = [
            {"path": f.path, "size": f.size_human, "bytes": f.size_bytes}
            for f in sorted_by_size[:20]
        ]

        # Top 20 highest entropy
        sorted_by_entropy = sorted(
            [f for f in profile.files if f.entropy > 0],
            key=lambda f: f.entropy,
            reverse=True,
        )
        profile.highest_entropy = [
            {
                "path": f.path,
                "entropy": round(f.entropy, 3),
                "assessment": f.entropy_assessment,
            }
            for f in sorted_by_entropy[:20]
        ]

        return profile

    def _compute_hashes(self, file_path: Path) -> dict[str, str]:
        """Compute MD5, SHA-256, SHA-512 hashes.

        Delegates to :func:`core.hashing.compute_hashes` (canonical
        implementation, DUP-001).
        """
        return compute_hashes(file_path)

    def _compute_entropy(self, file_path: Path) -> float:
        """Compute Shannon entropy (0-8 for byte-level)."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(1_000_000)  # First 1MB
            if not data:
                return 0.0

            counts = Counter(data)
            total = len(data)
            entropy = 0.0
            for count in counts.values():
                p = count / total
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy
        except OSError:
            return 0.0

    def _is_binary(self, file_path: Path, extension: str) -> bool:
        """Detect if file is binary."""
        if extension in self.config.binary_extensions:
            return True
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(8192)
            # Check for null bytes
            if b"\x00" in chunk:
                return True
            # Check ratio of non-text bytes
            text_chars = set(range(32, 127)) | {9, 10, 13}  # printable + tab, LF, CR
            non_text = sum(1 for b in chunk if b not in text_chars)
            return (non_text / max(len(chunk), 1)) > BINARY_DETECTION_THRESHOLD
        except OSError:
            return True

    def _analyze_content(self, file_path: Path, profile: FileProfile) -> None:
        """Analyze text file content: lines, chars, words, comments."""
        try:
            encoding = self._detect_encoding(file_path)
            profile.encoding = encoding

            with open(file_path, "r", encoding=encoding, errors="replace") as f:
                lines = f.readlines()

            profile.line_count = len(lines)
            profile.char_count = sum(len(line) for line in lines)
            profile.word_count = sum(len(line.split()) for line in lines)

            line_lengths = [len(line.rstrip()) for line in lines]
            profile.max_line_length = max(line_lengths) if line_lengths else 0
            profile.avg_line_length = (
                sum(line_lengths) / len(line_lengths) if line_lengths else 0.0
            )

            # Count blank, comment, and code lines
            comment_markers = self.COMMENT_MARKERS.get(profile.extension, ())
            in_block_comment = False

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    profile.blank_lines += 1
                    continue

                # Block comment tracking
                if comment_markers:
                    if "/*" in comment_markers and "/*" in stripped:
                        in_block_comment = True
                    if in_block_comment:
                        profile.comment_lines += 1
                        if "*/" in stripped:
                            in_block_comment = False
                        continue
                    if "<!--" in comment_markers and "<!--" in stripped:
                        if "-->" not in stripped:
                            in_block_comment = True
                        profile.comment_lines += 1
                        continue

                    # Single-line comment
                    is_comment = False
                    for marker in comment_markers:
                        if marker in ("/*", "*/", "<!--", "-->"):
                            continue
                        if stripped.startswith(marker):
                            is_comment = True
                            break
                    if is_comment:
                        profile.comment_lines += 1
                        continue

                profile.code_lines += 1

        except (UnicodeDecodeError, OSError):
            pass

    def _detect_encoding(self, file_path: Path) -> str:
        """Detect file encoding."""
        try:
            import chardet

            with open(file_path, "rb") as f:
                raw = f.read(10000)
            result = chardet.detect(raw)
            return result.get("encoding", "utf-8") or "utf-8"
        except ImportError:
            return "utf-8"

    def _detect_category(self, extension: str) -> str:
        """Detect file category from extension."""
        return detect_category(extension, default="other")

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        """Convert bytes to human-readable string."""
        return human_size(size_bytes)
