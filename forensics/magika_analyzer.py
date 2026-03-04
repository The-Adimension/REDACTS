"""
REDACTS Magika Analyzer — AI-powered content-type detection.

Uses Google's Magika deep-learning model to detect what a file ACTUALLY
contains, regardless of its extension.  This catches the evasion
techniques that INFINITERED (and similar campaigns) rely on:

    1. File-type masquerading — PHP hidden as .jpg, .css, .txt, .dat
    2. SQLite drops with camouflaged names — cache.tmp, session.dat
    3. Polyglot files — content valid as two types simultaneously
    4. Binary payloads disguised as text (or vice-versa)
    5. Extension-less or mis-extended malware drops

Traditional detection relies on extension → MIME mappings
(``mimetypes.guess_type``) or shallow byte-sniffing.  Magika instead
runs a ~2 MB deep-learning model that was trained on ~100 M samples
across 200+ content types.  It achieves ~99 % accuracy and returns a
prediction in single-digit milliseconds on CPU alone.

Magika is a **mandatory** dependency.  All failures are raised — there
is NO silent degradation.  If Magika is not installed or fails to load,
REDACTS will error out immediately rather than run with reduced detection.

Integration points
------------------
* ``evidence.manifest.ManifestBuilder``  — Tier 1 (every file is typed)
* ``forensics.file_analyzer.FileAnalyzer`` — Tier 2 profiling
* ``investigation.investigator.Investigator`` — mismatch findings
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy-loaded Magika instance (model weights loaded once)
# ---------------------------------------------------------------------------
_magika_instance: Any = None
_magika_loaded: bool = False


def _get_magika() -> Any:
    """Return a shared ``magika.Magika`` instance.

    Raises
    ------
    ImportError
        If the ``magika`` package is not installed.
    RuntimeError
        If the Magika model fails to initialise.
    """
    global _magika_instance, _magika_loaded
    if _magika_loaded:
        return _magika_instance
    try:
        from magika import Magika  # type: ignore[import-untyped]
    except ImportError:
        raise ImportError(
            "REQUIRED dependency 'magika' is not installed. "
            "Install it with: pip install 'magika>=0.6.0'  — "
            "REDACTS cannot run without AI content-type detection."
        )
    try:
        _magika_instance = Magika()
    except Exception as exc:
        raise RuntimeError(
            f"Magika model failed to initialise: {exc}  — "
            f"REDACTS cannot run without AI content-type detection."
        ) from exc
    _magika_loaded = True
    logger.info("Magika model loaded — AI content-type detection enabled")
    return _magika_instance


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class MagikaResult:
    """Content-type result produced by Magika for a single file."""

    # What Magika says the file IS
    label: str = ""  # e.g. "php", "sqlite", "javascript"
    description: str = ""  # e.g. "PHP source"
    mime_type: str = ""  # e.g. "text/x-php"
    group: str = ""  # e.g. "code", "executable", "document"
    is_text: bool = True
    score: float = 0.0  # Confidence 0.0–1.0

    # Forensic mismatch analysis
    extension_label: str = ""  # What the extension SAYS it should be
    content_type_match: bool = True  # Does content agree with extension?
    mismatch_severity: str = "none"  # "none", "info", "suspicious", "critical"
    mismatch_detail: str = ""  # Human-readable explanation

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


# ---------------------------------------------------------------------------
# Extension → expected Magika label mapping
# ---------------------------------------------------------------------------
# This map tells us what Magika SHOULD report for each extension.
# If the actual label is different, we have a mismatch.

EXTENSION_EXPECTED_LABELS: dict[str, set[str]] = {
    # PHP ecosystem
    ".php": {"php"},
    ".inc": {"php"},
    ".phtml": {"php"},
    ".php5": {"php"},
    ".php7": {"php"},
    ".module": {"php"},
    # Web
    ".html": {"html"},
    ".htm": {"html"},
    ".css": {"css"},
    ".js": {"javascript"},
    ".json": {"json"},
    ".xml": {"xml"},
    ".svg": {"svg", "xml"},
    # Images
    ".jpg": {"jpeg"},
    ".jpeg": {"jpeg"},
    ".png": {"png"},
    ".gif": {"gif"},
    ".bmp": {"bmp"},
    ".ico": {"ico"},
    ".webp": {"webp"},
    # Documents
    ".pdf": {"pdf"},
    ".md": {"markdown"},
    ".txt": {"txt", "empty", "unknown"},
    ".csv": {"csv"},
    ".ini": {"ini"},
    ".conf": {"ini", "txt", "unknown"},
    # Data
    ".sql": {"sql"},
    ".yml": {"yaml"},
    ".yaml": {"yaml"},
    # Archives
    ".zip": {"zip"},
    ".gz": {"gzip"},
    ".tar": {"tar"},
    ".7z": {"sevenzip"},
    ".rar": {"rar"},
    # Executables / libraries
    ".exe": {"pebin"},
    ".dll": {"pebin"},
    ".so": {"elf"},
    ".phar": {"php", "zip"},  # PHAR can look like PHP or ZIP
    # Databases (REDACTS-critical — INFINITERED drops SQLite files)
    ".db": {"sqlite"},
    ".sqlite": {"sqlite"},
    ".sqlite3": {"sqlite"},
    # Fonts
    ".woff": {"woff"},
    ".woff2": {"woff2"},
    ".ttf": {"ttf"},
    ".eot": {"eot"},
    ".otf": {"otf"},
    # Shell
    ".sh": {"shell"},
    ".bat": {"batch"},
}

# Labels that are ALWAYS suspicious if they appear where they shouldn't
# regardless of extension.  These represent executable/active content.
ACTIVE_CONTENT_LABELS: set[str] = {
    "php",
    "python",
    "perl",
    "ruby",
    "shell",
    "batch",
    "powershell",
    "javascript",
    "vba",
}

# Labels for database formats — finding one under a non-DB extension
# is a strong signal for data exfiltration à la INFINITERED.
DATABASE_LABELS: set[str] = {"sqlite", "mysql"}


# ---------------------------------------------------------------------------
# Mismatch severity rules
# ---------------------------------------------------------------------------

# (expected_group, actual_label)  →  severity
# These override the generic logic for specific attack-relevant pairings.
_CRITICAL_MISMATCHES: dict[tuple[str, str], str] = {
    # Image hiding code — polyglot attacks
    ("jpeg", "php"): "critical",
    ("png", "php"): "critical",
    ("gif", "php"): "critical",
    ("bmp", "php"): "critical",
    ("ico", "php"): "critical",
    ("webp", "php"): "critical",
    # Style/markup hiding code
    ("css", "php"): "critical",
    ("javascript", "php"): "critical",  # .js hiding PHP
    ("html", "php"): "suspicious",  # Can be legit (embedded PHP)
    # Anything hiding SQLite (INFINITERED exfiltration)
    ("php", "sqlite"): "critical",
    ("txt", "sqlite"): "critical",
    ("ini", "sqlite"): "critical",
    ("javascript", "sqlite"): "critical",
    ("css", "sqlite"): "critical",
    ("html", "sqlite"): "critical",
    ("jpeg", "sqlite"): "critical",
    ("png", "sqlite"): "critical",
    ("gif", "sqlite"): "critical",
    # Text files hiding executables
    ("txt", "php"): "critical",
    ("txt", "python"): "suspicious",
    ("txt", "perl"): "suspicious",
    ("txt", "shell"): "suspicious",
    # Log files hiding code
    ("txt", "php"): "critical",
    # Data/config hiding executable code
    ("json", "php"): "critical",
    ("yaml", "php"): "critical",
    ("ini", "php"): "critical",
    ("xml", "php"): "critical",
    ("csv", "php"): "critical",
    ("sql", "php"): "critical",
}


def _classify_mismatch(
    ext_label: str,
    actual_label: str,
    actual_group: str,
    score: float,
) -> tuple[str, str]:
    """
    Determine severity and detail string for a content-type mismatch.

    Returns:
        (severity, detail)  where severity ∈ {"none","info","suspicious","critical"}
    """
    if not ext_label or not actual_label:
        return "none", ""

    # Direct lookup in critical/suspicious mismatch table
    key = (ext_label, actual_label)
    if key in _CRITICAL_MISMATCHES:
        severity = _CRITICAL_MISMATCHES[key]
        detail = (
            f"Extension implies '{ext_label}' but content is '{actual_label}' "
            f"(confidence {score:.0%}) — {severity.upper()} content-type masquerading"
        )
        return severity, detail

    # Generic: active code hiding as non-code → suspicious
    if actual_label in ACTIVE_CONTENT_LABELS:
        detail = (
            f"Active content '{actual_label}' found in file expected to be "
            f"'{ext_label}' — possible code injection"
        )
        return "suspicious", detail

    # Generic: database hiding as non-database → suspicious
    if actual_label in DATABASE_LABELS:
        detail = (
            f"Database content '{actual_label}' found in file expected to be "
            f"'{ext_label}' — possible data exfiltration"
        )
        return "suspicious", detail

    # Low-confidence mismatch → informational
    if score < 0.5:
        return "info", f"Low-confidence type mismatch: expected '{ext_label}', got '{actual_label}' ({score:.0%})"

    # High-confidence but not in critical table → suspicious by default
    detail = (
        f"Content-type mismatch: extension says '{ext_label}', "
        f"Magika says '{actual_label}' ({score:.0%})"
    )
    return "suspicious", detail


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class MagikaAnalyzer:
    """
    Wrapper around Google Magika for forensic content-type detection.

    Usage::

        analyzer = MagikaAnalyzer()
        result = analyzer.identify(Path("suspect.jpg"))
        if not result.content_type_match:
            print(f"MISMATCH: {result.mismatch_detail}")

    Raises ``ImportError`` if ``magika`` is not installed and
    ``RuntimeError`` if the model fails to load.  There is no
    graceful degradation — Magika is mandatory.
    """

    def __init__(self) -> None:
        self._magika = _get_magika()  # raises on failure

    def identify(self, file_path: Path) -> MagikaResult:
        """
        Identify the true content type of *file_path*.

        Returns a ``MagikaResult`` with mismatch analysis.

        Raises
        ------
        RuntimeError
            If Magika fails to identify the file.
        """
        result = MagikaResult()

        try:
            raw = self._magika.identify_path(file_path)
            output = raw.output  # MagikaOutput

            result.label = output.label
            result.description = output.description
            result.mime_type = output.mime_type
            result.group = output.group
            result.is_text = output.is_text
            result.score = getattr(raw, "score", 0.0)
            # Some versions expose score via raw.result.value.score
            if result.score == 0.0:
                try:
                    result.score = raw.result.value.score  # type: ignore[union-attr]
                except (AttributeError, TypeError):
                    result.score = 1.0  # If score unavailable, assume confident

        except Exception as exc:
            raise RuntimeError(
                f"Magika failed to identify '{file_path}': {exc}"
            ) from exc

        # --- Mismatch analysis ---
        ext = file_path.suffix.lower()
        expected = EXTENSION_EXPECTED_LABELS.get(ext)
        if expected is not None:
            result.extension_label = next(iter(expected))  # primary label
            if result.label not in expected:
                result.content_type_match = False
                result.mismatch_severity, result.mismatch_detail = (
                    _classify_mismatch(
                        result.extension_label,
                        result.label,
                        result.group,
                        result.score,
                    )
                )
        elif ext:
            # Unknown extension — can't compare, but flag if active content
            ext_clean = ext.lstrip(".")
            result.extension_label = ext_clean
            if result.label in ACTIVE_CONTENT_LABELS | DATABASE_LABELS:
                result.content_type_match = False
                result.mismatch_severity = "suspicious"
                result.mismatch_detail = (
                    f"File with uncommon extension '{ext}' contains "
                    f"'{result.label}' content — review required"
                )
        else:
            # No extension at all
            if result.label in ACTIVE_CONTENT_LABELS | DATABASE_LABELS:
                result.content_type_match = False
                result.mismatch_severity = "suspicious"
                result.mismatch_detail = (
                    f"Extension-less file contains '{result.label}' content"
                )

        return result

    def identify_bytes(self, data: bytes) -> MagikaResult:
        """
        Identify content type from raw bytes.

        Useful for scanning file contents already in memory (e.g. from
        a ZIP or network stream).

        Raises
        ------
        RuntimeError
            If Magika fails to identify the bytes.
        """
        result = MagikaResult()

        try:
            raw = self._magika.identify_bytes(data)
            output = raw.output
            result.label = output.label
            result.description = output.description
            result.mime_type = output.mime_type
            result.group = output.group
            result.is_text = output.is_text
            result.score = getattr(raw, "score", 1.0)
        except Exception as exc:
            raise RuntimeError(
                f"Magika identify_bytes failed: {exc}"
            ) from exc

        return result

    def scan_directory(
        self,
        root: Path,
        *,
        skip_extensions: set[str] | None = None,
        progress_callback: Optional[Any] = None,
    ) -> list[MagikaResult]:
        """
        Scan all files under *root* and return results with mismatches.

        Args:
            root: Directory to scan recursively
            skip_extensions: Extensions to skip (e.g. {".woff", ".ttf"})
            progress_callback: Optional ``(scanned, total)`` callback

        Returns:
            List of ``MagikaResult`` for files with mismatches only.
        """
        skip = skip_extensions or set()
        files = [f for f in sorted(root.rglob("*")) if f.is_file() and f.suffix.lower() not in skip]
        total = len(files)
        mismatches: list[MagikaResult] = []

        for idx, fpath in enumerate(files, 1):
            result = self.identify(fpath)
            if not result.content_type_match:
                mismatches.append(result)
            if progress_callback and idx % 100 == 0:
                try:
                    progress_callback(idx, total)
                except Exception:
                    pass

        logger.info(
            "Magika scan complete: %d / %d files have content-type mismatches",
            len(mismatches),
            total,
        )
        return mismatches


# ---------------------------------------------------------------------------
# Anomaly names used in manifest.py when Magika detects issues
# ---------------------------------------------------------------------------
# These constants are referenced by ManifestBuilder._detect_anomalies()
# to stay consistent with the anomaly flag vocabulary.

ANOMALY_CONTENT_TYPE_MISMATCH_CRITICAL = "content_type_mismatch_critical"
ANOMALY_CONTENT_TYPE_MISMATCH_SUSPICIOUS = "content_type_mismatch_suspicious"
ANOMALY_SQLITE_DISGUISED = "sqlite_content_in_non_db_file"
ANOMALY_PHP_DISGUISED = "php_content_in_non_php_file"
ANOMALY_ACTIVE_CONTENT_HIDDEN = "active_content_in_non_code_file"
