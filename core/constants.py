"""Shared constants for REDACTS — single source of truth.

Replaces 9 families of duplicated literals scattered across the codebase
(DUP-003, DUP-004, DUP-009, DUP-010, DUP-011, DUP-012, DUP-013, HC-004,
HC-014) with one canonical module.

Design patterns
---------------
* **Registry** – mutable extension sets (:data:`SKIP_DIRS`,
  :data:`SCANNABLE_EXTENSIONS`) and maps (:data:`LANGUAGE_MAP`,
  :data:`CATEGORY_MAP`) store live data behind module-level dicts/sets.
  New entries can be added at runtime via :func:`register_language`,
  :func:`register_category_entries`, :func:`register_skip_dirs`, and
  :func:`register_scannable_extensions` without touching existing code.
* **Configuration-driven** – threshold constants (:data:`DEFAULT_ENTROPY_THRESHOLD`,
  :data:`ELEVATED_ENTROPY_THRESHOLD`, :data:`BINARY_DETECTION_THRESHOLD`)
  serve as canonical defaults for ``core.EvidenceConfig`` and
  ``core.AnalysisConfig`` dataclasses.
* **Immutable accessors** – public ``get_*`` helpers return *frozen*
  snapshots so callers cannot accidentally mutate the registry.

Backward-compatibility
----------------------
* Every constant value was extracted verbatim from its original site(s).
  Where two copies diverged the *superset* was taken so no existing
  consumer loses data (details noted inline).
* This file is purely additive (blast-radius **NONE**).  Consumers will be
  rewired in later steps.

Addresses
---------
DUP-003 (LANGUAGE_MAP ×2), DUP-004 (CATEGORY_MAP ×2), DUP-009
(SEVERITY_CVSS), DUP-010 (SEVERITY_ORDER ×2), DUP-011 (SKIP_DIRS ×13),
DUP-012 (SCANNABLE_EXTENSIONS ×3), DUP-013 (VERSION ×4), HC-004
(entropy thresholds ×4), HC-014 (binary-detection threshold).
"""

from __future__ import annotations

import logging
from typing import Iterable

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# DUP-013 — VERSION
# ═══════════════════════════════════════════════════════════════════════════
# __init__.__version__ and __main__.VERSION are "2.0.0".
# reporting/forensic_report._VERSION and sarif_exporter._TOOL_VERSION are
# still "1.0.0" (version drift).  Canonical truth follows the package.
VERSION: str = "2.0.0"

# ═══════════════════════════════════════════════════════════════════════════
# DUP-003 — LANGUAGE_MAP  (file-extension → human-readable language name)
# ═══════════════════════════════════════════════════════════════════════════
# Sources: forensics/file_analyzer.py L145 (class attr),
#          evidence/manifest.py L127 (module-level).
# Both copies are identical (23 entries).

_LANGUAGE_MAP: dict[str, str] = {
    ".php": "PHP",
    ".js": "JavaScript",
    ".css": "CSS",
    ".html": "HTML",
    ".htm": "HTML",
    ".xml": "XML",
    ".json": "JSON",
    ".sql": "SQL",
    ".py": "Python",
    ".sh": "Shell",
    ".bat": "Batch",
    ".yml": "YAML",
    ".yaml": "YAML",
    ".md": "Markdown",
    ".txt": "Text",
    ".csv": "CSV",
    ".ini": "INI",
    ".conf": "Config",
    ".htaccess": "Apache",
    ".twig": "Twig",
    ".tpl": "Template",
    ".inc": "PHP Include",
    ".module": "PHP Module",
}


def get_language_map() -> dict[str, str]:
    """Return *frozen* copy of the extension → language mapping."""
    return dict(_LANGUAGE_MAP)


def register_language(extension: str, language: str) -> None:
    """Add or overwrite an extension → language mapping at runtime.

    Parameters
    ----------
    extension:
        File extension including the leading dot (e.g. ``".ts"``).
    language:
        Human-readable language name (e.g. ``"TypeScript"``).

    Raises
    ------
    ValueError
        If *extension* does not start with ``"."``.
    """
    if not extension.startswith("."):
        raise ValueError(
            f"Extension must start with '.', got {extension!r}"
        )
    prev = _LANGUAGE_MAP.get(extension)
    _LANGUAGE_MAP[extension] = language
    if prev is None:
        logger.debug("Registered language mapping: %s → %s", extension, language)
    else:
        logger.debug(
            "Replaced language mapping: %s → %s (was %s)", extension, language, prev
        )


# ═══════════════════════════════════════════════════════════════════════════
# DUP-004 — CATEGORY_MAP  (category → set of extensions)
# ═══════════════════════════════════════════════════════════════════════════
# Sources: forensics/file_analyzer.py L172 (class attr),
#          evidence/manifest.py L154 (module-level).
#
# Divergences resolved by taking the SUPERSET of both copies:
#   "data"   — file_analyzer has ".sql"; manifest omits it  → KEPT
#   "config" — manifest has ".user.ini"; file_analyzer omits → KEPT
#   "doc"    — file_analyzer has ".pdf"; manifest omits it   → KEPT
#   "binary" — only in manifest                              → KEPT

_CATEGORY_MAP: dict[str, set[str]] = {
    "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
    "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
    "style": {".css", ".scss", ".less", ".sass"},
    "data": {".json", ".csv", ".yml", ".yaml", ".sql"},
    "config": {".ini", ".conf", ".htaccess", ".env", ".user.ini"},
    "doc": {".md", ".txt", ".rst", ".pdf"},
    "binary": {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
        ".zip", ".gz", ".tar", ".rar", ".7z",
        ".exe", ".dll", ".so", ".dylib", ".wasm",
        ".phar", ".db", ".sqlite", ".sqlite3",
    },
}


def get_category_map() -> dict[str, frozenset[str]]:
    """Return *frozen* copy of the category → extensions mapping."""
    return {k: frozenset(v) for k, v in _CATEGORY_MAP.items()}


def register_category_entries(
    category: str, extensions: Iterable[str]
) -> None:
    """Add *extensions* to *category*, creating the category if needed.

    Parameters
    ----------
    category:
        Category key (e.g. ``"code"``, ``"binary"``).
    extensions:
        One or more file extensions, each starting with ``"."``.

    Raises
    ------
    ValueError
        If any extension does not start with ``"."``.
    """
    exts = set(extensions)
    bad = [e for e in exts if not e.startswith(".")]
    if bad:
        raise ValueError(
            f"Extensions must start with '.', got {bad!r}"
        )
    if category in _CATEGORY_MAP:
        added = exts - _CATEGORY_MAP[category]
        _CATEGORY_MAP[category] |= exts
        if added:
            logger.debug(
                "Extended category %r with %s", category, sorted(added)
            )
    else:
        _CATEGORY_MAP[category] = exts
        logger.debug("Created category %r with %s", category, sorted(exts))


# ═══════════════════════════════════════════════════════════════════════════
# DUP-009 — SEVERITY_CVSS  (severity label → representative CVSS score)
# ═══════════════════════════════════════════════════════════════════════════
# Source: investigation/semgrep_adapter.py L329 (inline dict inside
#         _process_semgrep_result).  The reverse mapping lives in
#         core/models.SeverityLevel.from_cvss() and is NOT duplicated here.

SEVERITY_CVSS: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 0.0,
}

# ═══════════════════════════════════════════════════════════════════════════
# DUP-010 — SEVERITY_ORDER  (severity label → sort-rank integer)
# ═══════════════════════════════════════════════════════════════════════════
# Sources: reporting/forensic_report.py L46, investigation/investigator.py L46.
# Both contain identical values; only insertion order differed.

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# ═══════════════════════════════════════════════════════════════════════════
# DUP-011 — SKIP_DIRS  (directories to exclude from traversals)
# ═══════════════════════════════════════════════════════════════════════════
# Union of 13 non-archive sites.  See audit for per-site breakdown.
#
# Note: core/__init__.py AnalysisConfig.ignore_patterns also contains
# file-glob patterns ("*.pyc", "*.map", etc.) — those belong in
# SKIP_FILE_PATTERNS, not here.

_SKIP_DIRS: set[str] = {
    ".git",
    ".svn",
    "__pycache__",
    "node_modules",
    "vendor",
    ".tox",
    ".DS_Store",
}

# File-glob patterns found in AnalysisConfig.ignore_patterns that are
# NOT directory names.  Kept here for completeness; consumers can adopt
# whichever subset they need.
SKIP_FILE_PATTERNS: frozenset[str] = frozenset({
    "*.pyc",
    "*.map",
    "*.min.js",
    "*.min.css",
    "Thumbs.db",
})


def get_skip_dirs() -> frozenset[str]:
    """Return *frozen* snapshot of directories to exclude."""
    return frozenset(_SKIP_DIRS)


def register_skip_dirs(*dirs: str) -> None:
    """Add one or more directory names to the skip-set.

    Parameters
    ----------
    *dirs:
        Directory base-names (e.g. ``".mypy_cache"``, ``".pytest_cache"``).
    """
    added = set(dirs) - _SKIP_DIRS
    _SKIP_DIRS.update(dirs)
    if added:
        logger.debug("Registered skip dirs: %s", sorted(added))


# ═══════════════════════════════════════════════════════════════════════════
# DUP-012 — SCANNABLE_EXTENSIONS  (extensions eligible for content scanning)
# ═══════════════════════════════════════════════════════════════════════════
# Union of three sites:
#   knowledge/sensitive_data.py   — 21 extensions (frozenset)
#   investigation/investigator.py — 20 extensions + 3 by name-check
#   forensics/security_scanner.py — 11 extensions + 3 by name-check
#
# Canonical set = union of all (22 unique extensions).

_SCANNABLE_EXTENSIONS: set[str] = {
    ".php",
    ".inc",
    ".module",
    ".js",
    ".json",
    ".yml",
    ".yaml",
    ".xml",
    ".sql",
    ".txt",
    ".csv",
    ".html",
    ".htm",
    ".conf",
    ".ini",
    ".env",
    ".log",
    ".md",
    ".htaccess",
    ".user.ini",
    ".py",
    ".sh",
}


def get_scannable_extensions() -> frozenset[str]:
    """Return *frozen* snapshot of scannable file extensions."""
    return frozenset(_SCANNABLE_EXTENSIONS)


def register_scannable_extensions(*extensions: str) -> None:
    """Add one or more extensions to the scannable set.

    Parameters
    ----------
    *extensions:
        File extensions including the leading dot (e.g. ``".ts"``).

    Raises
    ------
    ValueError
        If any extension does not start with ``"."``.
    """
    bad = [e for e in extensions if not e.startswith(".")]
    if bad:
        raise ValueError(
            f"Extensions must start with '.', got {bad!r}"
        )
    added = set(extensions) - _SCANNABLE_EXTENSIONS
    _SCANNABLE_EXTENSIONS.update(extensions)
    if added:
        logger.debug("Registered scannable extensions: %s", sorted(added))


# ═══════════════════════════════════════════════════════════════════════════
# HC-004 — Entropy thresholds
# ═══════════════════════════════════════════════════════════════════════════
# Divergent values across the codebase:
#   forensics/file_analyzer.py   — >7.5 "suspicious", >6.0 "high"
#   evidence/manifest.py         — >7.0 "suspicious", >5.5 "elevated"
#   forensics/security_scanner.py — >5.5 (PHP-code-only Shannon)
#   core/__init__.py EvidenceConfig — entropy_threshold = 7.5
#
# Canonical defaults match the config dataclass (7.5) for the "suspicious"
# tier.  A secondary "elevated" tier is provided at 6.0 (the higher of the
# two secondary thresholds) to avoid false-positive regressions.

DEFAULT_ENTROPY_THRESHOLD: float = 7.5
"""Byte-level Shannon entropy above which a file is considered *suspicious*."""

ELEVATED_ENTROPY_THRESHOLD: float = 6.0
"""Byte-level Shannon entropy above which a file is flagged as *elevated*."""

# ═══════════════════════════════════════════════════════════════════════════
# HC-014 — Binary detection threshold
# ═══════════════════════════════════════════════════════════════════════════
# Source: forensics/file_analyzer.py L414 (only site).
# Ratio of non-printable bytes above which a file is treated as binary.

BINARY_DETECTION_THRESHOLD: float = 0.30
"""Non-text byte ratio above which a file is classified as binary."""
