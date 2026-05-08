"""Canonical constants for REDACTS.

Language map, category map, severity scoring, traversal exclusions, and
entropy thresholds. Mutable registries expose ``register_*`` mutators;
public ``get_*`` accessors return frozen copies so callers cannot mutate
shared state.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

# --- Portable tool cache path - used by cli/dependencies and scanners/external ---
# Single source of truth lives in static.core.paths. Resolution is lazy
# (via module __getattr__) so consumers always see the value reflecting
# the active FrozenCaseContract, even if they imported this module
# before the contract was installed.
from .paths import tools_dir as _resolve_tools_dir


def __getattr__(name: str):  # noqa: D401 (PEP 562 module hook)
    if name in ("TOOLS_DIR", "_TOOLS_DIR"):
        return _resolve_tools_dir()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# Canonical package version. Import this rather than hardcoding a
# literal in report headers, SARIF tool blocks, or audit footers.
VERSION: str = "3.0.0"

# --- LANGUAGE_MAP  (file-extension -> human-readable language name) ---

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
    """Return *frozen* copy of the extension -> language mapping."""
    return dict(_LANGUAGE_MAP)


def register_language(extension: str, language: str) -> None:
    """Add or overwrite an extension -> language mapping at runtime.

    Parameters
    extension:
        File extension including the leading dot (e.g. ``".ts"``).
    language:
        Human-readable language name (e.g. ``"TypeScript"``).

    Raises
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
        logger.debug("Registered language mapping: %s -> %s", extension, language)
    else:
        logger.debug(
            "Replaced language mapping: %s -> %s (was %s)", extension, language, prev
        )


# --- CATEGORY_MAP  (category -> set of extensions) ----------

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
    """Return *frozen* copy of the category -> extensions mapping."""
    return {k: frozenset(v) for k, v in _CATEGORY_MAP.items()}


def register_category_entries(
    category: str, extensions: Iterable[str]
) -> None:
    """Add *extensions* to *category*, creating the category if needed.

    Parameters
    category:
        Category key (e.g. ``"code"``, ``"binary"``).
    extensions:
        One or more file extensions, each starting with ``"."``.

    Raises
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


# --- SEVERITY_CVSS  (severity label -> representative CVSS score) ---
# The reverse mapping lives in core/models.SeverityLevel.from_cvss().

SEVERITY_CVSS: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 0.0,
}

# --- SEVERITY_ORDER  (severity label -> sort-rank integer) ---

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# --- SKIP_DIRS  (directories to exclude from traversals) ---
# Note: core/__init__.py AnalysisConfig.ignore_patterns also contains
# file-glob patterns ("*.pyc", "*.map", etc.) - those belong in
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
    *dirs:
        Directory base-names (e.g. ``".mypy_cache"``, ``".pytest_cache"``).
    """
    added = set(dirs) - _SKIP_DIRS
    _SKIP_DIRS.update(dirs)
    if added:
        logger.debug("Registered skip dirs: %s", sorted(added))


# --- SCANNABLE_EXTENSIONS  (extensions eligible for content scanning) ---

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
    *extensions:
        File extensions including the leading dot (e.g. ``".ts"``).

    Raises
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


# --- Entropy thresholds --

DEFAULT_ENTROPY_THRESHOLD: float = 7.5
"""Byte-level Shannon entropy above which a file is considered *suspicious*."""

ELEVATED_ENTROPY_THRESHOLD: float = 6.0
"""Byte-level Shannon entropy above which a file is flagged as *elevated*."""

# Manifest-specific (lower) thresholds - the evidence collector intentionally
# casts a wider net than the analysis layer so more files are flagged for
# forensic review.
MANIFEST_SUSPICIOUS_ENTROPY: float = 7.0
"""Manifest entropy above which a file is flagged *suspicious*."""

MANIFEST_ELEVATED_ENTROPY: float = 5.5
"""Manifest entropy above which a file is flagged *elevated*."""

# PHP obfuscation detection threshold (scanner.py)
OBFUSCATION_ENTROPY_THRESHOLD: float = 5.5
"""PHP code entropy above which obfuscation is suspected."""

# --- Binary detection threshold -----------
# Ratio of non-printable bytes above which a file is treated as binary.

BINARY_DETECTION_THRESHOLD: float = 0.30
"""Non-text byte ratio above which a file is classified as binary."""
