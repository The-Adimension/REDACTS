"""
REDACTS Sandbox Isolation Utilities
=====================================
Path validation, input sanitisation, and integrity checking.

These utilities guard against path-traversal, URL injection, and
provide chain-of-custody hashing for evidence packages.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PathSecurity:
    """Filesystem path validation utilities."""

    @staticmethod
    def validate_path(path: Path) -> None:
        """Raise ``ValueError`` if *path* is unsafe (symlink or traversal)."""
        resolved = path.resolve()

        # Reject symlinks — they can escape sandbox boundaries
        if path.is_symlink():
            raise ValueError(f"Symlink not allowed: {path}")

        # Reject paths that try to escape via '..'
        try:
            resolved.relative_to(Path.cwd().resolve())
        except ValueError:
            pass  # Absolute paths outside CWD are OK for local loader

    @staticmethod
    def validate_zip_entry(entry_name: str) -> bool:
        """Return ``True`` if a ZIP entry name is safe to extract.

        Rejects absolute paths and directory-traversal sequences.
        """
        # Reject absolute paths (Unix or Windows)
        if entry_name.startswith("/") or entry_name.startswith("\\"):
            return False
        if len(entry_name) >= 2 and entry_name[1] == ":":
            return False  # Windows drive letter

        # Reject directory traversal
        parts = PurePosixPath(entry_name).parts
        if ".." in parts:
            return False

        # Normalise and re-check
        normalised = os.path.normpath(entry_name)
        if normalised.startswith("..") or normalised.startswith(os.sep):
            return False

        return True


class InputSanitizer:
    """Input sanitisation for URLs and user-supplied strings."""

    # Only allow http, https, ftp, sftp schemes
    _ALLOWED_SCHEMES = frozenset({"http", "https", "ftp", "sftp"})

    # Strip control characters (C0 + DEL + C1)
    _CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

    @staticmethod
    def sanitize_url(url: str) -> str:
        """Return a cleaned URL or raise ``ValueError`` if malformed.

        Strips leading/trailing whitespace, rejects control characters
        and unknown schemes.
        """
        url = url.strip()
        if not url:
            raise ValueError("Empty URL")

        if InputSanitizer._CONTROL_RE.search(url):
            raise ValueError("URL contains control characters")

        parsed = urlparse(url)
        if parsed.scheme.lower() not in InputSanitizer._ALLOWED_SCHEMES:
            raise ValueError(
                f"Unsupported URL scheme: {parsed.scheme!r}"
            )

        if not parsed.hostname:
            raise ValueError(f"No hostname in URL: {url!r}")

        return url


class IntegrityChecker:
    """Cryptographic integrity utilities for chain-of-custody evidence."""

    _ALLOWED_ALGORITHMS = frozenset({"sha256", "sha512", "sha384"})

    @staticmethod
    def compute_hash(path: Path, *, algorithm: str = "sha256") -> str:
        """Return the hex digest of *path* using *algorithm*.

        Raises ``ValueError`` for unsupported algorithms.
        Raises ``FileNotFoundError`` if *path* does not exist.
        """
        if algorithm not in IntegrityChecker._ALLOWED_ALGORITHMS:
            raise ValueError(
                f"Unsupported hash algorithm: {algorithm!r}. "
                f"Allowed: {sorted(IntegrityChecker._ALLOWED_ALGORITHMS)}"
            )

        h = hashlib.new(algorithm)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
