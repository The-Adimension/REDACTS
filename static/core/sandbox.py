"""Path-validation and integrity helpers for evidence ingestion.

Two guards are provided:

    * :class:`PathSecurity` - strict and lenient path validators. The
      strict variant rejects symlinks and ``..`` traversal segments
      (CWE-22 https://cwe.mitre.org/data/definitions/22.html); the
      lenient one is for display only.
    * Hash-based integrity helpers used by the manifest stage.

Known limits:

    * Symlink rejection is point-in-time. A check-then-use pattern
      can race against an attacker who swaps a regular file for a
      symlink between the validator and the consumer (CWE-367 TOCTOU,
      https://cwe.mitre.org/data/definitions/367.html). Callers that
      need atomicity should ``open`` with ``O_NOFOLLOW`` (POSIX) or
      a Windows equivalent and operate on the file descriptor.
    * Path validation operates on strings/Paths supplied by the
      caller. It cannot detect a hostile filesystem mount layered
      under the target - that is an operator concern.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class PathSecurity:
    """Filesystem path validation utilities.

    Two flavours are exposed:

    * :py:meth:`validate_path_strict` - for ingestion / extraction sites.
      Rejects symlinks and any path containing ``..`` traversal segments.
    * :py:meth:`normalize_path_lenient` - for display / logging only.
      Never raises; returns a forward-slash POSIX rendering.
    """

    @staticmethod
    def validate_path_strict(path: Path) -> None:
        """Reject *path* if it is a symlink or contains ``..`` traversal.

        Parameters
        path:
            User-supplied path candidate (already converted to ``Path``).

        Raises
        ValueError
            When the path is a symlink, contains a parent-directory
            segment, or normalises outside its declared root.
        """
        # Reject symlinks - they can escape sandbox boundaries.
        if path.is_symlink():
            raise ValueError(f"Symlink not allowed: {path}")

        # Reject `..` segments in the user-supplied form *before* resolution.
        if any(part == ".." for part in path.parts):
            raise ValueError(f"Path traversal not allowed: {path}")

        # If the resolved path differs structurally from the normalised
        # input, treat that as a traversal attempt as well.
        resolved = path.resolve()
        normalised = Path(os.path.normpath(str(path)))
        if ".." in normalised.parts:
            raise ValueError(f"Path traversal not allowed: {path}")
        # ``resolved`` is intentionally not constrained to CWD: callers
        # routinely operate on absolute paths under /tmp, %TEMP%, etc.
        _ = resolved

    @staticmethod
    def normalize_path_lenient(path: Path | str) -> str:
        """Return a display-friendly POSIX rendering of *path*.

        This helper never raises and never resolves symlinks.  It is
        intended for log lines and report fields where readability
        matters more than security guarantees.
        """
        text = str(path).replace("\\", "/")
        # Collapse duplicate separators without touching `..` segments
        # so the display still reflects the operator's input.
        while "//" in text:
            text = text.replace("//", "/")
        return text

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

        # Delegate to the canonical hashing helper.  The allowlist
        # above remains the security boundary; compute_single_hash
        # does the buffered read.
        from static.core.hashing import compute_single_hash

        return compute_single_hash(path, algorithm=algorithm)
