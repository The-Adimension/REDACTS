"""Shared file-classification and formatting helpers.

Three concerns live here so they have one implementation across the
pipeline: category detection from extension/path, human-readable size
formatting, and binary-vs-text classification.

Binary detection is heuristic: a file is binary if it contains a NUL
byte in the sampled prefix, or if more than ``threshold`` of the
sampled bytes fall outside the printable-ASCII + tab/CR/LF set
(``_TEXT_CHARS``). UTF-16 and other wide-encoded text files therefore
classify as binary; that is intentional - the scanners run on UTF-8
sources, and a wide-encoded source should be flagged for review
rather than parsed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .constants import (
    BINARY_DETECTION_THRESHOLD,
    get_category_map,
)

logger = logging.getLogger(__name__)



_TEXT_CHARS: frozenset[int] = frozenset(range(32, 127)) | frozenset({9, 10, 13})


def ratio_strategy(chunk: bytes, *, threshold: float) -> bool:
    """Null-byte check + non-text ratio heuristic."""
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    non_text = sum(1 for b in chunk if b not in _TEXT_CHARS)
    return (non_text / len(chunk)) > threshold


def null_byte_strategy(chunk: bytes, *, threshold: float) -> bool:
    """Minimal heuristic: only check for null bytes."""
    if not chunk:
        return False
    return b"\x00" in chunk


_BUILT_IN_STRATEGIES = {
    "ratio": ratio_strategy,
    "null_byte": null_byte_strategy,
}



_SIZE_UNITS: dict[str, tuple[tuple[str, ...], int]] = {
    "binary_si": (("B", "KB", "MB", "GB", "TB"), 1024),
    "iec": (("B", "KiB", "MiB", "GiB", "TiB"), 1024),
    "decimal": (("B", "kB", "MB", "GB", "TB"), 1000),
}




def detect_category(
    extension: str,
    *,
    category_map: dict[str, Any] | None = None,
    default: str = "other",
) -> str:
    """Classify a file extension into a human-readable category.

    >>> detect_category(".py")
    'code'
    >>> detect_category(".xyz", default="unknown")
    'unknown'
    """
    cmap = category_map if category_map is not None else get_category_map()
    for category, extensions in cmap.items():
        if extension in extensions:
            return category
    return default




def human_size(
    size_bytes: int | float,
    *,
    unit_system: str = "binary_si",
    precision: int = 1,
) -> str:
    """Format byte count as a human-readable string.

    >>> human_size(0)
    '0.0 B'
    >>> human_size(1536)
    '1.5 KB'
    """
    if unit_system not in _SIZE_UNITS:
        raise KeyError(
            f"Unknown unit system {unit_system!r}. "
            f"Available: {sorted(_SIZE_UNITS)}"
        )
    labels, divisor = _SIZE_UNITS[unit_system]
    value: float = float(size_bytes)
    sign = -1 if value < 0 else 1
    value = abs(value)
    for unit in labels[:-1]:
        if value < divisor:
            return f"{sign * value:.{precision}f} {unit}"
        value /= divisor
    return f"{sign * value:.{precision}f} {labels[-1]}"




def is_binary(
    file_path: Path | str,
    *,
    extension: str = "",
    binary_extensions: frozenset[str] | set[str] | None = None,
    chunk_size: int = 8192,
    threshold: float = BINARY_DETECTION_THRESHOLD,
    strategy: Any = None,
) -> bool:
    """Detect whether a file is binary via extension shortcut or content heuristic."""
    # Resolve extension
    ext = extension or Path(file_path).suffix.lower()

    # 1. Extension shortcut
    if binary_extensions is not None and ext in binary_extensions:
        return True

    # 2. Content heuristic
    resolved_strategy = ratio_strategy
    if strategy is None:
        resolved_strategy = _BUILT_IN_STRATEGIES["ratio"]
    elif isinstance(strategy, str):
        if strategy not in _BUILT_IN_STRATEGIES:
            logger.warning(
                "Unknown binary strategy %r, falling back to 'ratio'",
                strategy,
            )
        else:
            resolved_strategy = _BUILT_IN_STRATEGIES[strategy]
    else:
        resolved_strategy = strategy

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(chunk_size)
        return resolved_strategy(chunk, threshold=threshold)
    except OSError:
        # Unreadable files are treated as binary (matches both adapters).
        return True


# Untrusted evidence files can be arbitrarily large (e.g. a 4 GB log that
# happened to land in the case dir).  Forensic analyzers only ever need
# the first few megabytes of any single artefact, so every analyzer call
# site is routed through ``_read_text_capped`` with an 8 MB ceiling.
#
# Behaviour:
#   * Reads at most ``limit`` bytes, decodes with the requested codec.
#   * If the file exceeds ``limit``, a ``TRUNCATED_MARKER`` line is
#     appended so downstream pattern matchers cannot accidentally treat
#     the cap as end-of-file.
#   * ``OSError`` and ``UnicodeDecodeError`` are translated to an empty
#     string + warning log so a single unreadable file does not abort
#     a whole investigation phase.

_DEFAULT_READ_LIMIT_BYTES: int = 8 * 1024 * 1024
TRUNCATED_MARKER: str = "\n<<<REDACTS-TRUNCATED-AT-CAP>>>\n"


def _read_text_capped(
    path: Path | str,
    *,
    limit: int = _DEFAULT_READ_LIMIT_BYTES,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Read up to ``limit`` bytes from *path* and return decoded text.

    Parameters
    path:
        File to read.  May be a :class:`pathlib.Path` or a ``str``.
    limit:
        Maximum number of bytes to read.  Defaults to 8 MiB.
    encoding, errors:
        Forwarded to :py:meth:`bytes.decode`.

    Returns
    str
        Decoded contents, with :data:`TRUNCATED_MARKER` appended when
        the file size exceeded ``limit``.  Returns ``""`` on I/O or
        decoding failure (a warning is logged in that case).
    """
    p = Path(path)
    try:
        with open(p, "rb") as fh:
            data = fh.read(limit + 1)
    except OSError as exc:
        logger.warning("Capped read failed for %s: %s", p, exc)
        return ""

    truncated = len(data) > limit
    if truncated:
        data = data[:limit]
    try:
        text = data.decode(encoding, errors=errors)
    except (LookupError, UnicodeDecodeError) as exc:
        logger.warning("Decode failed for %s: %s", p, exc)
        return ""
    if truncated:
        text += TRUNCATED_MARKER
    return text
