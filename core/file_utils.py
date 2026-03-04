"""Shared file-classification and formatting utilities for REDACTS.

Replaces duplicate ``_detect_category`` methods on
:class:`FileAnalyzer` and :class:`ManifestBuilder` (DUP-005) and the
duplicate ``_human_size`` static methods on both classes (DUP-006) with
canonical free-functions.

Design patterns
---------------
* **Strategy** – :func:`detect_category` accepts a *category_map*
  callback (or uses the canonical :func:`get_category_map`) and a
  configurable *default* return value so each caller can preserve its
  original fallback (``"other"`` vs ``"unknown"``) without branching
  in shared code.  :func:`is_binary` accepts a *strategy* callback so
  callers can plug in custom binary-detection heuristics.
* **Plugin registry** – :data:`_SIZE_UNITS` and :data:`_BINARY_STRATEGIES`
  registries allow new units or detection strategies to be registered
  via :func:`register_size_units` and :func:`register_binary_strategy`
  without touching existing code.
* **Configuration-driven** – all threshold / default values are
  keyword-only arguments (``default``, ``threshold``, ``chunk_size``)
  so callers can override them via config objects without forking the
  implementation.

Backward-compatibility
----------------------
* :func:`detect_category` returns the same ``str`` that both adapters'
  ``_detect_category`` produced (default differs per caller — pass
  ``default="other"`` or ``default="unknown"`` to match).
* :func:`human_size` returns the same formatted string as both
  adapters' ``_human_size`` (hybrid SI labels, binary thresholds).
* :func:`is_binary` matches the most complete implementation
  (``file_analyzer.py``) while accepting parameters that reproduce
  any other variant.
* This file is purely additive (blast-radius **NONE**).

Addresses
---------
DUP-005 (2 ``_detect_category``), DUP-006 (2 ``_human_size``).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .constants import (
    BINARY_DETECTION_THRESHOLD,
    get_category_map,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Strategy protocol for binary detection
# ═══════════════════════════════════════════════════════════════════════════


@runtime_checkable
class BinaryDetectionStrategy(Protocol):
    """Callable that decides whether a raw byte chunk is binary.

    Parameters
    ----------
    chunk:
        Raw bytes read from the beginning of a file.
    threshold:
        Ratio of non-printable bytes above which the content is binary.

    Returns
    -------
    bool
        ``True`` if the chunk should be classified as binary.
    """

    def __call__(self, chunk: bytes, *, threshold: float) -> bool: ...


# ═══════════════════════════════════════════════════════════════════════════
# Built-in binary-detection strategies
# ═══════════════════════════════════════════════════════════════════════════

#: Printable ASCII range + tab, LF, CR — matches file_analyzer.py L411.
_TEXT_CHARS: frozenset[int] = frozenset(range(32, 127)) | frozenset({9, 10, 13})


def ratio_strategy(chunk: bytes, *, threshold: float) -> bool:
    """Full heuristic: null-byte check **and** non-text ratio.

    This reproduces the logic in ``FileAnalyzer._is_binary`` (the most
    complete implementation):

    1. If the chunk contains ``\\x00`` → binary.
    2. Compute ratio of bytes outside printable-ASCII + whitespace.
    3. If ratio > *threshold* → binary.
    """
    if not chunk:
        return False
    if b"\x00" in chunk:
        return True
    non_text = sum(1 for b in chunk if b not in _TEXT_CHARS)
    return (non_text / len(chunk)) > threshold


def null_byte_strategy(chunk: bytes, *, threshold: float) -> bool:
    """Minimal heuristic: only check for null bytes.

    Reproduces the logic in ``sensitive_data.py::_is_binary`` which only
    tests for ``\\x00`` presence.  The *threshold* parameter is accepted
    for protocol compliance but ignored.
    """
    if not chunk:
        return False
    return b"\x00" in chunk


# ═══════════════════════════════════════════════════════════════════════════
# Plugin registry — binary-detection strategies
# ═══════════════════════════════════════════════════════════════════════════

_BINARY_STRATEGIES: dict[str, BinaryDetectionStrategy] = {
    "ratio": ratio_strategy,
    "null_byte": null_byte_strategy,
}


def register_binary_strategy(name: str, strategy: BinaryDetectionStrategy) -> None:
    """Register a new binary-detection strategy.

    Parameters
    ----------
    name:
        Unique strategy name.
    strategy:
        Callable matching :class:`BinaryDetectionStrategy`.

    Raises
    ------
    KeyError
        If *name* is already registered.  Use :func:`replace_binary_strategy`.
    """
    if name in _BINARY_STRATEGIES:
        raise KeyError(
            f"Binary strategy {name!r} already registered. "
            "Use replace_binary_strategy() to overwrite."
        )
    _BINARY_STRATEGIES[name] = strategy
    logger.debug("Registered binary strategy: %s", name)


def replace_binary_strategy(name: str, strategy: BinaryDetectionStrategy) -> None:
    """Register or replace a binary-detection strategy (upsert)."""
    _BINARY_STRATEGIES[name] = strategy
    logger.debug("Replaced binary strategy: %s", name)


def get_binary_strategies() -> dict[str, BinaryDetectionStrategy]:
    """Return a shallow copy of the strategy registry."""
    return dict(_BINARY_STRATEGIES)


# ═══════════════════════════════════════════════════════════════════════════
# Plugin registry — size unit sequences
# ═══════════════════════════════════════════════════════════════════════════

_SIZE_UNITS: dict[str, tuple[tuple[str, ...], int]] = {
    "binary_si": (("B", "KB", "MB", "GB", "TB"), 1024),
    "iec": (("B", "KiB", "MiB", "GiB", "TiB"), 1024),
    "decimal": (("B", "kB", "MB", "GB", "TB"), 1000),
}
"""Mapping of unit-system name → (labels, divisor).

``"binary_si"`` is the default and reproduces the existing behavior:
SI-style labels (KB, MB …) with a 1024-based divisor.  This is the
convention both ``file_analyzer.py`` and ``manifest.py`` used.
"""


def register_size_units(
    name: str, labels: tuple[str, ...], divisor: int
) -> None:
    """Register a new unit system for :func:`human_size`.

    Raises
    ------
    KeyError
        If *name* already exists.  Use :func:`replace_size_units`.
    """
    if name in _SIZE_UNITS:
        raise KeyError(
            f"Size unit system {name!r} already registered. "
            "Use replace_size_units() to overwrite."
        )
    _SIZE_UNITS[name] = (labels, divisor)
    logger.debug("Registered size units: %s", name)


def replace_size_units(
    name: str, labels: tuple[str, ...], divisor: int
) -> None:
    """Register or replace a unit system (upsert)."""
    _SIZE_UNITS[name] = (labels, divisor)
    logger.debug("Replaced size units: %s", name)


def get_size_units() -> dict[str, tuple[tuple[str, ...], int]]:
    """Return a shallow copy of the unit-system registry."""
    return dict(_SIZE_UNITS)


# ═══════════════════════════════════════════════════════════════════════════
# DUP-005 — detect_category  (canonical replacement)
# ═══════════════════════════════════════════════════════════════════════════


def detect_category(
    extension: str,
    *,
    category_map: dict[str, Any] | None = None,
    default: str = "other",
) -> str:
    """Classify a file extension into a human-readable category.

    Parameters
    ----------
    extension:
        The file extension **including** the leading dot (e.g. ``".py"``).
    category_map:
        Optional mapping of ``{category: collection_of_extensions}``.
        Defaults to the canonical :func:`get_category_map` from
        ``core.constants``.
    default:
        Value returned when *extension* matches no category.
        ``"other"`` matches ``FileAnalyzer._detect_category``;
        pass ``"unknown"`` to match ``ManifestBuilder._detect_category``.

    Returns
    -------
    str
        The matched category name, or *default*.

    Examples
    --------
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


# ═══════════════════════════════════════════════════════════════════════════
# DUP-006 — human_size  (canonical replacement)
# ═══════════════════════════════════════════════════════════════════════════


def human_size(
    size_bytes: int | float,
    *,
    unit_system: str = "binary_si",
    precision: int = 1,
) -> str:
    """Format byte count as a human-readable string.

    Parameters
    ----------
    size_bytes:
        Number of bytes (may be negative — ``abs()`` is used for
        threshold comparison, matching ``manifest.py``'s variant).
    unit_system:
        Key into :data:`_SIZE_UNITS` (default ``"binary_si"``).
        Determines labels and divisor.
    precision:
        Decimal places in the formatted number (default ``1``).

    Returns
    -------
    str
        Formatted string, e.g. ``"1.2 MB"``, ``"3.0 GiB"``.

    Raises
    ------
    KeyError
        If *unit_system* is not registered.

    Examples
    --------
    >>> human_size(0)
    '0.0 B'
    >>> human_size(1536)
    '1.5 KB'
    >>> human_size(-2048)
    '-2.0 KB'
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


# ═══════════════════════════════════════════════════════════════════════════
# is_binary — canonical replacement with Strategy pattern
# ═══════════════════════════════════════════════════════════════════════════


def is_binary(
    file_path: Path | str,
    *,
    extension: str = "",
    binary_extensions: frozenset[str] | set[str] | None = None,
    chunk_size: int = 8192,
    threshold: float = BINARY_DETECTION_THRESHOLD,
    strategy: BinaryDetectionStrategy | str | None = None,
) -> bool:
    """Detect whether a file is binary.

    Reproduces the three-tier check from ``FileAnalyzer._is_binary``:

    1. **Extension shortcut** — if *extension* is in *binary_extensions*
       the file is binary without reading content.
    2. **Content heuristic** — read *chunk_size* bytes and delegate to
       *strategy* (default ``"ratio"``).

    Parameters
    ----------
    file_path:
        Path to the file on disk.
    extension:
        Pre-extracted extension (e.g. ``".png"``).  When empty the
        extension is derived from *file_path*.
    binary_extensions:
        Set of extensions treated as binary.  ``None`` means skip the
        extension shortcut entirely (reproducing the
        ``sensitive_data.py`` variant).
    chunk_size:
        Bytes to read for content heuristic (default ``8192``).
    threshold:
        Non-text byte ratio above which content is binary.
        Default :data:`BINARY_DETECTION_THRESHOLD` from
        ``core.constants`` (``0.30``).
    strategy:
        Binary-detection strategy.  May be:
        - a ``str`` key into the :data:`_BINARY_STRATEGIES` registry,
        - a callable matching :class:`BinaryDetectionStrategy`,
        - ``None`` (default → ``"ratio"``).

    Returns
    -------
    bool
        ``True`` if the file should be treated as binary.
    """
    # Resolve extension
    ext = extension or Path(file_path).suffix.lower()

    # 1. Extension shortcut
    if binary_extensions is not None and ext in binary_extensions:
        return True

    # 2. Content heuristic
    resolved_strategy: BinaryDetectionStrategy
    if strategy is None:
        resolved_strategy = _BINARY_STRATEGIES["ratio"]
    elif isinstance(strategy, str):
        if strategy not in _BINARY_STRATEGIES:
            logger.warning(
                "Unknown binary strategy %r, falling back to 'ratio'",
                strategy,
            )
            resolved_strategy = _BINARY_STRATEGIES["ratio"]
        else:
            resolved_strategy = _BINARY_STRATEGIES[strategy]
    else:
        resolved_strategy = strategy

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(chunk_size)
        return resolved_strategy(chunk, threshold=threshold)
    except OSError:
        # Unreadable files are treated as binary (matches both adapters).
        return True
