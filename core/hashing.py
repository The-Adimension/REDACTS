"""Canonical file-hashing utilities for REDACTS.

Replaces 4 independent hash implementations scattered across the codebase
(DUP-001) with a single, configuration-driven module that uses the
**Strategy pattern** and a **plugin registry** so new algorithms can be
added without touching existing code.

Design patterns
---------------
* **Strategy** – each hash algorithm is a callable strategy conforming to
  :class:`HashStrategy`.
* **Plugin registry** – :data:`ALGORITHM_REGISTRY` maps ``str`` names to
  concrete strategy factories; register new ones via :func:`register_algorithm`.
* **Configuration-driven** – callers pass a sequence of algorithm *names* +
  a buffer size; the registry resolves them at call time.

Backward-compatibility
----------------------
* :func:`compute_hashes` returns ``dict[str, str]`` – drop-in for
  ``FileAnalyzer._compute_hashes`` and ``ManifestBuilder._compute_hashes``.
* :func:`compute_single_hash` returns a single ``str`` – drop-in for
  ``Investigator._sha256`` and ``BaselineValidator._hash_tree`` per-file hash.
* Buffer-size default is 65 536 (matches the larger of the two existing
  buffer sizes; the 8 192-byte sites get an invisible speed-up).

Addresses
---------
DUP-001 (6→1 hash implementations), HC-003 (hardcoded buffer sizes).
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Strategy protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class HashStrategy(Protocol):
    """A hashlib-compatible incremental-hash object.

    Any object exposing ``update(data)`` and ``hexdigest() -> str`` satisfies
    this protocol – including every ``hashlib`` hash and HMAC objects.
    """

    def update(self, data: bytes, /) -> Any:
        """Feed *data* into the hash state."""
        ...  # pragma: no cover

    def hexdigest(self) -> str:
        """Return the current digest as a lowercase hex string."""
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

# Maps a canonical algorithm name (lowercase) to a zero-arg factory that
# returns a fresh HashStrategy instance.
AlgorithmFactory = Callable[[], HashStrategy]

_ALGORITHM_REGISTRY: dict[str, AlgorithmFactory] = {}


def register_algorithm(name: str, factory: AlgorithmFactory) -> None:
    """Register a new hash algorithm under *name*.

    Parameters
    ----------
    name:
        Case-insensitive algorithm name (stored lowercase).
    factory:
        Zero-argument callable returning a fresh :class:`HashStrategy`.

    Raises
    ------
    ValueError
        If *name* is already registered (prevents silent overwrites).
    """
    key = name.strip().lower()
    if not key:
        raise ValueError("Algorithm name must be a non-empty string")
    if key in _ALGORITHM_REGISTRY:
        raise ValueError(
            f"Algorithm '{key}' is already registered. "
            "Use replace_algorithm() to override."
        )
    _ALGORITHM_REGISTRY[key] = factory


def replace_algorithm(name: str, factory: AlgorithmFactory) -> None:
    """Replace an existing algorithm registration.

    Identical to :func:`register_algorithm` but overwrites silently.
    Useful for testing or hot-patching.
    """
    key = name.strip().lower()
    if not key:
        raise ValueError("Algorithm name must be a non-empty string")
    _ALGORITHM_REGISTRY[key] = factory


def get_registered_algorithms() -> frozenset[str]:
    """Return the set of currently registered algorithm names."""
    return frozenset(_ALGORITHM_REGISTRY)


def _resolve_factory(name: str) -> AlgorithmFactory:
    """Look up *name* in the registry; raise :class:`KeyError` on miss."""
    key = name.strip().lower()
    try:
        return _ALGORITHM_REGISTRY[key]
    except KeyError:
        available = ", ".join(sorted(_ALGORITHM_REGISTRY)) or "(none)"
        raise KeyError(
            f"Unknown hash algorithm '{name}'. "
            f"Registered algorithms: {available}"
        ) from None


# ---------------------------------------------------------------------------
# Register stdlib defaults
# ---------------------------------------------------------------------------

register_algorithm("md5", hashlib.md5)
register_algorithm("sha256", hashlib.sha256)
register_algorithm("sha512", hashlib.sha512)
register_algorithm("sha1", hashlib.sha1)
register_algorithm("sha384", hashlib.sha384)
register_algorithm("sha3_256", hashlib.sha3_256)
register_algorithm("sha3_512", hashlib.sha3_512)
register_algorithm("blake2b", hashlib.blake2b)
register_algorithm("blake2s", hashlib.blake2s)


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

#: Default buffer size in bytes.  Matches the largest existing buffer
#: (``baseline_validator.py`` / ``investigator.py`` use 65 536).
DEFAULT_BUFFER_SIZE: int = 65_536

#: Default algorithm set — matches ``AnalysisConfig.hash_algorithms`` and
#: ``EvidenceConfig.hash_algorithms`` defaults.
DEFAULT_ALGORITHMS: tuple[str, ...] = ("md5", "sha256", "sha512")


# ---------------------------------------------------------------------------
# Public API — multi-algorithm hashing (Strategy + Config-driven)
# ---------------------------------------------------------------------------

def compute_hashes(
    path: Path,
    *,
    algorithms: tuple[str, ...] | list[str] = DEFAULT_ALGORITHMS,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> dict[str, str]:
    """Compute one or more cryptographic hashes for a single file.

    This is the **canonical** hashing entry point.  It replaces the four
    independent implementations formerly in *evidence/manifest.py*,
    *forensics/file_analyzer.py*, *forensics/baseline_validator.py*, and
    *investigation/investigator.py*.

    Parameters
    ----------
    path:
        Filesystem path to the file to hash.
    algorithms:
        Sequence of algorithm names (looked up in the plugin registry).
        Defaults to ``("md5", "sha256", "sha512")``.
    buffer_size:
        Read buffer in bytes.  Defaults to 65 536.

    Returns
    -------
    dict[str, str]
        ``{algorithm_name: hex_digest}`` for each requested algorithm.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    KeyError
        If an algorithm name is not in the registry.
    OSError
        For other I/O errors (permission denied, etc.).

    Examples
    --------
    >>> hashes = compute_hashes(Path("README.md"))
    >>> sorted(hashes.keys())
    ['md5', 'sha256', 'sha512']

    >>> sha_only = compute_hashes(Path("data.bin"), algorithms=("sha256",))
    >>> list(sha_only.keys())
    ['sha256']
    """
    if buffer_size <= 0:
        raise ValueError(f"buffer_size must be positive, got {buffer_size}")

    # Resolve strategies from the registry
    hashers: dict[str, HashStrategy] = {
        algo: _resolve_factory(algo)() for algo in algorithms
    }

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(buffer_size)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)

    return {algo: h.hexdigest() for algo, h in hashers.items()}


# ---------------------------------------------------------------------------
# Public API — single-algorithm convenience (drop-in for _sha256 callers)
# ---------------------------------------------------------------------------

def compute_single_hash(
    path: Path,
    *,
    algorithm: str = "sha256",
    buffer_size: int = DEFAULT_BUFFER_SIZE,
    suppress_errors: bool = False,
) -> str:
    """Compute a single hash digest for *path*.

    Drop-in replacement for ``Investigator._sha256`` (which returns ``""``
    on error) and ``BaselineValidator._hash_tree`` per-file hashing.

    Parameters
    ----------
    path:
        Filesystem path.
    algorithm:
        Registry algorithm name (default ``"sha256"``).
    buffer_size:
        Read buffer in bytes.
    suppress_errors:
        If ``True``, return ``""`` on any :class:`Exception` instead of
        raising.  Matches the original ``Investigator._sha256`` semantics.

    Returns
    -------
    str
        Hex digest, or ``""`` if *suppress_errors* is ``True`` and an
        error occurred.
    """
    try:
        result = compute_hashes(path, algorithms=(algorithm,), buffer_size=buffer_size)
        return result[algorithm]
    except Exception:
        if suppress_errors:
            logger.debug("Hash computation suppressed for %s", path, exc_info=True)
            return ""
        raise


# ---------------------------------------------------------------------------
# Public API — directory tree hashing (drop-in for _hash_tree)
# ---------------------------------------------------------------------------

def hash_tree(
    root: Path,
    *,
    algorithm: str = "sha256",
    buffer_size: int = DEFAULT_BUFFER_SIZE,
    skip_predicate: Callable[[str], bool] | None = None,
) -> dict[str, str]:
    """Build ``{relative_posix_path: hex_digest}`` for every file under *root*.

    Drop-in replacement for ``BaselineValidator._hash_tree``.

    Parameters
    ----------
    root:
        Root directory to walk.
    algorithm:
        Hash algorithm name (default ``"sha256"``).
    buffer_size:
        Read buffer in bytes.
    skip_predicate:
        Optional callable that receives the *relative* (forward-slash)
        path and returns ``True`` to skip the file.  ``None`` means
        hash everything.

    Returns
    -------
    dict[str, str]
        ``{relative_path: hex_digest}`` sorted by path.
    """
    hashes: dict[str, str] = {}
    for file_path in sorted(root.rglob("*")):
        if not file_path.is_file():
            continue
        rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        if skip_predicate is not None and skip_predicate(rel_path):
            continue
        try:
            digest = compute_single_hash(
                file_path, algorithm=algorithm, buffer_size=buffer_size
            )
            hashes[rel_path] = digest
        except Exception as exc:
            logger.warning("Could not hash %s: %s", rel_path, exc)
    return hashes
