"""Canonical file-hashing entry point.

One implementation feeds every module that needs a hash - manifest,
baseline validator, file analyser, investigator - so the algorithm
set, buffer size, and error handling stay consistent across the
pipeline.

Defaults: SHA-256 + SHA-512 (FIPS 180-4) at a 64 KiB buffer. SHA-256
is the chain-of-custody hash quoted in reports; SHA-512 is kept as a
second independent digest so a future SHA-2 weakness in one variant
does not invalidate stored manifests. MD5 and SHA-1 remain available
through the registry for cross-referencing third-party tooling but
are not in the default set; do not rely on them for integrity.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Callable

logger = logging.getLogger(__name__)


#: Default buffer size in bytes.  Matches the largest existing buffer
#: (``baseline_validator.py`` / ``investigator.py`` use 65 536).
DEFAULT_BUFFER_SIZE: int = 65_536

#: Default algorithm set - matches ``AnalysisConfig.hash_algorithms`` and
#: ``EvidenceConfig.hash_algorithms`` defaults.
DEFAULT_ALGORITHMS: tuple[str, ...] = ("sha256", "sha512")



def compute_hashes(
    path: Path,
    *,
    algorithms: tuple[str, ...] | list[str] = DEFAULT_ALGORITHMS,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
) -> dict[str, str]:
    """Compute one or more cryptographic hashes for a single file.

    Single source of truth for evidence-grade hashing across the
    manifest, baseline-validation, and investigation pipelines.

    Parameters
    path:
        Filesystem path to the file to hash.
    algorithms:
        Sequence of algorithm names (looked up in the plugin registry).
        Defaults to ``("sha256", "sha512")``.
    buffer_size:
        Read buffer in bytes.  Defaults to 65 536.

    Returns
    dict[str, str]
        ``{algorithm_name: hex_digest}`` for each requested algorithm.

    Raises
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If an algorithm name is not supported by :mod:`hashlib`.
    OSError
        For other I/O errors (permission denied, etc.).

    Examples
    >>> hashes = compute_hashes(Path("README.md"))
    >>> sorted(hashes.keys())
    ['sha256', 'sha512']

    >>> sha_only = compute_hashes(Path("data.bin"), algorithms=("sha256",))
    >>> list(sha_only.keys())
    ['sha256']
    """
    if buffer_size <= 0:
        raise ValueError(f"buffer_size must be positive, got {buffer_size}")

    hashers = {algo: hashlib.new(algo) for algo in algorithms}

    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(buffer_size)
            if not chunk:
                break
            for h in hashers.values():
                h.update(chunk)

    return {algo: h.hexdigest() for algo, h in hashers.items()}



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
