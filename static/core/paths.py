"""Canonical REDACTS path resolver.

Single source of truth for every directory REDACTS reads from or writes
to. Values come from the active :class:`~static.core.contract.FrozenCaseContract`
when one has been installed via :mod:`static.core.runtime_context`; otherwise
they fall back to the historical defaults under ``~/.redacts``.

Hard rules:

    * **No environment variables are consulted.** ``case.toml`` is the only
      configuration source. ``REDACTS_HOME`` / ``REDACTS_OUTPUT_DIR``
      / ``REDACTS_TOOLS_DIR`` / ``REDACTS_TEMP_DIR`` / ``REDACTS_CACHE_DIR``
      are all forbidden - see :data:`static.core.contract.FORBIDDEN_ENV_PREFIXES`.
    * The single permitted parent-process ``PATH`` mutation is
      :func:`inject_tools_on_path`. It exists so ``shutil.which`` finds
      auto-installed binaries (trivy, yara). Subprocess child environments
      are built separately by :mod:`static.core.subprocess_env`.

Every getter returns an absolute :class:`pathlib.Path`; the directory is
created (mode 0o700) on first access by :func:`ensure`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from .runtime_context import get_optional_contract

_DEFAULT_HOME: Final[Path] = (Path.home() / ".redacts").resolve()


def _from_contract(attr: str, fallback: Path) -> Path:
    contract = get_optional_contract()
    if contract is None:
        return fallback
    return getattr(contract.paths, attr).resolve()


def redacts_home() -> Path:
    """Base directory for all REDACTS state.

    With a contract installed, this is ``contract.paths.workspace_root``;
    otherwise ``~/.redacts``.
    """
    return _from_contract("workspace_root", _DEFAULT_HOME)


def output_dir() -> Path:
    """Reports + DAST results."""
    return _from_contract("output_root", _DEFAULT_HOME / "output")


def tools_dir() -> Path:
    """Auto-installed binaries (trivy, yara)."""
    return _from_contract("tools_root", _DEFAULT_HOME / "tools")


def temp_dir() -> Path:
    """Scratch space for in-progress scans."""
    return _from_contract("temp_root", _DEFAULT_HOME / "tmp")


def cache_dir() -> Path:
    """Long-lived enrichment cache (NVD, ATT&CK, YARA rules)."""
    return _from_contract("cache_root", _DEFAULT_HOME / "cache")


def ensure(path: Path) -> Path:
    """Create *path* with secure mode if missing; return it."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def resolved() -> dict[str, dict[str, str | bool]]:
    """Return a UI-friendly snapshot of every managed path.

    Used by ``GET /api/paths`` and by the ``redacts paths`` CLI.
    Each entry includes the resolved path, its source ("contract" or
    "default"), and whether the directory exists on disk.
    """
    contract_loaded = get_optional_contract() is not None
    source = "contract" if contract_loaded else "default"
    spec: list[tuple[str, Path]] = [
        ("home",   redacts_home()),
        ("output", output_dir()),
        ("tools",  tools_dir()),
        ("temp",   temp_dir()),
        ("cache",  cache_dir()),
    ]
    out: dict[str, dict[str, str | bool]] = {}
    for name, p in spec:
        out[name] = {
            "path": str(p),
            "source": source,
            "exists": p.exists(),
        }
    return out


def inject_tools_on_path() -> str:
    """Prepend :func:`tools_dir` to the parent process ``PATH``.

    Idempotent - re-calling does not duplicate the entry. This is the
    *only* place in the codebase allowed to mutate ``os.environ['PATH']``
    in the parent; subprocess child environments are constructed via
    :func:`static.core.subprocess_env.build`.
    """
    td = str(tools_dir())
    current = os.environ.get("PATH", "")  # ALLOWED: PATH chokepoint
    if td not in current.split(os.pathsep):
        os.environ["PATH"] = td + os.pathsep + current  # ALLOWED: PATH chokepoint
    return os.environ["PATH"]  # ALLOWED: PATH chokepoint
