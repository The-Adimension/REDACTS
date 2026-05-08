"""REDACTS - subprocess environment chokepoint.

Every ``subprocess.Popen`` / ``subprocess.run`` call in REDACTS routes its
``env=`` argument through :func:`build`. Direct use of ``os.environ.copy()``
to seed a child process is forbidden by ``scripts/check_no_env_reads.py``.

Why a chokepoint:

* The contract module refuses to start if any ``REDACTS_*``/``DAST_*``/
  ``REDCAP_*``/``PLAYWRIGHT_*`` variable is set in the parent. That guarantee
  is undone the moment any caller seeds a child with the parent's full env.
* A small, audited whitelist makes the *exact* set of variables a child
  inherits visible at the call site.

Children are configured by being passed ``--case <path>`` (and, where
relevant, the path to ``case.lock.json`` via ``REDACTS_CASE_LOCK``). They
do *not* receive a copy of the parent process environment.

Copyright 2024-2026 The Adimension / Shehab Anwer.
Licensed under the Apache License, Version 2.0.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping

from .contract import FrozenCaseContract


# Names that are always safe to inherit because a child cannot use them to
# alter REDACTS run semantics; they only let the OS function.
_BASE_INHERIT_POSIX: tuple[str, ...] = (
    "HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
)
_BASE_INHERIT_WINDOWS: tuple[str, ...] = (
    "SystemRoot", "COMSPEC", "PATHEXT", "USERPROFILE",
    "APPDATA", "LOCALAPPDATA", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
    "WINDIR",
)


def _inherit(name: str) -> str | None:
    """Read a single inheritable variable from the parent env, or ``None``."""
    return os.environ.get(name)


def build(
    contract: FrozenCaseContract,
    *,
    role: str,
    case_lock_path: Path | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a *minimal* explicit environment for a child process.

    Args:
        contract: The frozen contract for the running case.
        role: A label used by tests / logs (e.g. ``"redacts-cli"``,
            ``"docker-compose"``, ``"playwright"``).
        case_lock_path: If provided, the child receives ``REDACTS_CASE_LOCK``
            pointing at this lockfile (the *only* ``REDACTS_*`` variable
            this module is allowed to set).
        extra: Additional explicit pairs the caller knows the child needs
            (e.g. compose passing ``COMPOSE_FILE``). All names must be
            documented at the call site; this function does not vet them.

    Returns:
        A dict suitable for ``subprocess.Popen(..., env=...)``.
    """
    if not isinstance(role, str) or not role.strip():
        raise ValueError("subprocess_env.build: 'role' must be a non-empty string")

    env: dict[str, str] = {}

    # PATH: derive from the contract's tools_root + the OS PATH (so /bin,
    # /usr/bin, system32 still resolve). The tools_root is prepended so
    # auto-installed binaries take precedence.
    parent_path = os.environ.get("PATH", "")
    tools_root = str(contract.paths.tools_root)
    if parent_path:
        env["PATH"] = os.pathsep.join([tools_root, parent_path])
    else:
        env["PATH"] = tools_root

    # PYTHONUNBUFFERED guarantees stdout flushing for SSE streaming.
    env["PYTHONUNBUFFERED"] = "1"

    # Per-run temp dir comes from the contract.
    temp_root = str(contract.paths.temp_root)
    env["TMPDIR"] = temp_root
    if sys.platform == "win32":
        env["TEMP"] = temp_root
        env["TMP"] = temp_root
        for name in _BASE_INHERIT_WINDOWS:
            value = _inherit(name)
            if value is not None:
                env[name] = value
    else:
        for name in _BASE_INHERIT_POSIX:
            value = _inherit(name)
            if value is not None:
                env[name] = value

    if case_lock_path is not None:
        env["REDACTS_CASE_LOCK"] = str(Path(case_lock_path).resolve())

    if extra:
        for key, value in extra.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError(
                    f"subprocess_env.build: extra[{key!r}] must be a (str, str) pair"
                )
            env[key] = value

    return env


def minimal_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return a contract-less, minimum-viable child environment.

    Intended for early-bootstrap paths that spawn a child ``main.py``
    which will load the contract for itself. Reads only ``PATH`` plus
    the platform's small set of OS-essential vars; nothing
    REDACTS-specific is inherited. Callers add their own explicit
    values via ``extra``.
    """
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONUNBUFFERED": "1",
    }
    inherits = _BASE_INHERIT_WINDOWS if sys.platform == "win32" else _BASE_INHERIT_POSIX
    for name in inherits:
        value = _inherit(name)
        if value is not None:
            env[name] = value
    if extra:
        for key, value in extra.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError(
                    f"subprocess_env.minimal_env: extra[{key!r}] must be (str, str)"
                )
            env[key] = value
    return env


__all__ = ["build", "minimal_env"]
