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
import re
import shutil
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


def _is_windows() -> bool:
    """Platform probe read at call time so tests can simulate Windows."""
    return sys.platform == "win32" or os.name == "nt"


# Characters cmd.exe treats as metacharacters. ``subprocess`` quotes arguments
# for the MSVCRT argument parser via ``list2cmdline``, but cmd.exe parses the
# command line *before* that runs, so an unquoted one of these inside an
# argument is a command separator, not data. There is no fully sound escaping
# for this (``%VAR%`` expansion happens ahead of quote processing and cannot be
# suppressed), which is why we resolve shims away instead of escaping.
_CMD_METACHARACTERS = frozenset('&|<>^()"%!\r\n')

# npm-generated ``.cmd`` shims end in a line equivalent to
#   "%_prog%" "%dp0%\node_modules\<pkg>\bin\<entry>.cjs" %*
# The ``%*`` is what cmd.exe re-expands, so the embedded entry path is the
# thing we want to hand to node directly.
_NPM_SHIM_ENTRY_RE = re.compile(
    r'%dp0%[\\/]([^"%\r\n]+?\.(?:cjs|mjs|js))',
    re.IGNORECASE,
)


class UnsafeCommandError(ValueError):
    """An argument cannot reach a Windows script shim without shell injection."""


def _resolve_npm_shim(shim: Path) -> list[str] | None:
    """Resolve an npm ``.cmd`` wrapper to a direct ``[node, entry_script]`` call.

    Returns ``None`` when *shim* is not a recognisable npm wrapper, when the
    entry script it names is missing, or when no node executable can be found -
    in which case the caller falls back to the guarded cmd.exe path.
    """
    try:
        text = shim.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    match = _NPM_SHIM_ENTRY_RE.search(text)
    if match is None:
        return None

    entry = shim.parent / match.group(1).replace("\\", os.sep).replace("/", os.sep)
    if not entry.is_file():
        return None

    # The shim itself prefers a node.exe sitting beside it before falling back
    # to PATH; mirror that so a bundled node keeps winning.
    local_node = shim.parent / "node.exe"
    node = str(local_node) if local_node.is_file() else shutil.which("node")
    if not node:
        return None

    return [node, str(entry)]


def _reject_cmd_metacharacters(target: str, args: list[str]) -> None:
    """Raise if any part of a cmd.exe-bound invocation would be reinterpreted."""
    for value in (target, *args):
        bad = sorted(_CMD_METACHARACTERS.intersection(value))
        if bad:
            raise UnsafeCommandError(
                f"refusing to run Windows script shim {target!r}: argument "
                f"{value!r} contains cmd.exe metacharacter(s) {''.join(bad)!r} "
                "that cmd.exe would execute as a command. Install the tool as a "
                "native executable, or move the input to a path without these "
                "characters."
            )


def resolve_and_wrap_cmd(
    cmd: list[str],
    *,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """Resolve ``cmd[0]`` to a directly-executable program.

    On Windows a ``.cmd``/``.bat`` shim cannot be handed to CreateProcessW
    (WinError 193), and routing it through ``cmd.exe /c`` re-exposes every
    argument to the shell - a path such as ``target.zip&whoami`` becomes two
    commands. Since REDACTS passes attacker-influenced paths from the archive
    under analysis, that is a command-injection sink.

    Resolution order on Windows:

    1. Not a script shim - return the resolved path unchanged (the common case:
       ``trivy.exe``, ``yara.exe``, and pip console scripts such as
       ``semgrep.exe``, which are real PE launchers).
    2. An npm ``.cmd`` wrapper - rewrite to ``[node, entry.cjs, *args]`` so the
       shell is never involved.
    3. Any other batch wrapper - cmd.exe is unavoidable, so refuse arguments it
       would reinterpret rather than emit an injectable command line.

    ``.ps1`` is deliberately unsupported: running one requires an
    ``-ExecutionPolicy Bypass`` that we are not willing to issue implicitly.

    Raises:
        UnsafeCommandError: when the invocation cannot be made safely.
    """
    if not cmd:
        return cmd

    exe_name = str(cmd[0])
    args = [str(a) for a in cmd[1:]]

    path_str = env.get("PATH") if env is not None else None
    if path_str is None:
        path_str = os.environ.get("PATH", "")

    resolved = shutil.which(exe_name, path=path_str) if path_str else shutil.which(exe_name)
    target = resolved or exe_name

    if not _is_windows():
        return [target, *args]

    target_lower = target.lower()

    if target_lower.endswith(".ps1"):
        raise UnsafeCommandError(
            f"refusing to run PowerShell script {target!r}: executing it would "
            "require bypassing the machine's execution policy. Install the tool "
            "as a native executable instead."
        )

    if not target_lower.endswith((".cmd", ".bat")):
        return [target, *args]

    npm_invocation = _resolve_npm_shim(Path(target))
    if npm_invocation is not None:
        return [*npm_invocation, *args]

    _reject_cmd_metacharacters(target, args)
    comspec = (env.get("COMSPEC") if env is not None else None) or os.environ.get(
        "COMSPEC", "cmd.exe"
    )
    return [comspec, "/d", "/c", target, *args]


__all__ = [
    "build",
    "minimal_env",
    "resolve_and_wrap_cmd",
    "UnsafeCommandError",
]
