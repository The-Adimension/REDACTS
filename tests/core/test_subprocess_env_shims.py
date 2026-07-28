"""Windows script-shim handling in ``subprocess_env.resolve_and_wrap_cmd``.

Routing a ``.cmd``/``.bat`` shim through ``cmd.exe /c`` re-exposes every
argument to the shell: ``subprocess`` quotes for the MSVCRT argument parser,
but cmd.exe parses the command line first, so an argument such as
``target.zip&whoami`` becomes two commands. REDACTS passes paths taken from the
archive under analysis straight into scanner argv, so that is a
command-injection sink rather than a theoretical one.

The fix resolves npm shims to a direct ``node <entry>`` call and refuses any
remaining shell-bound invocation whose arguments cmd.exe would reinterpret.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from static.core.subprocess_env import (
    UnsafeCommandError,
    _resolve_npm_shim,
    resolve_and_wrap_cmd,
)


IS_WINDOWS = sys.platform == "win32" or os.name == "nt"
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows shim behaviour")

# The payload that demonstrated the original injection. No space, so
# ``list2cmdline`` leaves it unquoted and cmd.exe treats '&' as a separator.
INJECTION_ARG = "target.zip&whoami"


def _write_npm_shim(directory: Path, name: str = "repomix") -> Path:
    """Create an npm-style ``.cmd`` wrapper plus the entry script it names.

    Mirrors the real wrapper npm generates, whose final line is effectively
    ``"%_prog%" "%dp0%\\node_modules\\<pkg>\\bin\\<entry>.cjs" %*``.
    """
    bin_dir = directory / "node_modules" / name / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / f"{name}.cjs").write_text("// entry point\n", encoding="utf-8")

    shim = directory / f"{name}.cmd"
    shim.write_text(
        "@ECHO off\r\n"
        "GOTO start\r\n"
        ":find_dp0\r\n"
        "SET dp0=%~dp0\r\n"
        "EXIT /b\r\n"
        ":start\r\n"
        "SETLOCAL\r\n"
        "CALL :find_dp0\r\n"
        'IF EXIST "%dp0%\\node.exe" (\r\n'
        '  SET "_prog=%dp0%\\node.exe"\r\n'
        ") ELSE (\r\n"
        '  SET "_prog=node"\r\n'
        ")\r\n"
        "endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "
        '"%_prog%"  "%dp0%\\node_modules\\' + name + "\\bin\\" + name + '.cjs" %*\r\n',
        encoding="utf-8",
    )
    return shim


@pytest.fixture()
def npm_tool(tmp_path, monkeypatch):
    """An npm shim on PATH with a stub ``node.exe`` beside it."""
    shim = _write_npm_shim(tmp_path)
    node = tmp_path / ("node.exe" if IS_WINDOWS else "node")
    node.write_text("stub", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    return shim


# --- npm shims resolve to a direct node call --


@windows_only
def test_npm_shim_resolves_to_node_entry_script(npm_tool) -> None:
    argv = resolve_and_wrap_cmd(["repomix", "."])

    assert argv[0].lower().endswith("node.exe")
    assert argv[1].lower().endswith(os.path.join("bin", "repomix.cjs").lower())
    assert argv[2] == "."


@windows_only
def test_npm_shim_never_routes_through_cmd_exe(npm_tool) -> None:
    argv = resolve_and_wrap_cmd(["repomix", INJECTION_ARG])

    assert not any("cmd.exe" in part.lower() for part in argv)
    assert "/c" not in argv


@windows_only
def test_npm_shim_passes_metacharacter_arg_through_intact(npm_tool) -> None:
    """The payload must survive as one inert argv element, not become a command."""
    argv = resolve_and_wrap_cmd(["repomix", INJECTION_ARG])

    assert argv[-1] == INJECTION_ARG
    assert argv.count(INJECTION_ARG) == 1


@windows_only
def test_npm_shim_prefers_sibling_node_over_path(npm_tool, tmp_path) -> None:
    argv = resolve_and_wrap_cmd(["repomix", "."])
    assert Path(argv[0]).parent == tmp_path


def test_resolve_npm_shim_returns_none_for_non_npm_batch(tmp_path) -> None:
    other = tmp_path / "mystery.bat"
    other.write_text("@echo %*\r\n", encoding="utf-8")
    assert _resolve_npm_shim(other) is None


def test_resolve_npm_shim_returns_none_when_entry_missing(tmp_path) -> None:
    shim = _write_npm_shim(tmp_path)
    (tmp_path / "node_modules" / "repomix" / "bin" / "repomix.cjs").unlink()
    assert _resolve_npm_shim(shim) is None


# --- unresolvable shims refuse rather than inject --


@pytest.fixture()
def simulated_windows(monkeypatch):
    """Force the Windows branch so the refusal tests also run on POSIX CI.

    ``resolve_and_wrap_cmd`` reads the platform at call time precisely so this
    works; the injection it guards against is Windows-only, but the guard
    itself should be covered wherever the suite runs.
    """
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(os, "name", "nt")


@pytest.mark.parametrize("metachar", ["&", "|", "<", ">", "^", "(", ")", '"', "%", "!"])
def test_unknown_batch_shim_refuses_cmd_metacharacters(
    tmp_path, simulated_windows, metachar
) -> None:
    shim = tmp_path / "mystery.bat"
    shim.write_text("@echo %*\r\n", encoding="utf-8")

    with pytest.raises(UnsafeCommandError):
        resolve_and_wrap_cmd([str(shim), f"target.zip{metachar}whoami"])


def test_unknown_batch_shim_allows_benign_arguments(tmp_path, simulated_windows) -> None:
    shim = tmp_path / "mystery.bat"
    shim.write_text("@echo %*\r\n", encoding="utf-8")

    argv = resolve_and_wrap_cmd([str(shim), "clean-path.zip"])

    assert argv[1:3] == ["/d", "/c"]
    assert argv[-1] == "clean-path.zip"


def test_refusal_names_the_offending_argument(tmp_path, simulated_windows) -> None:
    """The operator has to be able to tell which input was rejected and why."""
    shim = tmp_path / "mystery.bat"
    shim.write_text("@echo %*\r\n", encoding="utf-8")

    with pytest.raises(UnsafeCommandError) as excinfo:
        resolve_and_wrap_cmd([str(shim), INJECTION_ARG])

    message = str(excinfo.value)
    assert INJECTION_ARG in message
    assert "&" in message


def test_powershell_scripts_are_refused(tmp_path, simulated_windows) -> None:
    script = tmp_path / "tool.ps1"
    script.write_text("Write-Host hi\r\n", encoding="utf-8")

    with pytest.raises(UnsafeCommandError, match="execution policy"):
        resolve_and_wrap_cmd([str(script), "arg"])


# --- end-to-end: the original exploit must not execute --


@windows_only
def test_injection_payload_does_not_execute(tmp_path, monkeypatch) -> None:
    """Full regression: actually run the resolved argv, assert no second command ran.

    The stub ``node.exe`` is a copy of the running interpreter so the launch
    genuinely happens (it then fails to parse the .cjs entry, which is fine).
    What matters is that the marker a successful injection would create never
    appears.
    """
    _write_npm_shim(tmp_path)
    node = tmp_path / "node.exe"
    node.write_bytes(Path(sys.executable).read_bytes())
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))

    # Must be whitespace-free: list2cmdline quotes an argument only when it
    # contains a space or tab, so a spaced payload would be neutralised by
    # quoting alone and would not prove anything about this code path.
    marker = tmp_path / "INJECTED"
    payload = f"target.zip&whoami>{marker}"
    assert " " not in payload

    argv = resolve_and_wrap_cmd(["repomix", payload])
    proc = subprocess.run(argv, capture_output=True, timeout=120)

    assert not marker.exists(), (
        f"injected command executed; argv={argv!r} rc={proc.returncode}"
    )
    # Sanity: the launch really occurred rather than silently no-op'ing.
    assert proc.returncode != 0
