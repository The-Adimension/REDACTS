"""Subprocess-env chokepoint - minimal, explicit, no leakage."""

from __future__ import annotations

import os
import sys

from static.core.contract import (
    FORBIDDEN_ENV_EXACT,
    FORBIDDEN_ENV_PREFIXES,
    load_and_freeze,
)
from static.core.subprocess_env import build


def _is_forbidden(name: str) -> bool:
    return name in FORBIDDEN_ENV_EXACT or name.startswith(FORBIDDEN_ENV_PREFIXES)


def test_build_returns_minimal_env(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    env = build(contract, role="test-runner")
    assert env["PYTHONUNBUFFERED"] == "1"
    assert "PATH" in env
    assert env["TMPDIR"] == str(contract.paths.temp_root)


def test_build_does_not_propagate_forbidden_names(valid_case_factory, isolated_search_paths, monkeypatch):
    monkeypatch.setenv("REDACTS_FORBIDDEN", "leaked")
    monkeypatch.setenv("DAST_ADMIN_PASS", "leaked")
    monkeypatch.setenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", "/leaked")
    case_path = valid_case_factory()
    # NB: load_and_freeze itself would refuse this env, so we pass an
    # explicit clean env here; we are unit-testing ``build``, which is
    # what runs *after* the parent already validated its env.
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    env = build(contract, role="test-runner")
    leaked = [k for k in env if _is_forbidden(k)]
    assert leaked == [], f"leaked forbidden names into child env: {leaked!r}"


def test_case_lock_is_the_only_redacts_var(valid_case_factory, isolated_search_paths, tmp_path):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    lock = tmp_path / "case.lock.json"
    lock.write_text("{}", encoding="utf-8")
    env = build(contract, role="child", case_lock_path=lock)
    redacts_keys = [k for k in env if k.startswith("REDACTS_")]
    assert redacts_keys == ["REDACTS_CASE_LOCK"]
    assert env["REDACTS_CASE_LOCK"] == str(lock.resolve())


def test_extra_pairs_are_passed_through(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    env = build(contract, role="compose", extra={"COMPOSE_FILE": "x.yml"})
    assert env["COMPOSE_FILE"] == "x.yml"


def test_platform_specific_inheritance(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    env = build(contract, role="child")
    if sys.platform == "win32":
        # SystemRoot is required for subprocess to work on Windows.
        if os.environ.get("SystemRoot"):
            assert env.get("SystemRoot") == os.environ["SystemRoot"]
    else:
        if os.environ.get("HOME"):
            assert env.get("HOME") == os.environ["HOME"]


def test_resolve_and_wrap_cmd_empty():
    from static.core.subprocess_env import resolve_and_wrap_cmd
    assert resolve_and_wrap_cmd([]) == []


def test_resolve_and_wrap_cmd_windows_batch(monkeypatch, tmp_path):
    import sys
    from static.core.subprocess_env import resolve_and_wrap_cmd

    cmd_file = tmp_path / "test_tool.cmd"
    cmd_file.write_text("@echo off", encoding="utf-8")

    monkeypatch.setattr(sys, "platform", "win32")
    wrapped = resolve_and_wrap_cmd([str(cmd_file), "arg1"])
    assert len(wrapped) >= 4
    assert wrapped[1:3] == ["/d", "/c"]
    assert wrapped[3] == str(cmd_file)
    assert wrapped[4] == "arg1"


def test_resolve_and_wrap_cmd_windows_batch_space_in_path(monkeypatch, tmp_path):
    import sys
    from static.core.subprocess_env import resolve_and_wrap_cmd

    dir_with_space = tmp_path / "folder with spaces"
    dir_with_space.mkdir()
    cmd_file = dir_with_space / "test_tool.cmd"
    cmd_file.write_text("@echo off", encoding="utf-8")

    monkeypatch.setattr(sys, "platform", "win32")
    wrapped = resolve_and_wrap_cmd([str(cmd_file), "arg with spaces"])
    assert len(wrapped) >= 4
    assert wrapped[1:3] == ["/d", "/c"]
    assert wrapped[3] == str(cmd_file)
    assert wrapped[4] == "arg with spaces"



def test_resolve_and_wrap_cmd_windows_ps1_is_refused(monkeypatch, tmp_path):
    """``.ps1`` is not runnable without ``-ExecutionPolicy Bypass``, so we refuse.

    Issuing that bypass implicitly would let any ``.ps1`` dropped into the
    auto-install tools directory run with the machine's policy disabled.
    """
    import sys

    import pytest

    from static.core.subprocess_env import UnsafeCommandError, resolve_and_wrap_cmd

    ps_file = tmp_path / "script.ps1"
    ps_file.write_text("Write-Output 1", encoding="utf-8")

    monkeypatch.setattr(sys, "platform", "win32")
    with pytest.raises(UnsafeCommandError, match="execution policy"):
        resolve_and_wrap_cmd([str(ps_file), "--flag"])

