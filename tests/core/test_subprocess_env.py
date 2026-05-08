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
