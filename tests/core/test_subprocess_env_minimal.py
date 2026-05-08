"""``subprocess_env.minimal_env`` contract-less builder."""
from __future__ import annotations

import os
import sys

import pytest

from static.core import subprocess_env as _se


def test_minimal_env_does_not_copy_arbitrary_vars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A leaked secret/var must NOT appear in the child env."""
    monkeypatch.setenv("MY_SECRET_TOKEN", "leaked-value")
    monkeypatch.setenv("REDCAP_VERSION", "99.99.99")
    env = _se.minimal_env()
    assert "MY_SECRET_TOKEN" not in env
    assert "REDCAP_VERSION" not in env


def test_minimal_env_includes_path_and_pythonunbuffered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    env = _se.minimal_env()
    assert "PATH" in env
    assert env["PYTHONUNBUFFERED"] == "1"


def test_minimal_env_merges_extra_strings() -> None:
    env = _se.minimal_env(extra={"CUSTOM_FLAG": "1", "FOO": "bar"})
    assert env["CUSTOM_FLAG"] == "1"
    assert env["FOO"] == "bar"


def test_minimal_env_rejects_non_string_extras() -> None:
    with pytest.raises(ValueError):
        _se.minimal_env(extra={"X": 123})  # type: ignore[dict-item]


def test_minimal_env_inherits_platform_basics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Platform-specific OS variables (e.g. SystemRoot, HOME) are inherited."""
    env = _se.minimal_env()
    if sys.platform == "win32":
        # SystemRoot is required by CPython on Windows.
        assert "SystemRoot" in env or "SYSTEMROOT" in {k.upper() for k in env}
    else:
        # HOME is typically required for POSIX child processes.
        if "HOME" in os.environ:
            assert env.get("HOME") == os.environ["HOME"]
