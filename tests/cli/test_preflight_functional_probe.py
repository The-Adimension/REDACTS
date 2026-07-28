"""Preflight must verify an external tool actually runs, not just that it exists.

A binary that is present but cannot report its version is broken (e.g. Semgrep
installs on Python 3.14 but its engine exits non-zero with no output). Reporting
such a tool as PASS masks a silent failure and lets a scan proceed with coverage
that never actually ran.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from static.cli import preflight

_TOOL = {
    "name": "semgrep",
    "binary": "semgrep",
    "required": True,
    "description": "AST-based PHP security scanner",
    "install_cmd": "pip install semgrep",
}


def _fake_proc(returncode: int, stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_present_but_nonfunctional_tool_fails(monkeypatch) -> None:
    """--version exits non-zero -> present-but-broken -> not PASS."""
    monkeypatch.setattr(
        "static.scanners.external._resolve_venv_tool", lambda name: r"C:\x\semgrep.exe"
    )
    monkeypatch.setattr(preflight.subprocess, "run", lambda *a, **k: _fake_proc(1, "", ""))

    check = preflight._check_external_tool(_TOOL, tier="BLOCK")

    assert check.passed is False
    assert check.tier == "BLOCK"
    assert "not functional" in check.message


def test_probe_that_raises_is_nonfunctional(monkeypatch) -> None:
    monkeypatch.setattr(
        "static.scanners.external._resolve_venv_tool", lambda name: r"C:\x\semgrep.exe"
    )

    def _boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="semgrep", timeout=10)

    monkeypatch.setattr(preflight.subprocess, "run", _boom)

    check = preflight._check_external_tool(_TOOL, tier="BLOCK")
    assert check.passed is False
    assert "not functional" in check.message


def test_functional_tool_passes(monkeypatch) -> None:
    """--version exits 0 with a version line -> PASS with the version recorded."""
    monkeypatch.setattr(
        "static.scanners.external._resolve_venv_tool", lambda name: r"C:\x\semgrep.exe"
    )
    monkeypatch.setattr(
        preflight.subprocess, "run", lambda *a, **k: _fake_proc(0, "1.100.0\n", "")
    )

    check = preflight._check_external_tool(_TOOL, tier="BLOCK")
    assert check.passed is True
    assert check.version == "1.100.0"


def test_missing_tool_still_reported_not_found(monkeypatch) -> None:
    """A truly absent tool keeps its 'not found' message (distinct from broken)."""
    monkeypatch.setattr("static.scanners.external._resolve_venv_tool", lambda name: None)
    monkeypatch.setattr(preflight.shutil, "which", lambda name: None)

    check = preflight._check_external_tool(_TOOL, tier="BLOCK")
    assert check.passed is False
    assert "not found" in check.message
