"""Tests for contract-driven path resolution in ``static.core.paths``.

Paths are sourced from the active :class:`FrozenCaseContract` when one
has been installed via :mod:`static.core.runtime_context`, and fall back
to ``~/.redacts`` otherwise. ``REDACTS_HOME`` / ``REDACTS_OUTPUT_DIR``
/ etc. environment-variable overrides are not consulted.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from static.core import paths, runtime_context
from static.core.contract import load_and_freeze


@pytest.fixture(autouse=True)
def _reset_context():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


# --- defaults (no contract) -------


class TestDefaults:
    def test_redacts_home_default(self):
        assert paths.redacts_home() == (Path.home() / ".redacts").resolve()

    def test_output_dir_default(self):
        assert paths.output_dir() == (Path.home() / ".redacts" / "output").resolve()

    def test_tools_dir_default(self):
        assert paths.tools_dir() == (Path.home() / ".redacts" / "tools").resolve()

    def test_temp_dir_default(self):
        assert paths.temp_dir() == (Path.home() / ".redacts" / "tmp").resolve()

    def test_cache_dir_default(self):
        assert paths.cache_dir() == (Path.home() / ".redacts" / "cache").resolve()

    def test_env_vars_no_longer_honoured(self, monkeypatch):
        # Even setting REDACTS_HOME must NOT change the resolved path.
        monkeypatch.setenv("REDACTS_HOME", "/should/be/ignored")
        monkeypatch.setenv("REDACTS_OUTPUT_DIR", "/should/be/ignored")
        assert paths.redacts_home() == (Path.home() / ".redacts").resolve()
        assert paths.output_dir() == (Path.home() / ".redacts" / "output").resolve()


# --- contract-driven ---------------


class TestContractDriven:
    def test_paths_come_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        assert paths.redacts_home() == contract.paths.workspace_root.resolve()
        assert paths.output_dir() == contract.paths.output_root.resolve()
        assert paths.tools_dir() == contract.paths.tools_root.resolve()
        assert paths.temp_dir() == contract.paths.temp_root.resolve()
        assert paths.cache_dir() == contract.paths.cache_root.resolve()


# --- resolved() snapshot ----------


class TestResolvedSnapshot:
    def test_default_snapshot_shape(self):
        snap = paths.resolved()
        assert set(snap.keys()) == {"home", "output", "tools", "temp", "cache"}
        for entry in snap.values():
            assert set(entry.keys()) == {"path", "source", "exists"}
            assert entry["source"] == "default"

    def test_contract_snapshot_marks_source(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        snap = paths.resolved()
        for entry in snap.values():
            assert entry["source"] == "contract"


# --- inject_tools_on_path --------


class TestInjectToolsOnPath:
    def test_prepends_tools_dir(self, monkeypatch):
        monkeypatch.setenv("PATH", "/x:/y")
        result = paths.inject_tools_on_path()
        assert result.startswith(str(paths.tools_dir()) + os.pathsep)

    def test_idempotent(self, monkeypatch):
        monkeypatch.setenv("PATH", "/x:/y")
        first = paths.inject_tools_on_path()
        second = paths.inject_tools_on_path()
        assert first == second
        # Tools dir appears exactly once.
        td = str(paths.tools_dir())
        assert second.split(os.pathsep).count(td) == 1
