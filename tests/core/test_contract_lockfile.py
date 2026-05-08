"""Lockfile reproducibility (strict drift refusal)."""

from __future__ import annotations

import json

import pytest

from static.core.contract import (
    CaseConfigError,
    load_and_freeze,
    verify_lockfile,
    write_lockfile,
)


def test_serialization_is_deterministic_across_loads(valid_case_factory, isolated_search_paths, tmp_path):
    case_path = valid_case_factory()
    a = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    b = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)

    lock_a = tmp_path / "a.lock.json"
    lock_b = tmp_path / "b.lock.json"
    write_lockfile(a, lock_a)
    write_lockfile(b, lock_b)

    stable_a = json.loads(lock_a.read_text(encoding="utf-8"))["stable"]
    stable_b = json.loads(lock_b.read_text(encoding="utf-8"))["stable"]
    assert stable_a == stable_b


def test_verify_lockfile_passes_on_unchanged_contract(valid_case_factory, isolated_search_paths, tmp_path):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    lock = tmp_path / "case.lock.json"
    write_lockfile(contract, lock)
    # Re-load and verify (the source SHA is identical).
    contract2 = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    verify_lockfile(contract2, lock)  # no exception


def test_verify_lockfile_refuses_on_drift(valid_case_factory, isolated_search_paths, tmp_path):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    lock = tmp_path / "case.lock.json"
    write_lockfile(contract, lock)

    # Mutate case.toml in a behaviour-affecting way.
    text = case_path.read_text(encoding="utf-8")
    text = text.replace('port = 8585', 'port = 9999', 1)
    case_path.write_text(text, encoding="utf-8")
    drifted = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)

    with pytest.raises(CaseConfigError, match="lockfile-drift"):
        verify_lockfile(drifted, lock)


def test_verify_lockfile_no_op_when_missing(valid_case_factory, isolated_search_paths, tmp_path):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    verify_lockfile(contract, tmp_path / "does-not-exist.json")  # silent
