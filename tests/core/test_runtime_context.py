"""Tests for ``static.core.runtime_context``."""

from __future__ import annotations

import pytest

from static.core import runtime_context
from static.core.contract import load_and_freeze


@pytest.fixture(autouse=True)
def _reset_context():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


def test_get_optional_returns_none_before_set():
    assert runtime_context.get_optional_contract() is None


def test_get_raises_before_set():
    with pytest.raises(RuntimeError, match="no contract installed"):
        runtime_context.get_contract()


def test_set_then_get(valid_case_factory):
    contract = load_and_freeze(valid_case_factory())
    runtime_context.set_contract(contract)
    assert runtime_context.get_contract() is contract
    assert runtime_context.get_optional_contract() is contract


def test_set_same_contract_is_idempotent(valid_case_factory):
    contract = load_and_freeze(valid_case_factory())
    runtime_context.set_contract(contract)
    runtime_context.set_contract(contract)  # no raise
    assert runtime_context.get_contract() is contract


def test_set_different_contract_raises(valid_case_factory):
    a = load_and_freeze(valid_case_factory())
    runtime_context.set_contract(a)
    b = load_and_freeze(
        valid_case_factory(target_bytes=b"different-target\n", case_subdir="case2")
    )
    with pytest.raises(RuntimeError, match="different contract"):
        runtime_context.set_contract(b)


def test_reset_clears(valid_case_factory):
    contract = load_and_freeze(valid_case_factory())
    runtime_context.set_contract(contract)
    runtime_context.reset_contract()
    assert runtime_context.get_optional_contract() is None


def test_set_rejects_non_contract():
    with pytest.raises(TypeError):
        runtime_context.set_contract({"paths": "fake"})  # type: ignore[arg-type]
