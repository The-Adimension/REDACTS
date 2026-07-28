"""CLI overrides must not be able to run a configuration the lockfile never covered.

``case.toml.lock`` exists so a run is reproducible: ``verify_lockfile`` refuses
on any drift in the stable surface. CLI flags such as ``--target`` and
``--severity-gate`` change exactly that surface, so the order in which they are
applied decides whether the seal means anything.

Applying overrides *after* verification would let a sealed case run against a
different target than the one it was sealed for, with the lockfile still
reporting a clean verify. ``_install_contract`` therefore applies overrides
first and verifies second, so the existing ``lockfile-drift`` refusal covers
them for free.

The other half of this is ``runtime_context``: the contract is installed
exactly once per process, and ``reset_contract()`` is test-only. Overrides must
not reach for it to swap in a mutated copy mid-run.
"""

from __future__ import annotations

import argparse
import inspect
from pathlib import Path

import pytest

import main
from static.core import runtime_context
from static.core.contract import load_and_freeze, write_lockfile


@pytest.fixture(autouse=True)
def _reset_contract():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


def _args(**overrides) -> argparse.Namespace:
    """A scan namespace with only the named override flags set."""
    base = dict(
        case=None,
        target=None,
        reference=None,
        severity_gate=None,
        parallel_workers=None,
        global_timeout_seconds=None,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# --- a sealed case refuses overrides that change the sealed surface --


def test_sealed_case_refuses_target_override(valid_case_factory, tmp_path) -> None:
    case_path = valid_case_factory()
    write_lockfile(load_and_freeze(case_path), Path(str(case_path) + ".lock"))

    other = tmp_path / "other_target.bin"
    other.write_bytes(b"a different evidence artifact")

    with pytest.raises(SystemExit) as exc_info:
        main._install_contract(case_path, _args(target=other))

    assert exc_info.value.code == 2
    assert runtime_context.get_optional_contract() is None


def test_seal_mismatch_does_not_advise_regenerating_the_case(valid_case_factory) -> None:
    """"Run init" would overwrite the case.toml under dispute - never suggest it."""
    from static.cli.error_recovery import format_error_recovery
    from static.core.contract import CaseConfigError

    block = format_error_recovery(
        CaseConfigError("lockfile-drift: case.toml.lock disagrees with the current case.toml")
    )

    assert block.title == "Contract Seal Mismatch"
    assert block.recommended_command != "python main.py init"
    assert not any("main.py init" in step for step in block.how_to_fix)
    assert any("case.toml.lock" in step for step in block.how_to_fix)


def test_sealed_case_refuses_severity_gate_override(valid_case_factory) -> None:
    case_path = valid_case_factory()
    write_lockfile(load_and_freeze(case_path), Path(str(case_path) + ".lock"))

    with pytest.raises(SystemExit) as exc_info:
        main._install_contract(case_path, _args(severity_gate="critical"))

    assert exc_info.value.code == 2


def test_sealed_case_still_installs_without_overrides(valid_case_factory) -> None:
    """The seal must not become a blanket refusal - a clean run still works."""
    case_path = valid_case_factory()
    write_lockfile(load_and_freeze(case_path), Path(str(case_path) + ".lock"))

    assert main._install_contract(case_path, _args()) is True
    assert runtime_context.get_optional_contract() is not None


# --- an unsealed case accepts overrides --


def test_unsealed_case_accepts_target_override(valid_case_factory, tmp_path) -> None:
    case_path = valid_case_factory()
    assert not Path(str(case_path) + ".lock").exists()

    other = tmp_path / "other_target.bin"
    other.write_bytes(b"a different evidence artifact")

    assert main._install_contract(case_path, _args(target=other)) is True

    contract = runtime_context.get_contract()
    assert contract.inputs.target.path == other.resolve()


def test_override_recomputes_sha256_of_new_target(valid_case_factory, tmp_path) -> None:
    """A swapped-in artifact must carry its own digest, not the sealed one."""
    import hashlib

    case_path = valid_case_factory()
    original_sha = load_and_freeze(case_path).inputs.target.sha256

    payload = b"a different evidence artifact"
    other = tmp_path / "other_target.bin"
    other.write_bytes(payload)

    main._install_contract(case_path, _args(target=other))

    contract = runtime_context.get_contract()
    assert contract.inputs.target.sha256 == hashlib.sha256(payload).hexdigest()
    assert contract.inputs.target.sha256 != original_sha


# --- the override helper stays pure --


def test_apply_cli_overrides_does_not_touch_runtime_context(valid_case_factory) -> None:
    contract = load_and_freeze(valid_case_factory())

    updated = main._apply_cli_overrides(contract, _args(severity_gate="critical"))

    assert updated.static.severity_gate == "critical"
    assert contract.static.severity_gate != "critical"  # original untouched
    assert runtime_context.get_optional_contract() is None  # nothing installed


def test_apply_cli_overrides_returns_same_object_when_no_flags(valid_case_factory) -> None:
    contract = load_and_freeze(valid_case_factory())
    assert main._apply_cli_overrides(contract, _args()) is contract


def test_production_code_does_not_call_reset_contract() -> None:
    """``reset_contract()`` is documented test-only; main.py must not call it.

    Checked against the AST rather than the raw text so prose mentioning the
    function (such as the comment explaining *why* it is not called) does not
    trip the assertion.
    """
    import ast

    tree = ast.parse(inspect.getsource(main))
    called = {
        node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, (ast.Attribute, ast.Name))
    }

    assert "reset_contract" not in called


def test_contract_is_installed_exactly_once(valid_case_factory, monkeypatch) -> None:
    """A second differing set_contract() raises; overrides must not trigger it."""
    calls: list[object] = []
    real_set = runtime_context.set_contract

    def _counting_set(contract):
        calls.append(contract)
        return real_set(contract)

    monkeypatch.setattr(runtime_context, "set_contract", _counting_set)

    case_path = valid_case_factory()
    main._install_contract(case_path, _args(severity_gate="critical"))

    assert len(calls) == 1


# --- streamed hashing --


def test_file_sha256_matches_hashlib_and_streams(tmp_path) -> None:
    import hashlib

    blob = tmp_path / "big.bin"
    payload = b"x" * (3 * 1024 * 1024 + 17)  # spans several read chunks
    blob.write_bytes(payload)

    assert main._file_sha256(blob) == hashlib.sha256(payload).hexdigest()


def test_file_sha256_handles_empty_file(tmp_path) -> None:
    import hashlib

    blob = tmp_path / "empty.bin"
    blob.write_bytes(b"")

    assert main._file_sha256(blob) == hashlib.sha256(b"").hexdigest()
