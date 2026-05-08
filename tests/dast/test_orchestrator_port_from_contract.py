"""Orchestrator port resolution comes from the contract."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from dynamic.orchestrator import DASTOrchestrator
from static.core import runtime_context


@pytest.fixture(autouse=True)
def _isolate_contract():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


@pytest.fixture(autouse=True)
def _skip_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        DASTOrchestrator, "_preflight_dast", lambda self: None, raising=True
    )


def _stub_contract(port: int):
    """Minimal duck-typed object exposing only ``.dynamic.port``."""
    return SimpleNamespace(dynamic=SimpleNamespace(port=port))


def test_orchestrator_uses_contract_port_when_no_arg(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        runtime_context, "get_optional_contract", lambda: _stub_contract(9999)
    )
    orch = DASTOrchestrator(output_dir=str(tmp_path / "out"))
    assert orch.dast_port == 9999


def test_explicit_arg_overrides_contract_port(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        runtime_context, "get_optional_contract", lambda: _stub_contract(9999)
    )
    orch = DASTOrchestrator(output_dir=str(tmp_path / "out"), dast_port=7000)
    assert orch.dast_port == 7000


def test_no_contract_falls_back_to_8585(tmp_path: Path) -> None:
    orch = DASTOrchestrator(output_dir=str(tmp_path / "out"))
    assert orch.dast_port == 8585


def test_redcap_version_no_env_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setting REDCAP_VERSION in the parent must NOT leak into the orchestrator."""
    monkeypatch.setenv("REDCAP_VERSION", "99.99.99")
    orch = DASTOrchestrator(output_dir=str(tmp_path / "out"))
    assert orch.redcap_version == ""

    orch2 = DASTOrchestrator(
        output_dir=str(tmp_path / "out"), redcap_version="16.1.2"
    )
    assert orch2.redcap_version == "16.1.2"
