"""Offline / air-gapped operation must remain runnable.

``[security].network_disabled = true`` is a supported, deliberate operator
choice, and the tool prints offline remediation steps ("fetch the CWE data on
an internet-connected system, copy it into threat_base/data/") in several
places. If the Layer 5 network probe or the Layer 3c ATT&CK bundle check are
BLOCK-tier, none of that is reachable: preflight refuses to run at all on an
air-gapped workstation, and the advice contradicts itself.

These tests pin the tiering so that cannot silently regress.
"""

from __future__ import annotations

import socket

import pytest

from static.cli import preflight
from static.core import runtime_context
from static.core.contract import load_and_freeze


@pytest.fixture(autouse=True)
def _reset_contract():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


def _install_disabled_contract(valid_case_factory) -> None:
    contract = load_and_freeze(valid_case_factory())
    assert contract.security.network_disabled is True
    runtime_context.set_contract(contract)


# --- Layer 5: network --


def test_network_disabled_is_warn_not_block(valid_case_factory) -> None:
    """An intentional offline configuration must not block the scan."""
    _install_disabled_contract(valid_case_factory)

    check = preflight._check_network_status()

    assert check.tier == "WARN"
    assert check.passed is False


def test_unreachable_network_is_warn_not_block(monkeypatch) -> None:
    """An air-gapped host that never set the flag must still be able to scan."""

    def _offline(*args, **kwargs):
        raise OSError("network unreachable")

    monkeypatch.setattr(socket, "create_connection", _offline)

    check = preflight._check_network_status()

    assert check.tier == "WARN"
    assert check.passed is False
    assert "cached/bundled data" in check.message


def test_network_check_never_blocks_preflight(valid_case_factory) -> None:
    """The network check alone must never make PreflightResult.blocked true."""
    _install_disabled_contract(valid_case_factory)

    result = preflight.PreflightResult(checks=[preflight._check_network_status()])

    assert result.blocked is False
    assert len(result.warn_failures) == 1


# --- Layer 3c: ATT&CK bundle --


@pytest.mark.parametrize("available", [True, False])
def test_attack_bundle_is_warn_tier(monkeypatch, available: bool) -> None:
    """The bundled 34-pattern subset works, so a missing bundle is a warning."""
    import threat_base.prefetch as prefetch

    monkeypatch.setattr(prefetch, "is_attack_data_available", lambda: available)

    check = preflight._check_attack_data()

    assert check.tier == "WARN"
    assert check.passed is available


def test_attack_bundle_check_failure_is_warn(monkeypatch) -> None:
    """Even an erroring ATT&CK probe must not block - the subset still works."""
    import threat_base.prefetch as prefetch

    def _boom():
        raise RuntimeError("cache corrupt")

    monkeypatch.setattr(prefetch, "is_attack_data_available", _boom)

    check = preflight._check_attack_data()

    assert check.tier == "WARN"
    assert check.passed is False


def test_attack_bundle_never_blocks_preflight(monkeypatch) -> None:
    import threat_base.prefetch as prefetch

    monkeypatch.setattr(prefetch, "is_attack_data_available", lambda: False)

    result = preflight.PreflightResult(checks=[preflight._check_attack_data()])

    assert result.blocked is False


# --- tier tracks the tool's ``required`` flag --


def test_optional_tools_are_checked_at_warn_tier() -> None:
    """Checking the WARN list at BLOCK would make 'optional' mean nothing."""
    optional = [t for t in preflight._WARN_EXTERNAL_TOOLS]
    for tool in optional:
        check = preflight._check_external_tool(tool, tier="WARN")
        assert check.tier == "WARN", tool["name"]


def test_required_and_optional_tool_lists_are_disjoint() -> None:
    block_names = {t["name"] for t in preflight._BLOCK_EXTERNAL_TOOLS}
    warn_names = {t["name"] for t in preflight._WARN_EXTERNAL_TOOLS}

    assert not (block_names & warn_names)


# --- DAST-only tools (Docker) are gated by scan mode --


def _docker_missing(monkeypatch) -> None:
    """Make every external-tool probe report the binary as absent."""
    monkeypatch.setattr(preflight.shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "static.scanners.external._resolve_venv_tool", lambda *_a, **_k: None
    )


def _docker_check(result) -> "preflight.PreflightCheck":
    return next(c for c in result.checks if c.name == "docker")


def test_missing_docker_is_warn_for_static_only(monkeypatch) -> None:
    """A static-only run must not be blocked *by Docker* (DAST-only).

    Other tools are forced missing too, so the run as a whole still blocks -
    the point is that Docker is not one of the blockers.
    """
    _docker_missing(monkeypatch)

    result = preflight.run_preflight(
        check_knowledge=False, dynamic_enabled=False
    )

    assert _docker_check(result).tier == "WARN"
    assert "docker" not in {c.name for c in result.block_failures}
    assert "docker" in {c.name for c in result.warn_failures}


def test_missing_docker_blocks_when_dynamic_enabled(monkeypatch) -> None:
    """When DAST will run, Docker returns to a hard BLOCK requirement."""
    _docker_missing(monkeypatch)

    result = preflight.run_preflight(
        check_knowledge=False, dynamic_enabled=True
    )

    assert _docker_check(result).tier == "BLOCK"
    assert "docker" in {c.name for c in result.block_failures}


def _install_contract_with_dynamic(valid_case_factory, *, enabled: bool) -> None:
    """Install a contract whose ``[dynamic].enabled`` is set as requested."""
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    if not enabled:
        text = text.replace("[dynamic]\nenabled = true", "[dynamic]\nenabled = false")
    case_path.write_text(text, encoding="utf-8")
    runtime_context.set_contract(load_and_freeze(case_path))


def test_static_contract_derives_docker_as_warn(monkeypatch, valid_case_factory) -> None:
    """With no explicit flag and a static contract, Docker derives to WARN."""
    _docker_missing(monkeypatch)
    _install_contract_with_dynamic(valid_case_factory, enabled=False)

    result = preflight.run_preflight(check_knowledge=False)  # dynamic_enabled=None

    assert _docker_check(result).tier == "WARN"
    assert "docker" not in {c.name for c in result.block_failures}


def test_dynamic_contract_derives_docker_as_block(monkeypatch, valid_case_factory) -> None:
    """A contract that enables DAST makes Docker a BLOCK, without an explicit flag."""
    _docker_missing(monkeypatch)
    _install_contract_with_dynamic(valid_case_factory, enabled=True)

    result = preflight.run_preflight(check_knowledge=False)  # dynamic_enabled=None

    assert _docker_check(result).tier == "BLOCK"
    assert "docker" in {c.name for c in result.block_failures}


def test_only_docker_is_dast_gated_semgrep_stays_block(monkeypatch) -> None:
    """Static scanners remain BLOCK even in a static-only run."""
    _docker_missing(monkeypatch)

    result = preflight.run_preflight(
        check_knowledge=False, dynamic_enabled=False
    )

    semgrep = next(c for c in result.checks if c.name == "semgrep")
    assert semgrep.tier == "BLOCK"
    assert result.blocked is True  # semgrep missing still blocks
