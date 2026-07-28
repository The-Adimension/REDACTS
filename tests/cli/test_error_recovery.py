"""Unit tests for Progressive Flag Disclosure (R7) and Guided Error Recovery (R7).

Tests argument group structure in `python main.py scan --help`, CLI flag overrides
of runtime contract configuration, and structured guided error recovery blocks
for various failure modes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dataclasses import replace
import pytest

from main import build_parser, _apply_cli_overrides
from static.cli.error_recovery import (
    ErrorRecoveryBlock,
    format_error_recovery,
    format_exception_recovery,
    handle_error,
)
from static.core import runtime_context
from static.core.contract import (
    CaseConfigError,
    FrozenCaseContract,
    InputArtifact,
    InputsConfig,
    StaticConfig,
)
from static.core.network import NetworkDisabledError


# --- 1. Progressive Flag Disclosure in scan --help ---


def test_scan_help_displays_common_and_advanced_option_groups() -> None:
    """Assert `python main.py scan --help` displays 'Common Options' and 'Advanced Options' section headers."""
    parser = build_parser()
    subparsers_actions = [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]
    assert subparsers_actions, "Subparser action not found"
    scan_help = subparsers_actions[0].choices["scan"].format_help()


    assert "Common Options:" in scan_help
    assert "Advanced / Tuning Options:" in scan_help or "Advanced Options:" in scan_help

    # Common options flags
    assert "--target" in scan_help
    assert "--reference" in scan_help
    assert "--mode" in scan_help

    # Advanced options flags
    assert "--severity-gate" in scan_help
    assert "--parallel-workers" in scan_help
    assert "--timeout" in scan_help or "--global-timeout-seconds" in scan_help


def test_scan_parser_accepts_common_and_advanced_flags() -> None:
    """Assert scan parser correctly parses common and advanced flags."""
    parser = build_parser()
    args = parser.parse_args([
        "scan",
        "--target", "custom_target.zip",
        "--reference", "custom_ref.zip",
        "--mode", "full",
        "--severity-gate", "critical",
        "--parallel-workers", "8",
        "--timeout", "300",
    ])

    assert args.command == "scan"
    assert args.target == Path("custom_target.zip")
    assert args.reference == Path("custom_ref.zip")
    assert args.mode == "full"
    assert args.severity_gate == "critical"
    assert args.parallel_workers == 8
    assert args.global_timeout_seconds == 300


# --- 2. CLI Argument Contract Overrides ---


def test_apply_cli_overrides_updates_installed_contract(tmp_path: Path) -> None:
    """Assert _apply_cli_overrides updates runtime_context contract with CLI flags."""
    target_p = tmp_path / "tgt.zip"
    target_p.write_bytes(b"target_data")
    ref_p = tmp_path / "ref.zip"
    ref_p.write_bytes(b"ref_data")

    # Create dummy contract
    from types import SimpleNamespace
    dummy_target = InputArtifact(path=tmp_path / "old_tgt.zip", sha256="")
    dummy_ref = InputArtifact(path=tmp_path / "old_ref.zip", sha256="")
    dummy_inputs = InputsConfig(target=dummy_target, reference=dummy_ref, upgrade_package=None)
    dummy_static = StaticConfig(
        enabled=True,
        scanners=("semgrep",),
        formats=("json",),
        severity_gate="low",
        max_total_files=1000,
        parallel_workers=2,
        global_timeout_seconds=600,
    )

    contract = SimpleNamespace(
        schema_version=2,
        inputs=dummy_inputs,
        static=dummy_static,
    )

    # Wrap as FrozenCaseContract or mock
    fake_contract = replace(
        FrozenCaseContract(
            schema_version=2,
            case=SimpleNamespace(id="case-1", analyst="a", organization="o", date="d", description="desc"),  # type: ignore
            paths=SimpleNamespace(),  # type: ignore
            inputs=dummy_inputs,
            static=dummy_static,
            dynamic=SimpleNamespace(enabled=False),  # type: ignore
            threat_base=SimpleNamespace(),  # type: ignore
            tools=SimpleNamespace(),  # type: ignore
            nix=SimpleNamespace(),  # type: ignore
            security=SimpleNamespace(),  # type: ignore
            logging=SimpleNamespace(),  # type: ignore
            source_path=tmp_path / "case.toml",
            source_sha256="abc",
            loaded_at_utc="2026-01-01T00:00:00Z",
        ),
        inputs=dummy_inputs,
        static=dummy_static,
    )

    parser = build_parser()
    args = parser.parse_args([
        "scan",
        "--target", str(target_p),
        "--reference", str(ref_p),
        "--severity-gate", "high",
        "--parallel-workers", "16",
        "--global-timeout-seconds", "900",
    ])

    # Pure: returns a new contract rather than swapping the installed one, so
    # the caller can verify the lockfile against the overridden result.
    updated = _apply_cli_overrides(fake_contract, args)

    assert updated is not fake_contract
    assert fake_contract.inputs.target.path == tmp_path / "old_tgt.zip"
    assert updated.inputs.target.path == target_p.resolve()
    assert updated.inputs.reference.path == ref_p.resolve()
    assert updated.static.severity_gate == "high"
    assert updated.static.parallel_workers == 16
    assert updated.static.global_timeout_seconds == 900

    runtime_context.reset_contract()


# --- 3. Guided Error Recovery Block ---


def test_error_recovery_block_format_headers() -> None:
    """Assert ErrorRecoveryBlock outputs explicit [WHAT WENT WRONG] and [HOW TO FIX IT] headers."""
    block = ErrorRecoveryBlock(
        title="Test Error",
        what_went_wrong="Something bad happened.",
        how_to_fix=["Run python main.py init", "Check configuration"],
        recommended_command="python main.py init",
        exit_code=1,
    )

    plain = block.render_plain()
    assert "[WHAT WENT WRONG]:" in plain
    assert "[HOW TO FIX IT]:" in plain
    assert "Something bad happened." in plain
    assert "Run python main.py init" in plain
    assert "Recommended command:" in plain.lower() or "[RECOMMENDED COMMAND]:" in plain


def test_format_error_recovery_missing_case_toml() -> None:
    """Assert missing case.toml / CaseConfigError provides guided recovery pointing to `python main.py init`."""
    err = CaseConfigError("case.toml not found")
    block = format_exception_recovery(err)

    assert block.exit_code == 2
    assert "case.toml" in block.what_went_wrong
    assert any("python main.py init" in step for step in block.how_to_fix)
    assert block.recommended_command == "python main.py init"


def test_format_error_recovery_missing_threat_data() -> None:
    """Assert missing threat database error guides to `python main.py update cwe`."""
    block = format_error_recovery("CWE threat database is missing")

    assert "threat" in block.what_went_wrong.lower() or "cwe" in block.what_went_wrong.lower()
    assert any("python main.py update cwe" in step for step in block.how_to_fix)
    assert block.recommended_command == "python main.py update cwe"


def test_format_error_recovery_missing_semgrep() -> None:
    """Assert missing Semgrep dependency guides to `pip install semgrep`."""
    block = format_error_recovery("semgrep scanner not found on PATH")

    assert "semgrep" in block.what_went_wrong.lower()
    assert any("pip install semgrep" in step for step in block.how_to_fix)
    assert block.recommended_command == "pip install semgrep"


def test_format_error_recovery_missing_trivy() -> None:
    """Assert missing Trivy dependency guides to `winget install AquaSecurity.Trivy` or preflight install."""
    block = format_error_recovery("trivy vulnerability scanner not found")

    assert "trivy" in block.what_went_wrong.lower()
    assert any("winget install AquaSecurity.Trivy" in step or "preflight --install" in step for step in block.how_to_fix)


def test_format_error_recovery_file_not_found() -> None:
    """Assert FileNotFoundError produces structured error recovery block."""
    err = FileNotFoundError("target.zip not found")
    block = format_error_recovery(err)

    assert "target.zip" in block.what_went_wrong
    assert len(block.how_to_fix) > 0


def test_format_error_recovery_timeout() -> None:
    """Assert TimeoutError guides to increasing scan timeout."""
    err = TimeoutError("Global scan timeout (600s) exceeded")
    block = format_error_recovery(err)

    assert "timeout" in block.what_went_wrong.lower()
    assert any("timeout" in step.lower() for step in block.how_to_fix)


def test_format_error_recovery_network_disabled() -> None:
    """Assert NetworkDisabledError guides to offline update or case.toml configuration."""
    err = NetworkDisabledError("Network access is disabled")
    block = format_error_recovery(err)

    assert "network" in block.what_went_wrong.lower()
    assert any("python main.py update cwe" in step for step in block.how_to_fix)


def test_format_error_recovery_severity_gate() -> None:
    """Assert severity gate exit code 2 produces guided error recovery block."""
    block = format_error_recovery(2)

    assert block.exit_code == 2
    assert "severity" in block.what_went_wrong.lower() or "gate" in block.what_went_wrong.lower()
    assert any("--severity-gate" in step for step in block.how_to_fix)


def test_handle_error_displays_to_stderr(capsys: pytest.CaptureFixture) -> None:
    """Assert handle_error outputs guided error recovery block to stderr."""
    rc = handle_error("Test failure message")
    assert rc == 1

    captured = capsys.readouterr()
    assert "[WHAT WENT WRONG]:" in captured.err
    assert "[HOW TO FIX IT]:" in captured.err
    assert "Test failure message" in captured.err
