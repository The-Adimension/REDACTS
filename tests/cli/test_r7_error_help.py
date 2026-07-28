"""Tests for Requirement R7: Progressive Flag Disclosure & Guided Error Recovery."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
import pytest

from main import build_parser, _install_contract


def _no_override_args():
    """A namespace with no override flags set."""
    return build_parser().parse_args(["scan"])
from static.cli.error_recovery import ErrorRecoveryBlock, format_exception_recovery
from static.core.contract import CaseConfigError


def test_main_help_contains_grouped_options() -> None:
    parser = build_parser()
    help_text = parser.format_help()
    assert "Common Options:" in help_text
    assert "Subcommands:" in help_text
    assert "--case" in help_text


def test_scan_help_contains_common_and_advanced_options() -> None:
    parser = build_parser()
    scan_parser = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            scan_parser = action.choices["scan"]
            break
    assert scan_parser is not None
    help_text = scan_parser.format_help()
    assert "Common Options:" in help_text
    assert "Advanced Options:" in help_text
    assert "--mode" in help_text



def test_error_recovery_block_formatting() -> None:
    block = ErrorRecoveryBlock(
        title="Test Error",
        what_went_wrong="Something failed catastrophically.",
        how_to_fix=["Step 1 fix it", "Step 2 verify it"],
        recommended_command="python main.py scan",
        exit_code=1,
    )
    plain = block.render_plain()
    assert "TEST ERROR" in plain
    assert "what went wrong" in plain.lower()
    assert "Something failed catastrophically." in plain
    assert "how to fix" in plain.lower()
    assert "Step 1 fix it" in plain
    assert "Step 2 verify it" in plain
    assert "recommended command" in plain.lower()
    assert "$ python main.py scan" in plain


def test_format_exception_recovery_case_config_error() -> None:
    exc = CaseConfigError("Missing required key [case].id")
    block = format_exception_recovery(exc)
    assert block.title == "Configuration Contract Error"
    assert "Missing required key [case].id" in block.what_went_wrong
    assert len(block.how_to_fix) > 0
    assert block.recommended_command == "python main.py init"
    assert block.exit_code == 2


def test_invalid_contract_displays_error_recovery_block(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    bad_toml = tmp_path / "case.toml"
    bad_toml.write_text("invalid_toml = [", encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        _install_contract(bad_toml, _no_override_args())

    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    err_output = captured.err + captured.out
    assert "what went wrong" in err_output.lower()
    assert "how to fix" in err_output.lower()
    assert "recommended command" in err_output.lower()


def test_missing_contract_static_main_displays_error_recovery_block(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from static import __main__ as static_main_mod
    from static.core import runtime_context

    runtime_context.reset_contract()
    monkeypatch.setattr(static_main_mod, "step_banner", lambda console: None)
    monkeypatch.setattr(
        static_main_mod, "step_preflight", lambda console: (True, [], None)
    )

    rc = static_main_mod.main()
    assert rc == 1
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "what went wrong" in output.lower()
    assert "how to fix" in output.lower()
    assert "recommended command" in output.lower()


def test_explicit_missing_contract_raises_file_not_found(tmp_path: Path) -> None:
    non_existent = tmp_path / "non_existent.toml"
    with pytest.raises(FileNotFoundError) as exc_info:
        _install_contract(non_existent, _no_override_args())
    assert "non_existent.toml" in str(exc_info.value)

