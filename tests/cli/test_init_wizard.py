"""
Tests for R2 Interactive Contract Builder (main.py init) and R3 Auto-Download Threat Data logic.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import tomllib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from static.cli.init_wizard import (
    detect_scanners,
    generate_case_toml,
    run_init_wizard,
)
from static.__main__ import warn_if_cwe_data_missing
from static.core.contract import load_and_freeze


from static.core import runtime_context


class TestInitWizard:
    """Unit tests for static.cli.init_wizard and main.py init integration."""

    @pytest.fixture(autouse=True)
    def reset_contract_fixture(self) -> None:
        runtime_context.reset_contract()
        yield
        runtime_context.reset_contract()

    def test_detect_scanners_always_includes_regex(self) -> None:
        scanners = detect_scanners()
        assert "regex" in scanners
        assert isinstance(scanners, list)

    def test_generate_case_toml_schema_version_2(self, tmp_path: Path) -> None:
        target_f = tmp_path / "target.zip"
        target_f.write_bytes(b"dummy target content")
        target_sha = hashlib.sha256(b"dummy target content").hexdigest()

        ref_f = tmp_path / "ref.zip"
        ref_f.write_bytes(b"dummy reference content")
        ref_sha = hashlib.sha256(b"dummy reference content").hexdigest()

        toml_str = generate_case_toml(
            case_id="CASE-TEST-001",
            analyst="Test Analyst",
            organization="Test Org",
            target_path=str(target_f),
            target_sha256=target_sha,
            reference_path=str(ref_f),
            reference_sha256=ref_sha,
            scanners=["regex", "yara"],
        )

        parsed = tomllib.loads(toml_str)
        assert parsed["schema_version"] == 2
        assert parsed["case"]["id"] == "CASE-TEST-001"
        assert parsed["case"]["analyst"] == "Test Analyst"
        assert parsed["case"]["organization"] == "Test Org"
        assert parsed["inputs"]["target"]["path"] == str(target_f).replace("\\", "/")
        assert parsed["inputs"]["target"]["sha256"] == target_sha
        assert parsed["inputs"]["reference"]["path"] == str(ref_f).replace("\\", "/")
        assert parsed["inputs"]["reference"]["sha256"] == ref_sha
        assert parsed["static"]["scanners"] == ["regex", "yara"]

    def test_run_init_wizard_non_interactive_file_targets(self, tmp_path: Path) -> None:
        target_f = tmp_path / "my_target.zip"
        target_f.write_bytes(b"target payload data")
        ref_f = tmp_path / "my_reference.zip"
        ref_f.write_bytes(b"reference payload data")

        out_case = tmp_path / "case.toml"

        args = argparse.Namespace(
            target=target_f,
            reference=ref_f,
            case_id="CASE-2026-9999",
            analyst="Jane Doe",
            organization="CyberSec Inc",
            output=out_case,
            yes=True,
            non_interactive=True,
        )

        rc = run_init_wizard(args)
        assert rc == 0
        assert out_case.is_file()

        # Validate with load_and_freeze
        contract = load_and_freeze(out_case)
        assert contract.schema_version == 2
        assert contract.case.id == "CASE-2026-9999"
        assert contract.case.analyst == "Jane Doe"
        assert contract.case.organization == "CyberSec Inc"
        assert contract.inputs.target.sha256 == hashlib.sha256(b"target payload data").hexdigest()
        assert contract.inputs.reference.sha256 == hashlib.sha256(b"reference payload data").hexdigest()

    def test_run_init_wizard_directory_targets(self, tmp_path: Path) -> None:
        target_d = tmp_path / "target_dir"
        target_d.mkdir()
        ref_d = tmp_path / "ref_dir"
        ref_d.mkdir()

        out_case = tmp_path / "case.toml"

        args = argparse.Namespace(
            target=target_d,
            reference=ref_d,
            case_id="CASE-DIR-001",
            analyst="Dir Analyst",
            organization="Org",
            output=out_case,
            yes=True,
        )

        rc = run_init_wizard(args)
        assert rc == 0
        contract = load_and_freeze(out_case)
        assert contract.inputs.target.sha256 == ""
        assert contract.inputs.reference.sha256 == ""

    def test_main_init_command_line_parsing(self, tmp_path: Path) -> None:
        import main as main_mod

        target_f = tmp_path / "tgt.zip"
        target_f.write_bytes(b"tgt")
        ref_f = tmp_path / "ref.zip"
        ref_f.write_bytes(b"ref")
        out_case = tmp_path / "case.toml"

        parser = main_mod.build_parser()
        ns = parser.parse_args([
            "init",
            "--target", str(target_f),
            "--reference", str(ref_f),
            "--case-id", "CASE-CLI-100",
            "--analyst", "CLI Tester",
            "--organization", "TestCorp",
            "-o", str(out_case),
            "--yes",
        ])

        assert ns.command == "init"
        assert hasattr(ns, "func")

        rc = ns.func(ns)
        assert rc == 0
        assert out_case.is_file()
        contract = load_and_freeze(out_case)
        assert contract.case.id == "CASE-CLI-100"

    def test_main_init_with_corrupt_case_toml_in_cwd(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Verify main.py init succeeds even when an invalid case.toml exists in CWD."""
        import main as main_mod

        # Create invalid case.toml in CWD
        corrupt_toml = tmp_path / "case.toml"
        corrupt_toml.write_text("[corrupt\ninvalid_key = {{{", encoding="utf-8")

        # Stage real inputs: the wizard refuses to invent missing evidence.
        (tmp_path / "tgt.zip").write_bytes(b"target payload")
        (tmp_path / "ref.zip").write_bytes(b"reference payload")

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "sys.argv",
            [
                "main.py",
                "init",
                "--target",
                "tgt.zip",
                "--reference",
                "ref.zip",
                "--case-id",
                "CASE-CORRUPT-TEST",
                "--yes",
            ],
        )

        # main() should skip _install_contract and run init cleanly
        rc = main_mod.main()
        assert rc == 0
        assert corrupt_toml.is_file()
        contract = load_and_freeze(corrupt_toml)
        assert contract.case.id == "CASE-CORRUPT-TEST"

    def test_main_preflight_trailing_case_arg(self) -> None:
        """Verify trailing --case is accepted by subcommands such as preflight."""
        import main as main_mod

        parser = main_mod.build_parser()
        ns = parser.parse_args(["preflight", "--case", "custom_case.toml"])
        assert ns.command == "preflight"
        assert ns.case == Path("custom_case.toml")

    def test_run_init_wizard_output_subdirectory(self, tmp_path: Path) -> None:
        """Verify relative target paths resolve against output_dir, not the CWD."""
        sub_dir = tmp_path / "subworkspace"
        (sub_dir / "inputs").mkdir(parents=True)
        (sub_dir / "inputs" / "target.zip").write_bytes(b"target payload")
        (sub_dir / "inputs" / "reference.zip").write_bytes(b"reference payload")
        out_case = sub_dir / "case.toml"

        args = argparse.Namespace(
            target=Path("inputs/target.zip"),
            reference=Path("inputs/reference.zip"),
            case_id="CASE-SUBDIR-001",
            analyst="Sub Analyst",
            organization="Sub Org",
            output=out_case,
            yes=True,
            non_interactive=True,
        )

        rc = run_init_wizard(args)
        assert rc == 0
        assert out_case.is_file()

        # Contract load_and_freeze should pass cleanly, resolving the relative
        # input paths against the case file's own directory.
        contract = load_and_freeze(out_case)
        assert contract.case.id == "CASE-SUBDIR-001"
        assert contract.inputs.target.path == (sub_dir / "inputs" / "target.zip").resolve()
        assert (
            contract.inputs.target.sha256
            == hashlib.sha256(b"target payload").hexdigest()
        )


class TestThreatAutoDownload:
    """The scan-path CWE notice must be non-interactive and never download.

    ``static.__main__`` is on the non-interactive scan-path allowlist. The
    notice informs the operator that enrichment will be reduced and how to fix
    it, then continues - it must never prompt, block, or reach out to MITRE.
    """

    def test_present_data_is_a_silent_no_op(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        (tmp_path / "cwec_v4.19.csv").write_text("CWE-ID,Name\n1,Test", encoding="utf-8")
        monkeypatch.setattr("threat_base.cwe_database._DATA_DIR", tmp_path)

        console_mock = MagicMock()
        warn_if_cwe_data_missing(console_mock, MagicMock())

        console_mock.print.assert_not_called()

    def test_missing_data_never_downloads(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("threat_base.cwe_database._DATA_DIR", tmp_path)

        update_mock = MagicMock()
        monkeypatch.setattr("threat_base.updater.update_cwe", update_mock)
        monkeypatch.setattr(
            "static.core.network.assert_network_allowed", lambda url, label="": None
        )

        contract = MagicMock()
        contract.security.network_disabled = False
        warn_if_cwe_data_missing(MagicMock(), contract)

        update_mock.assert_not_called()

    def test_missing_data_never_calls_input(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The crash this replaced: input() with no TTY raised EOFError mid-scan."""
        monkeypatch.setattr("threat_base.cwe_database._DATA_DIR", tmp_path)
        monkeypatch.setattr(
            "static.core.network.assert_network_allowed", lambda url, label="": None
        )

        def _boom(*_args, **_kwargs):  # pragma: no cover - must never run
            raise AssertionError("scan path must not call input()")

        monkeypatch.setattr("builtins.input", _boom)

        contract = MagicMock()
        contract.security.network_disabled = False
        warn_if_cwe_data_missing(MagicMock(), contract)  # must not raise

    def test_missing_data_advises_automatic_update_when_network_allowed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("threat_base.cwe_database._DATA_DIR", tmp_path)
        monkeypatch.setattr(
            "static.core.network.assert_network_allowed", lambda url, label="": None
        )

        printed: list[str] = []
        console_mock = MagicMock()
        console_mock.print.side_effect = lambda msg, *a, **k: printed.append(str(msg))

        contract = MagicMock()
        contract.security.network_disabled = False
        warn_if_cwe_data_missing(console_mock, contract)

        blob = "\n".join(printed)
        assert "python main.py update cwe" in blob
        assert "Reduced CWE enrichment" in blob

    def test_missing_data_omits_automatic_update_when_network_disabled(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setattr("threat_base.cwe_database._DATA_DIR", tmp_path)

        printed: list[str] = []
        console_mock = MagicMock()
        console_mock.print.side_effect = lambda msg, *a, **k: printed.append(str(msg))

        contract = MagicMock()
        contract.security.network_disabled = True
        warn_if_cwe_data_missing(console_mock, contract)

        blob = "\n".join(printed)
        # Automatic path is useless offline; the manual path must still appear.
        assert "network_disabled" in blob
        assert "Manual" in blob
