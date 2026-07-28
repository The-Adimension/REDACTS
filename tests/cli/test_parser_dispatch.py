"""Argument-parser dispatch invariants for ``main.build_parser`` / ``main.main``.

Two regressions motivated these tests:

* ``redacts --case X <subcommand>`` silently lost ``--case``. argparse parses a
  subcommand into a fresh namespace and copies every key back onto the parent
  namespace, so a subparser ``--case`` carrying a concrete default overwrote the
  top-level value with ``None`` - the scan then ran against ``./case.toml``
  instead of the contract the operator named.
* A bare ``redacts`` (no subcommand) falls back to ``cmd_scan``, which reads
  ``args.mode`` - a flag only the ``scan`` subparser defines - and raised
  ``AttributeError`` before reaching any scan logic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import main


SUBCOMMANDS = ["scan", "preflight", "update", "paths", "init"]


# --- --case must survive subcommand dispatch --


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_case_before_subcommand_is_preserved(subcommand: str) -> None:
    """``--case`` given before the subcommand must reach the namespace."""
    args = main.build_parser().parse_args(["--case", "custom.toml", subcommand])
    assert getattr(args, "case", None) == Path("custom.toml")


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_case_after_subcommand_is_preserved(subcommand: str) -> None:
    """``--case`` given after the subcommand must also reach the namespace."""
    args = main.build_parser().parse_args([subcommand, "--case", "custom.toml"])
    assert getattr(args, "case", None) == Path("custom.toml")


def test_subcommand_case_overrides_top_level_case() -> None:
    """The value nearest the subcommand wins when both positions are used."""
    args = main.build_parser().parse_args(
        ["--case", "outer.toml", "scan", "--case", "inner.toml"]
    )
    assert args.case == Path("inner.toml")


@pytest.mark.parametrize("subcommand", SUBCOMMANDS)
def test_case_defaults_to_none_when_absent(subcommand: str) -> None:
    """Omitting ``--case`` leaves ``None`` so ``_install_contract`` uses ./case.toml."""
    args = main.build_parser().parse_args([subcommand])
    assert getattr(args, "case", None) is None


# --- bare invocation falls back to scan --


def test_bare_invocation_has_no_func_or_mode() -> None:
    """Documents the namespace shape ``main()`` has to compensate for."""
    args = main.build_parser().parse_args([])
    assert not hasattr(args, "func")
    assert not hasattr(args, "mode")


def test_cmd_scan_tolerates_namespace_without_mode() -> None:
    """cmd_scan is the bare-invocation fallback, so ``--mode`` may be absent."""
    args = main.build_parser().parse_args([])
    # Must get past mode resolution; whatever the scan itself does afterwards is
    # not this test's concern, only that no AttributeError escapes.
    try:
        main.cmd_scan(args)
    except AttributeError as exc:  # pragma: no cover - regression guard
        pytest.fail(f"cmd_scan raised AttributeError on a bare namespace: {exc}")
    except Exception:
        pass


def test_main_seeds_mode_before_dispatching_to_cmd_scan(monkeypatch) -> None:
    """``main()`` must set ``args.mode`` when defaulting to ``cmd_scan``."""
    seen: dict[str, object] = {}

    def _fake_cmd_scan(args) -> int:
        seen["mode"] = args.mode
        return 0

    monkeypatch.setattr(main.sys, "argv", ["redacts"])
    monkeypatch.setattr(main, "cmd_scan", _fake_cmd_scan)
    monkeypatch.setattr(main, "_install_contract", lambda case_path, args: False)

    assert main.main() == 0
    assert seen["mode"] is None


def test_main_does_not_fall_back_to_scan_for_explicit_subcommand(monkeypatch) -> None:
    """An explicit subcommand routes through its own ``func``, never ``cmd_scan``."""
    called: list[str] = []

    def _fail_cmd_scan(args) -> int:  # pragma: no cover - regression guard
        pytest.fail("cmd_scan ran for an explicit 'paths' subcommand")

    def _fake_paths(args) -> int:
        called.append("paths")
        return 0

    # ``set_defaults`` captures the function object at parser-build time, so
    # patch the module attribute before build_parser() runs inside main().
    monkeypatch.setattr(main.sys, "argv", ["redacts", "paths"])
    monkeypatch.setattr(main, "cmd_scan", _fail_cmd_scan)
    monkeypatch.setattr(main, "cmd_paths", _fake_paths)
    monkeypatch.setattr(main, "_install_contract", lambda case_path, args: False)

    assert main.main() == 0
    assert called == ["paths"]
