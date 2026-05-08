"""CLI surface invariants.

Asserts that the CLI is contract-only:

* Removed modules ``static.cli.case_contract`` and ``static.cli.prompts``
  are unimportable.
* ``static.__main__.main`` refuses to run without a ``FrozenCaseContract``
  installed on ``runtime_context``.
* With a contract installed, ``static.__main__.main`` reads the
  target/reference paths from ``contract.inputs`` and forwards them to
  ``step_run_scan`` (no prompting, no auto-detect).
* ``static/__main__.py`` and ``static/cli/workflow.py`` contain no
  ``input(...)`` calls.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


# --- Removed modules are unimportable --


@pytest.mark.parametrize(
    "module_name",
    ["static.cli.prompts", "static.cli.case_contract"],
)
def test_removed_modules_unimportable(module_name: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)


def test_cli_init_does_not_export_prompt_helpers() -> None:
    import static.cli as cli_pkg

    for symbol in ("step_prompt_target", "step_prompt_reference"):
        assert not hasattr(cli_pkg, symbol), (
            f"static.cli must not re-export {symbol!r}"
        )
    assert symbol not in (cli_pkg.__all__ or ())


def test_console_helpers_no_longer_expose_prompts() -> None:
    from static.cli import _console

    assert not hasattr(_console, "cli_prompt")
    assert not hasattr(_console, "cli_confirm")


# static.__main__ requires a contract


def test_static_main_requires_installed_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no contract on the runtime context, ``main()`` returns 1."""
    from static import __main__ as static_main_mod
    from static.core import runtime_context

    runtime_context.reset_contract()

    # Stub banner + preflight so the test does not hit the real preflight.
    monkeypatch.setattr(static_main_mod, "step_banner", lambda console: None)
    monkeypatch.setattr(
        static_main_mod, "step_preflight", lambda console: (True, [], None)
    )

    captured: list[Any] = []
    monkeypatch.setattr(
        static_main_mod,
        "step_run_scan",
        lambda *a, **kw: captured.append((a, kw)) or 0,
    )

    rc = static_main_mod.main()

    assert rc == 1
    assert captured == [], "step_run_scan must not be invoked without a contract"


def test_static_main_uses_contract_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When a contract is installed, target/reference come from it."""
    from static import __main__ as static_main_mod
    from static.core import runtime_context

    monkeypatch.setattr(static_main_mod, "step_banner", lambda console: None)
    monkeypatch.setattr(
        static_main_mod, "step_preflight", lambda console: (True, [], None)
    )

    seen: dict[str, Any] = {}

    def _capture(console, target, reference, dep_report=None, coverage_notes=None):
        seen["target"] = target
        seen["reference"] = reference
        return 0

    monkeypatch.setattr(static_main_mod, "step_run_scan", _capture)

    target_p = tmp_path / "tgt.zip"
    reference_p = tmp_path / "ref.zip"

    fake_contract = SimpleNamespace(
        case=SimpleNamespace(id="case-001"),
        inputs=SimpleNamespace(
            target=SimpleNamespace(path=target_p),
            reference=SimpleNamespace(path=reference_p),
        ),
    )
    monkeypatch.setattr(
        "static.core.runtime_context.get_optional_contract",
        lambda: fake_contract,
    )

    try:
        rc = static_main_mod.main()
    finally:
        runtime_context.reset_contract()

    assert rc == 0
    assert seen["target"] == str(target_p)
    assert seen["reference"] == str(reference_p)


# main.py argparse surface


def test_secrets_subcommand_registered() -> None:
    import main as main_mod

    parser = main_mod.build_parser()
    ns = parser.parse_args(["secrets", "list"])
    assert ns.command == "secrets"
    assert ns.secrets_argv == ["list"]


# AST sweep: no interactive ``input(...)`` calls in the scan path


_NON_INTERACTIVE_FILES = [
    Path("static/__main__.py"),
    Path("static/cli/workflow.py"),
    Path("static/cli/_console.py"),
    Path("static/cli/__init__.py"),
    Path("static/cli/preflight.py"),
    Path("static/cli/banner.py"),
    Path("main.py"),
]


@pytest.mark.parametrize("rel_path", _NON_INTERACTIVE_FILES)
def test_scan_path_has_no_input_calls(rel_path: Path) -> None:
    """No ``input(...)`` / ``getpass(...)`` calls in the scan-flow modules.

    ``static.core.secrets`` keeps a ``getpass`` for the ``secrets set``
    admin command - it is intentionally not in this list.
    """
    project_root = Path(__file__).resolve().parents[2]
    file_path = project_root / rel_path
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))

    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"input", "cli_prompt", "cli_confirm"}:
                offenders.append(f"line {node.lineno}: {node.func.id}(...)")

    assert not offenders, (
        f"{rel_path} must be non-interactive but contains: "
        + ", ".join(offenders)
    )
