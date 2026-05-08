"""
REDACTS - REDCap Arbitrary Code Threat Scan

Non-interactive scan entry point.

This module is invoked by ``main.py``'s ``cmd_scan`` after the
``FrozenCaseContract`` has been installed on ``runtime_context``. Every
input flows through the contract - there is no argv parsing, no
interactive prompting, and no auto-detection of case files.

Workflow:
    1. Display banner & version.
    2. Run preflight (BLOCK / WARN gate).
    3. Read target / reference paths from the contract.
    4. Execute the full scan pipeline and generate reports.

DISCLAIMER:
    REDACTS is a forensic analysis AID. It does NOT replace thorough
    manual review by qualified security professionals. Results are
    not guaranteed to be complete or definitive.

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
Contact: atrium@theadimension.com
"""

from __future__ import annotations

import faulthandler
import sys
import threading
import traceback

from .cli import (
    create_console,
    cli_print,
    step_banner,
    step_preflight,
    step_run_scan,
)
from .core import paths as _paths


def _install_crash_handlers() -> None:
    """F.1: ensure the scan never dies silently.

    Mirrors the hooks installed in ``main.py`` so that direct invocations
    of ``python -m static`` (used by the orchestrator and a handful of
    integration tests) are equally protected. Idempotent.
    """
    if getattr(_install_crash_handlers, "_installed", False):
        return
    try:
        faulthandler.enable(file=sys.stderr, all_threads=True)
    except (RuntimeError, ValueError) as exc:
        sys.stderr.write(f"[WARN] faulthandler unavailable: {exc}\n")

    def _excepthook(exc_type, exc, tb) -> None:
        sys.stderr.write(
            "\n[FATAL] REDACTS scan aborted with an uncaught exception.\n"
        )
        traceback.print_exception(exc_type, exc, tb, file=sys.stderr)
        sys.stderr.write(
            f"[FATAL] {exc_type.__name__}: {exc}\n"
            "[FATAL] Exit code 70 (EX_SOFTWARE).\n"
        )
        sys.stderr.flush()

    sys.excepthook = _excepthook

    def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
        sys.stderr.write(
            f"\n[FATAL] Uncaught exception in thread "
            f"{args.thread.name if args.thread else '<unknown>'}.\n"
        )
        traceback.print_exception(
            args.exc_type, args.exc_value, args.exc_traceback, file=sys.stderr
        )
        sys.stderr.flush()

    threading.excepthook = _thread_excepthook
    _install_crash_handlers._installed = True  # type: ignore[attr-defined]


def main() -> int:
    """Execute the contract-driven scan pipeline.

    Returns the exit code from ``step_run_scan`` (0 on success).
    A missing contract is a hard failure: the CLI is non-interactive,
    so without ``case.toml`` there is nothing to scan.
    """
    # F.1: protect the long-running scan loop from silent native crashes.
    _install_crash_handlers()

    # F.3: inject ~/.redacts/tools onto PATH BEFORE preflight runs so
    # auto-installed binaries (Trivy, YARA, ...) are visible to
    # ``shutil.which`` and any subprocesses spawned by phase code.
    # Idempotent - safe to call multiple times.
    _paths.inject_tools_on_path()

    from .core.runtime_context import get_optional_contract

    console = create_console()

    # Startup banner
    step_banner(console)

    # Preflight verification (BLOCK / WARN gate)
    preflight_passed, coverage_notes, dep_report = step_preflight(console)
    if not preflight_passed:
        cli_print(
            console,
            "Aborting - resolve BLOCK-tier failures before running REDACTS.",
            style="bold red",
        )
        return 1

    # Resolve target / reference from the FrozenCaseContract.
    contract = get_optional_contract()
    if contract is None:
        cli_print(
            console,
            "Aborting - no case.toml is installed on the runtime context. "
            "Pass --case <path> to ``redacts`` (or place case.toml in the "
            "current working directory).",
            style="bold red",
        )
        return 1

    target = str(contract.inputs.target.path)
    reference = str(contract.inputs.reference.path)
    cli_print(console, f"  Case ID:    {contract.case.id}", style="dim")
    cli_print(console, f"  Target:     {target}", style="dim")
    cli_print(console, f"  Reference:  {reference}", style="dim")
    cli_print(console, "")

    # Run the full scan, with a final ``[FATAL]`` banner if the
    # pipeline raises an exception that nothing else handled.
    try:
        return step_run_scan(
            console,
            target,
            reference,
            dep_report=dep_report,
            coverage_notes=coverage_notes,
        )
    except KeyboardInterrupt:
        cli_print(console, "\n  Scan interrupted by user (Ctrl+C).",
                  style="bold yellow")
        return 130
    except Exception as exc:  # F.1: convert to clean banner + exit code
        sys.stderr.write(
            "\n[FATAL] scan crashed: "
            f"{type(exc).__name__}: {exc}\n"
        )
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        return 70


if __name__ == "__main__":
    sys.exit(main())
