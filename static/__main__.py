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


def warn_if_cwe_data_missing(console: Any, contract: Any) -> None:
    """Notify up front when a scan will run with reduced CWE enrichment.

    Deliberately **non-interactive and side-effect-free**: ``static.__main__``
    is on the scan-path allowlist that must never prompt (see
    ``tests/cli/test_cli_surface_invariants.py``) and must run unattended in
    CI, pipelines, and background jobs. So this never asks a question and never
    downloads anything.

    When the CWE CSV is absent it prints one prominent notice - what is lost,
    that the scan is continuing anyway, and how to obtain the full data
    (automatically via ``update cwe`` when the case permits network, or
    manually) - then returns. An operator who would rather have full
    enrichment can stop now (Ctrl+C), update, and re-run. Detection itself is
    unaffected; only the CWE classification attached to each finding is reduced.

    See ``docs``/``USER_GUIDE.md`` (\"Reduced CWE enrichment\") for the full
    explanation this notice summarises.
    """
    import threat_base.cwe_database as cwe_db
    from static.core.network import NetworkDisabledError, assert_network_allowed

    if cwe_db.is_cwe_data_available():
        return

    filename = cwe_db.CWE_CSV_FILENAME
    data_dir = cwe_db.cwe_data_dir()

    # The source URL is only for the manual-update line. Resolving it reads the
    # contract, so keep it defensive - a notice must never abort the scan.
    try:
        source_url = cwe_db.cwe_source_url()
    except Exception:  # pragma: no cover - resolution is best-effort here
        source_url = ""

    # Which update method to advise depends on whether the case allows the
    # scan to reach MITRE - the automatic path is useless when it does not.
    # Advisory only: any failure here defaults to showing both methods.
    network_allowed = True
    try:
        if contract is not None and getattr(
            getattr(contract, "security", None), "network_disabled", False
        ):
            network_allowed = False
        elif source_url:
            assert_network_allowed(source_url, label="threat_base:cwe")
    except (NetworkDisabledError, ValueError):
        network_allowed = False
    except Exception:  # pragma: no cover - partial/absent contract must not crash
        pass

    cli_print(console, "")
    cli_print(
        console,
        "  [NOTICE] Reduced CWE enrichment - the scan will continue.",
        style="bold yellow",
    )
    cli_print(
        console,
        f"    The CWE weakness catalog ({filename}) is not installed.",
        style="yellow",
    )
    cli_print(
        console,
        "    Detection is unaffected, but findings will not be labelled with CWE\n"
        "    weakness IDs, names, descriptions, or mitigation guidance.",
        style="yellow",
    )
    cli_print(
        console,
        "    To include full CWE context, stop now (Ctrl+C), update, then re-run:",
        style="yellow",
    )
    if network_allowed:
        cli_print(console, "      - Automatic:  python main.py update cwe", style="cyan")
    else:
        cli_print(
            console,
            "      - Automatic update unavailable ([security].network_disabled = true).",
            style="yellow",
        )
    manual_source = source_url or "the CWE CSV from MITRE (https://cwe.mitre.org)"
    cli_print(
        console,
        f"      - Manual:     download {manual_source}\n"
        f"                    and place '{filename}' into {data_dir}",
        style="cyan",
    )
    cli_print(console, "")


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
    from .cli.error_recovery import ErrorRecoveryBlock, format_exception_recovery

    console = create_console()

    # Startup banner
    step_banner(console)

    # Preflight verification (BLOCK / WARN gate)
    preflight_passed, coverage_notes, dep_report = step_preflight(console)
    if not preflight_passed:
        block = ErrorRecoveryBlock(
            title="Preflight Gate Blocked",
            what_went_wrong="Critical BLOCK-tier dependencies or system requirements are missing.",
            how_to_fix=[
                "See SETUP.md for step-by-step instructions to install required dependencies.",
                "Ensure Python >= 3.12 and required scanner binaries exist on PATH.",
            ],
            recommended_command="python main.py preflight",
            exit_code=1,
        )
        block.display(console)
        return 1

    # Resolve target / reference from the FrozenCaseContract.
    contract = get_optional_contract()
    if contract is None:
        block = ErrorRecoveryBlock(
            title="Missing Configuration Contract",
            what_went_wrong="No case.toml configuration contract installed on runtime context.",
            how_to_fix=[
                "Run 'python main.py init' to create a valid case.toml file.",
                "Or pass '--case /path/to/case.toml' to specify an existing contract.",
            ],
            recommended_command="python main.py init",
            exit_code=1,
        )
        block.display(console)
        return 1

    # Notify up front (never prompt, never download) if CWE enrichment will be
    # reduced, so an operator can Ctrl+C and update before the scan does work.
    warn_if_cwe_data_missing(console, contract)

    target = str(contract.inputs.target.path)
    reference = str(contract.inputs.reference.path)
    cli_print(console, f"  Case ID:    {contract.case.id}", style="dim")
    cli_print(console, f"  Target:     {target}", style="dim")
    cli_print(console, f"  Reference:  {reference}", style="dim")
    cli_print(console, "")

    # Run the full scan, rendering guided error recovery if an uncaught exception occurs.
    try:
        return step_run_scan(
            console,
            target,
            reference,
            dep_report=dep_report,
            coverage_notes=coverage_notes,
        )
    except KeyboardInterrupt:
        cli_print(console, "\n  Scan interrupted by user (Ctrl+C).", style="bold yellow")
        return 130
    except Exception as exc:
        block = format_exception_recovery(exc)
        block.display(console)
        return block.exit_code


if __name__ == "__main__":
    sys.exit(main())
