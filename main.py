#!/usr/bin/env python3
"""
REDACTS - REDCap Arbitrary Code Threat Scan

Unified entry point for static analysis, dynamic analysis, or both.

Usage:
    python main.py scan                     # Run scan (mode from case.toml)
    python main.py scan --mode static       # Static analysis only
    python main.py scan --mode dynamic      # Dynamic analysis only
    python main.py scan --mode full         # Both static + dynamic
    python main.py preflight                # Run preflight checks
    python main.py update                   # Update threat database
    python main.py paths                    # Show resolved storage locations
    python main.py secrets <subcmd>         # Manage OS credential store

Configuration is sourced exclusively from ``case.toml`` (and its
companion lockfile). Environment variables are not consulted.

DISCLAIMER:
    REDACTS is a forensic analysis AID. It does NOT replace thorough manual
    review by qualified security professionals. Results are not guaranteed to
    be complete or definitive.

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import argparse
import faulthandler
import sys
import threading
import traceback
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from static.core.contract import FrozenCaseContract

# Resolve project root for consistent path references
PROJECT_ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = PROJECT_ROOT / "output"
INPUTS_DIR = PROJECT_ROOT / "inputs"
SANDBOX_DIR = PROJECT_ROOT / ".inputs"


def _install_crash_handlers() -> None:
    """Wire faulthandler and sys.excepthook so REDACTS never dies silently.

    These hooks make failures visible even when they happen outside the
    Rich/reporting path:

    * Native crashes (segfault, stack overflow, SIGABRT) print a Python
      traceback for every thread to stderr via ``faulthandler``.
    * Uncaught Python exceptions print a ``[FATAL]`` banner with the
      exception type, message, and traceback to stderr - even from
      worker threads (``threading.excepthook``).

    Idempotent: calling twice is a no-op.
    """
    if getattr(_install_crash_handlers, "_installed", False):
        return

    # Native-fault dump goes to stderr - survives even when stdout is
    # redirected or buffered.
    try:
        faulthandler.enable(file=sys.stderr, all_threads=True)
    except (RuntimeError, ValueError) as exc:
        # stderr may be unavailable in odd hosting situations (frozen
        # GUI, etc.); proceed without faulthandler in that case.
        sys.stderr.write(f"[WARN] faulthandler unavailable: {exc}\n")

    def _excepthook(exc_type, exc, tb) -> None:
        from static.cli.error_recovery import handle_error
        sys.stderr.write(
            "\n[FATAL] REDACTS aborted with an uncaught exception.\n"
        )
        traceback.print_exception(exc_type, exc, tb, file=sys.stderr)
        handle_error(exc)
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


def _file_sha256(path: Path) -> str:
    """Stream a file's SHA-256 so a multi-GB archive is not read into memory.

    Delegates to the project's hashing chokepoint rather than reimplementing
    the buffered read.
    """
    from static.core.hashing import compute_single_hash

    return compute_single_hash(path)


def _apply_cli_overrides(
    contract: "FrozenCaseContract", args: argparse.Namespace
) -> "FrozenCaseContract":
    """Return *contract* with CLI flag overrides applied.

    Pure: takes and returns a contract rather than swapping the one installed
    on ``runtime_context``. That matters for two reasons.

    * ``runtime_context`` documents the contract as set exactly once per
      process, with ``reset_contract()`` reserved for tests. Resetting it
      mid-run to install a mutated copy defeats that guarantee.
    * The caller verifies the lockfile *after* calling this, so an override
      that changes the sealed surface is caught by the existing
      ``lockfile-drift`` refusal instead of silently running a configuration
      that no longer matches the seal.
    """
    from dataclasses import replace

    from static.core.contract import InputArtifact

    # 1. Inputs override (--target, --reference)
    target_path = getattr(args, "target", None)
    ref_path = getattr(args, "reference", None)
    new_inputs = contract.inputs

    if target_path is not None or ref_path is not None:
        new_target = new_inputs.target
        new_ref = new_inputs.reference

        if target_path is not None:
            p = Path(target_path).resolve()
            new_target = InputArtifact(
                path=p, sha256=_file_sha256(p) if p.is_file() else ""
            )

        if ref_path is not None:
            p = Path(ref_path).resolve()
            new_ref = InputArtifact(
                path=p, sha256=_file_sha256(p) if p.is_file() else ""
            )

        new_inputs = replace(new_inputs, target=new_target, reference=new_ref)

    # 2. Static override (--severity-gate, --parallel-workers, --timeout / --global-timeout-seconds)
    severity_gate = getattr(args, "severity_gate", None)
    parallel_workers = getattr(args, "parallel_workers", None)
    timeout = getattr(args, "global_timeout_seconds", None)
    if timeout is None:
        timeout = getattr(args, "timeout", None)

    static_updates = {}
    if severity_gate is not None:
        static_updates["severity_gate"] = severity_gate
    if parallel_workers is not None:
        static_updates["parallel_workers"] = parallel_workers
    if timeout is not None:
        static_updates["global_timeout_seconds"] = timeout

    new_static = contract.static
    if static_updates:
        new_static = replace(new_static, **static_updates)

    if new_inputs is contract.inputs and new_static is contract.static:
        return contract
    return replace(contract, inputs=new_inputs, static=new_static)


def _install_contract(case_path: Path | None, args: argparse.Namespace) -> bool:
    """Load case.toml, apply CLI overrides, verify the seal, and install once.

    Order is deliberate: overrides are applied *before* ``verify_lockfile`` so
    a sealed case refuses any flag that would change the locked surface, rather
    than the run proceeding under a configuration the lockfile never covered.

    Returns ``True`` on success, ``False`` when no case file is present.
    Aborts (``sys.exit(2)``) on a structural / lockfile error so every
    downstream consumer can rely on a contract being installed.
    """
    from static.core.contract import (
        CaseConfigError,
        load_and_freeze,
        verify_lockfile,
    )
    from static.core import runtime_context
    from static.cli.error_recovery import format_exception_recovery

    target = case_path if case_path is not None else (PROJECT_ROOT / "case.toml")
    if not target.exists():
        if case_path is not None:
            raise FileNotFoundError(f"Specified case file does not exist: {case_path}")
        return False

    try:
        contract = load_and_freeze(target)
        contract = _apply_cli_overrides(contract, args)

        lock_path = target.with_suffix(target.suffix + ".lock")
        if lock_path.exists():
            verify_lockfile(contract, lock_path)
    except CaseConfigError as exc:
        block = format_exception_recovery(exc)
        block.display()
        sys.exit(2)

    runtime_context.set_contract(contract)
    return True


def cmd_scan(args: argparse.Namespace) -> int:
    """Run static analysis, dynamic analysis, or both."""
    from static.core.runtime_context import get_optional_contract

    contract = get_optional_contract()
    # ``--mode`` is defined only by the scan subparser, but cmd_scan is also the
    # fallback for a bare ``redacts`` invocation, so read it defensively.
    requested_mode = getattr(args, "mode", None)
    if contract is not None and requested_mode is None:
        # Default mode comes from the contract: static-only unless dynamic.enabled.
        mode = "full" if contract.dynamic.enabled else "static"
    else:
        mode = requested_mode or "static"

    def _run() -> int:
        if mode in ("static", "full"):
            from static.__main__ import main as static_main
            result = static_main()
            if result != 0 and mode == "static":
                return result

        # Dynamic-only mode runs the DAST CLI directly. In ``full`` mode the
        # DastPhase already ran as part of ``static_main`` (it shares the
        # ``DASTOrchestrator``), so re-invoking ``dynamic_main`` here would
        # just cause the dynamic argparse to choke on this script's
        # scan argv (``scan --mode full``). Skip it.
        if mode == "dynamic":
            from dynamic.__main__ import main as dynamic_main
            dynamic_main()

        return 0

    return _run()


def cmd_preflight(args: argparse.Namespace) -> int:
    """Run preflight verification.

    Standalone and scan-embedded preflight invocations share the same
    ``run_preflight`` / ``auto_install_missing`` / ``_display_preflight_table``
    pipeline, so CLI output is identical regardless of entry point.
    """
    # Prepend the contract's tools_root to PATH so shutil.which() finds
    # auto-installed Trivy / YARA binaries before any check runs.
    from static.core import paths
    paths.inject_tools_on_path()
    _print_paths_banner()

    def _run() -> int:
        from static.cli.preflight import (
            _display_preflight_table,
            auto_install_missing,
            run_preflight,
        )

        try:
            from rich.console import Console
            console = Console()
        except ImportError:
            console = None  # type: ignore[assignment]

        result = run_preflight(phase="check")
        _display_preflight_table(console, result)

        if result.blocked and getattr(args, "install", False):
            result = auto_install_missing(result, console=console)
            _display_preflight_table(console, result)

        if result.blocked:
            print("\n[BLOCKED] Critical dependencies missing. Cannot proceed.")
            for check in result.block_failures:
                line = f"  x {check.name}: {check.message}"
                if check.fix_hint:
                    line += f"  [fix: {check.fix_hint}]"
                print(line)
            if not getattr(args, "install", False):
                print("Tip: see SETUP.md for step-by-step instructions to install all required dependencies.")
            return 1
        if result.warn_failures:
            print("\n[WARNING] Some tools unavailable - reduced coverage:")
            for check in result.warn_failures:
                line = f"  ! {check.name}: {check.message}"
                if check.fix_hint:
                    line += f"  [fix: {check.fix_hint}]"
                print(line)
        else:
            print("\n[OK] All preflight checks passed.")
        return 0

    return _run()


def _print_paths_banner() -> None:
    """Print the resolved REDACTS storage locations so users always see
    where artifacts will be written."""
    from static.core import paths
    snapshot = paths.resolved()
    print("REDACTS storage locations (driven by case.toml):")
    for name, info in snapshot.items():
        marker = "*" if info["source"] == "contract" else " "
        exists = "exists" if info["exists"] else "missing"
        source = info["source"]
        print(f"  {marker} {name:<7} [{source:<8}] {info['path']}  [{exists}]")
    print("  (* = sourced from case.toml; otherwise built-in default)\n")


def cmd_paths(args: argparse.Namespace) -> int:
    """Print the resolved REDACTS path configuration."""
    _print_paths_banner()
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """Update the threat database."""
    def _run() -> int:
        import sys as _sys
        from threat_base.updater import main as updater_main
        # Compose argv expected by the updater CLI.
        forwarded = ["redacts-update"]
        if getattr(args, "target", None):
            forwarded.append(args.target)
        if getattr(args, "no_confirm", False):
            forwarded.append("--no-confirm")
        saved = _sys.argv
        try:
            _sys.argv = forwarded
            return updater_main()
        finally:
            _sys.argv = saved

    return _run()


def cmd_secrets(args: argparse.Namespace) -> int:
    """Manage secrets in the OS credential store."""
    from static.core.secrets import cli_main as secrets_main
    return secrets_main(list(args.secrets_argv or []))


def cmd_init(args: argparse.Namespace) -> int:
    """Run interactive contract wizard to generate case.toml."""
    from static.cli.init_wizard import run_init_wizard
    return run_init_wizard(args)


class REDACTSArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser providing Guided Error Recovery on CLI argument errors."""

    def error(self, message: str) -> None:
        from static.cli.error_recovery import ErrorRecoveryBlock

        block = ErrorRecoveryBlock(
            title="CLI Argument Error",
            what_went_wrong=f"Invalid command line invocation: {message}",
            how_to_fix=[
                "Check command line syntax and flag spelling.",
                "Review available subcommands and option groups in '--help'.",
            ],
            recommended_command="python main.py scan --help",
            exit_code=2,
        )
        block.display()
        sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = REDACTSArgumentParser(
        prog="redacts",
        description="REDACTS - REDCap Arbitrary Code Threat Scan",
        add_help=False,
    )

    top_common = parser.add_argument_group("Common Options")
    top_common.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit",
    )
    top_common.add_argument(
        "--case",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to case.toml (defaults to ./case.toml). The case file "
            "is the single source of configuration; environment "
            "variables are not consulted."
        ),
    )

    sub = parser.add_subparsers(dest="command", title="Subcommands")

    def _create_subparser(name: str, help_msg: str):
        sp = sub.add_parser(name, help=help_msg, add_help=False)
        cg = sp.add_argument_group("Common Options")
        cg.add_argument(
            "-h",
            "--help",
            action="help",
            default=argparse.SUPPRESS,
            help="Show this help message and exit",
        )
        cg.add_argument(
            "--case",
            type=Path,
            # SUPPRESS - not None. argparse parses a subcommand into a fresh
            # namespace and copies every key back over the top-level one, so a
            # concrete default here would clobber ``redacts --case X scan``
            # with None. With SUPPRESS the key is absent unless actually given.
            default=argparse.SUPPRESS,
            metavar="PATH",
            help="Path to case.toml (defaults to ./case.toml).",
        )
        ag = sp.add_argument_group("Advanced Options")
        return sp, cg, ag


    # init
    init_p, init_cg, init_ag = _create_subparser(
        "init", "Interactively build a valid case.toml configuration"
    )
    init_cg.add_argument(
        "--target", type=Path, default=None, help="Target archive or directory path"
    )
    init_cg.add_argument(
        "--reference", type=Path, default=None, help="Reference archive or directory path"
    )
    init_cg.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Output path for case.toml (defaults to ./case.toml)",
    )
    init_ag.add_argument("--case-id", default=None, help="Case ID")
    init_ag.add_argument("--analyst", default=None, help="Analyst name")
    init_ag.add_argument("--organization", default=None, help="Organization name")
    init_ag.add_argument(
        "--yes",
        "-y",
        "--non-interactive",
        action="store_true",
        dest="non_interactive",
        help="Skip interactive prompts and use defaults/flags",
    )
    init_p.set_defaults(func=cmd_init)

    # scan
    scan_p, scan_cg, scan_ag = _create_subparser("scan", "Run analysis (default)")
    scan_cg.add_argument(
        "--target",
        type=Path,
        default=None,
        metavar="PATH",
        help="Target archive or directory path for analysis",
    )
    scan_cg.add_argument(
        "--reference",
        type=Path,
        default=None,
        metavar="PATH",
        help="Reference archive or directory path for analysis",
    )
    scan_cg.add_argument(
        "--mode",
        choices=["static", "dynamic", "full"],
        default=None,
        help="Analysis mode (default: derived from case.toml [dynamic].enabled).",
    )

    scan_ag.add_argument(
        "--severity-gate",
        choices=["info", "low", "medium", "high", "critical"],
        default=None,
        help="Minimum severity threshold for findings",
    )
    scan_ag.add_argument(
        "--parallel-workers",
        type=int,
        default=None,
        help="Number of parallel worker processes for static analysis",
    )
    scan_ag.add_argument(
        "--timeout",
        "--global-timeout-seconds",
        type=int,
        default=None,
        dest="global_timeout_seconds",
        help="Global timeout in seconds for static analysis",
    )
    scan_ag.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose diagnostic logging.",
    )
    scan_p.set_defaults(func=cmd_scan)

    # preflight
    pf, pf_cg, pf_ag = _create_subparser("preflight", "Run preflight checks")
    pf_ag.add_argument(
        "--install",
        action="store_true",
        help=(
            "On BLOCK-tier failure, attempt auto-install (pip + Trivy/YARA)"
            " then re-run.  Honours [security].network_disabled."
        ),
    )
    pf.set_defaults(func=cmd_preflight)

    # update
    up, up_cg, up_ag = _create_subparser("update", "Update threat database")
    up_cg.add_argument(
        "target",
        nargs="?",
        choices=["cwe", "attack", "yara", "nvd", "all"],
        default=None,
        help="Optional update target (positional). Defaults to all.",
    )
    up_ag.add_argument(
        "--no-confirm", action="store_true", help="Skip confirmation prompt"
    )
    up.set_defaults(func=cmd_update)

    # paths
    pp, pp_cg, pp_ag = _create_subparser(
        "paths", "Show resolved REDACTS storage locations"
    )
    pp.set_defaults(func=cmd_paths)

    # secrets - passthrough to static.core.secrets.cli_main
    sp, sp_cg, sp_ag = _create_subparser(
        "secrets", "Manage secrets in the OS credential store (set/get/delete/list)"
    )
    sp_ag.add_argument(
        "secrets_argv",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to ``redacts secrets`` (e.g. ``set <key>``).",
    )
    sp.set_defaults(func=cmd_secrets)

    return parser


def main() -> int:
    # F.1: install crash handlers as the very first thing - before
    # parsing arguments - so even argparse-internal aborts produce a
    # readable banner instead of a silent exit.
    _install_crash_handlers()

    try:
        parser = build_parser()
        args = parser.parse_args()

        # Install the FrozenCaseContract for every consumer to read from.
        # When no case.toml is present we proceed with built-in defaults
        # so ``python main.py paths`` and ``python main.py preflight`` work
        # outside a case workspace.
        if getattr(args, "command", None) != "init":
            _install_contract(getattr(args, "case", None), args)

        if hasattr(args, "func"):
            func = args.func
        else:
            # No subcommand given: default to ``scan``. cmd_scan reads flags
            # that only the scan subparser defines, so seed them here.
            func = cmd_scan
            args.mode = None

        # Subcommands own their own failure reporting - static.__main__, for
        # instance, already renders a specific recovery block before returning
        # nonzero. Rendering a second, generic one here just buried the useful
        # message under "Runtime Error: Error: 1".
        return func(args)
    except SystemExit:
        raise
    except Exception as exc:
        from static.cli.error_recovery import handle_error
        return handle_error(exc)


if __name__ == "__main__":
    sys.exit(main())
