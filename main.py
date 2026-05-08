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
        sys.stderr.write(
            "\n[FATAL] REDACTS aborted with an uncaught exception.\n"
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


def _install_contract(case_path: Path | None) -> bool:
    """Load case.toml + lockfile, freeze, and install into runtime_context.

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

    target = case_path if case_path is not None else (PROJECT_ROOT / "case.toml")
    if not target.exists():
        return False

    try:
        contract = load_and_freeze(target)
    except CaseConfigError as exc:
        print(f"[FATAL] case.toml is invalid: {exc}", file=sys.stderr)
        sys.exit(2)

    lock_path = target.with_suffix(target.suffix + ".lock")
    if lock_path.exists():
        try:
            verify_lockfile(contract, lock_path)
        except CaseConfigError as exc:
            print(
                f"[FATAL] case.toml.lock mismatch - the contract has been "
                f"modified since it was sealed: {exc}",
                file=sys.stderr,
            )
            sys.exit(2)

    runtime_context.set_contract(contract)
    return True


def cmd_scan(args: argparse.Namespace) -> int:
    """Run static analysis, dynamic analysis, or both."""
    from static.core.runtime_context import get_optional_contract

    contract = get_optional_contract()
    if contract is not None and args.mode is None:
        # Default mode comes from the contract: static-only unless dynamic.enabled.
        mode = "full" if contract.dynamic.enabled else "static"
    else:
        mode = args.mode or "static"

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
                print("Tip: re-run with '--install' to auto-install missing items.")
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


def build_parser() -> argparse.ArgumentParser:
    # Shared options every subcommand inherits via ``parents=[]``.
    shared = argparse.ArgumentParser(add_help=False)

    parser = argparse.ArgumentParser(
        prog="redacts",
        description="REDACTS - REDCap Arbitrary Code Threat Scan",
        parents=[shared],
    )
    parser.add_argument(
        "--case",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to case.toml (defaults to ./case.toml). The case file "
             "is the single source of configuration; environment "
             "variables are not consulted.",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_p = sub.add_parser("scan", parents=[shared], help="Run analysis (default)")
    scan_p.add_argument(
        "--mode",
        choices=["static", "dynamic", "full"],
        default=None,
        help="Analysis mode (default: derived from case.toml [dynamic].enabled).",
    )
    scan_p.set_defaults(func=cmd_scan)

    # preflight
    pf = sub.add_parser("preflight", parents=[shared], help="Run preflight checks")
    pf.add_argument(
        "--install",
        action="store_true",
        help=(
            "On BLOCK-tier failure, attempt auto-install (pip + Trivy/YARA)"
            " then re-run.  Honours [security].network_disabled."
        ),
    )
    pf.set_defaults(func=cmd_preflight)

    # update
    up = sub.add_parser("update", parents=[shared], help="Update threat database")
    up.add_argument(
        "target",
        nargs="?",
        choices=["cwe", "attack", "yara", "nvd", "all"],
        default=None,
        help="Optional update target (positional). Defaults to all.",
    )
    up.add_argument("--no-confirm", action="store_true")
    up.set_defaults(func=cmd_update)

    # paths
    pp = sub.add_parser("paths", help="Show resolved REDACTS storage locations")
    pp.set_defaults(func=cmd_paths)

    # secrets - passthrough to static.core.secrets.cli_main
    sp = sub.add_parser(
        "secrets",
        help="Manage secrets in the OS credential store (set/get/delete/list)",
    )
    sp.add_argument(
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

    parser = build_parser()
    args = parser.parse_args()

    # Install the FrozenCaseContract for every consumer to read from.
    # When no case.toml is present we proceed with built-in defaults
    # so ``python main.py paths`` and ``python main.py preflight`` work
    # outside a case workspace.
    _install_contract(getattr(args, "case", None))

    if not hasattr(args, "func"):
        # Default to scan when no subcommand was given.
        args.mode = None
        return cmd_scan(args)

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
