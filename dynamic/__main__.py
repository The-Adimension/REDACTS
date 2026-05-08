"""
REDACTS DAST - CLI Entry Point
Usage:
    python -m dast -p /path/to/redcap.zip          # Full DAST run
    python -m dast --suite export                   # Single suite
    python -m dast --suite admin,upgrade            # Multiple suites
    python -m dast --stack-only                     # Just start stack
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Configuration is owned by the FrozenCaseContract installed by main.py.
# Environment variables are not consulted for configuration.

from static.core import runtime_context
from .orchestrator import DASTOrchestrator

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="REDACTS DAST - Dynamic Application Security Testing"
    )
    parser.add_argument(
        "--package",
        "-p",
        type=str,
        default="",
        help="Path to REDCap ZIP archive or extracted directory (required)",
    )
    parser.add_argument(
        "--suite",
        "-s",
        type=str,
        default="export,admin,upgrade",
        help="Comma-separated suite names: export, admin, upgrade (default: all)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output directory for DAST results (default: contract.paths.output_dir or ~/.redacts/output)",
    )
    parser.add_argument(
        "--keep-stack",
        action="store_true",
        help="Don't tear down Docker stack after tests",
    )
    parser.add_argument(
        "--stack-only",
        action="store_true",
        help="Start the REDCap stack but skip tests (for manual testing)",
    )
    parser.add_argument(
        "--redcap-version",
        type=str,
        default="",
        help="Explicit REDCap version override, e.g. 16.1.2",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Per-suite timeout in seconds (default: 600)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument(
        "--admin-password",
        type=str,
        default="",
        help="Set a fixed admin password (default: sourced from contract.dynamic.credentials)",
    )
    parser.add_argument(
        "--runtime",
        type=str,
        default=None,
        choices=["docker", "nix"],
        help="Runtime backend (default: contract.dynamic.runtime, falls back to 'docker').",
    )

    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    suites = [s.strip() for s in args.suite.split(",")]

    if args.output is None:
        from static.core.paths import output_dir as _output_dir
        args.output = str(_output_dir())

    # Resolve --runtime default from contract when not explicitly given.
    if args.runtime is None:
        contract = runtime_context.get_optional_contract()
        if contract is not None and contract.dynamic.runtime in ("docker", "nix"):
            args.runtime = contract.dynamic.runtime
        else:
            args.runtime = "docker"

    orchestrator = DASTOrchestrator(
        output_dir=args.output,
        suites=suites,
        keep_stack=args.keep_stack or args.stack_only,
        timeout=args.timeout,
        package=args.package,
        redcap_version=args.redcap_version,
        runtime=args.runtime,
        admin_password=args.admin_password,
    )

    if args.stack_only:
        logger.info("[DAST] Starting stack only (--stack-only)")
        orchestrator._compose_up()
        if not orchestrator._wait_for_redcap():
            print("\nERROR: REDCap did not become ready within timeout.")
            sys.exit(1)
        port = orchestrator.dast_port
        print(f"\nREDCap is ready at http://localhost:{port}/redcap/")
        print("Run tests manually: npm test --prefix dast")
        print("Tear down: docker compose -f dast/docker-compose.dast.yml down -v")
        return

    result = orchestrator.run()

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  REDACTS DAST - Results")
    print(f"{'=' * 60}")
    print(f"  Suites:   {', '.join(result.suites_run)}")
    print(f"  Total:    {result.total_tests}")
    print(f"  Passed:   {result.passed}")
    print(f"  Failed:   {result.failed}")
    print(f"  Skipped:  {result.skipped}")
    print(f"  Duration: {result.duration_seconds}s")
    print(f"  Status:   {'PASS' if result.success else 'FAIL'}")
    print(f"{'=' * 60}")

    if result.failed > 0:
        print(f"\nFailed tests:")
        for tr in result.test_results:
            if tr.get("status") == "failed":
                print(f"  X [{tr['suite']}] {tr.get('test', '?')}")
                if tr.get("error"):
                    print(f"    -> {tr['error'][:200]}")

    if result.errors:
        print(f"\nOrchestration errors:")
        for err in result.errors:
            print(f"  ! {err}")

    # Exit with failure code if tests failed
    exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
