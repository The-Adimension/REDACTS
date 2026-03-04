"""
REDACTS DAST — CLI Entry Point
================================
Usage:
    python -m REDACTS.dast                          # Full DAST run
    python -m REDACTS.dast --suite export           # Single suite
    python -m REDACTS.dast --suite admin,upgrade    # Multiple suites
    python -m REDACTS.dast --compose-only           # Just start stack
"""

from __future__ import annotations

import argparse
import logging

from .orchestrator import DASTOrchestrator

logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="REDACTS DAST — Dynamic Application Security Testing"
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
        default="results",
        help="Output directory for DAST results (default: results)",
    )
    parser.add_argument(
        "--keep-stack",
        action="store_true",
        help="Don't tear down Docker stack after tests",
    )
    parser.add_argument(
        "--compose-only",
        action="store_true",
        help="Only start the Docker stack (skip tests)",
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

    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    suites = [s.strip() for s in args.suite.split(",")]

    orchestrator = DASTOrchestrator(
        output_dir=args.output,
        suites=suites,
        keep_stack=args.keep_stack or args.compose_only,
        timeout=args.timeout,
    )

    if args.compose_only:
        logger.info("[DAST] Starting stack only (--compose-only)")
        orchestrator._compose_up()
        if not orchestrator._wait_for_redcap():
            print("\nERROR: REDCap did not become ready within timeout.")
            exit(1)
        port = orchestrator.dast_port
        print(f"\nREDCap is ready at http://localhost:{port}/redcap/")
        print("Run tests manually: npm test --prefix dast")
        print("Tear down: docker compose -f dast/docker-compose.dast.yml down -v")
        return

    result = orchestrator.run()

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  REDACTS DAST — Results")
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
