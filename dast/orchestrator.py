"""
REDACTS DAST Orchestrator — Dynamic Analysis Integration
=========================================================
Bridges the REDACTS static analysis pipeline with Playwright
dynamic testing. Runs as pipeline step 13 (post-report) or
standalone via CLI.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DAST_DIR = Path(__file__).parent
COMPOSE_FILE = DAST_DIR / "docker-compose.dast.yml"
COMPOSE_CRAWLMAZE_FILE = DAST_DIR / "docker-compose.crawlmaze.yml"


class DASTResult:
    """Result from a DAST run, compatible with REDACTS reporting."""

    def __init__(self):
        self.timestamp: str = datetime.now().isoformat()
        self.duration_seconds: float = 0.0
        self.suites_run: list[str] = []
        self.total_tests: int = 0
        self.passed: int = 0
        self.failed: int = 0
        self.skipped: int = 0
        self.test_results: list[dict] = []
        self.filesystem_diffs: dict = {}
        self.network_anomalies: list[str] = []
        self.xdebug_traces: list[str] = []
        self.errors: list[str] = []

    @property
    def success(self) -> bool:
        return self.failed == 0 and len(self.errors) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dast_result": {
                "timestamp": self.timestamp,
                "duration_seconds": self.duration_seconds,
                "success": self.success,
                "suites_run": self.suites_run,
                "summary": {
                    "total": self.total_tests,
                    "passed": self.passed,
                    "failed": self.failed,
                    "skipped": self.skipped,
                },
                "test_results": self.test_results,
                "filesystem_diffs": self.filesystem_diffs,
                "network_anomalies": self.network_anomalies,
                "xdebug_traces": self.xdebug_traces,
                "errors": self.errors,
            }
        }


class DASTOrchestrator:
    """
    Orchestrates the full DAST workflow:
      1. Build and start Docker stack (REDCap + DB)
      2. Wait for REDCap readiness
      3. Run Playwright test suites
      4. Collect results (JSON, traces, filesystem diffs)
      5. Tear down stack
    """

    SUITES = {
        "export": "tests/export-report.spec.ts",
        "admin": "tests/admin-access.spec.ts",
        "upgrade": "tests/upgrade-flow.spec.ts",
        "crawlmaze": "tests/crawlmaze-coverage.spec.ts",
    }

    def __init__(
        self,
        output_dir: str = "results",
        suites: Optional[list[str]] = None,
        keep_stack: bool = False,
        timeout: int = 600,
        include_crawlmaze: bool = False,
        redcap_version: str = "",
        dast_port: int = 0,
    ):
        self.output_dir = Path(output_dir)
        self.suites = suites or list(self.SUITES.keys())
        self.keep_stack = keep_stack
        self.timeout = timeout
        self.include_crawlmaze = include_crawlmaze or "crawlmaze" in self.suites
        self.redcap_version = redcap_version or os.environ.get("REDCAP_VERSION", "")
        self.dast_port = dast_port or int(os.environ.get("DAST_PORT", "8585"))

    def run(self) -> DASTResult:
        """Execute the full DAST workflow."""
        result = DASTResult()
        start = time.time()

        self.output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Step 1: Build and start stack
            logger.info("[DAST] Building Docker stack...")
            self._compose_up()

            # Step 2: Wait for readiness
            logger.info("[DAST] Waiting for REDCap to be ready...")
            if not self._wait_for_redcap():
                result.errors.append("REDCap not ready within timeout")
                return result

            # Step 3: Run test suites
            for suite in self.suites:
                if suite not in self.SUITES:
                    raise ValueError(
                        f"Unknown DAST suite '{suite}'. "
                        f"Valid suites: {', '.join(self.SUITES.keys())}"
                    )

                logger.info(f"[DAST] Running suite: {suite}")
                result.suites_run.append(suite)
                suite_result = self._run_suite(suite)
                result.test_results.extend(suite_result)

            # Step 4: Collect results
            logger.info("[DAST] Collecting results...")
            self._collect_results(result)

        except Exception as exc:
            result.errors.append(f"DAST orchestration error: {str(exc)}")
            logger.error(f"[DAST] Error: {exc}")

        finally:
            if not self.keep_stack:
                logger.info("[DAST] Tearing down stack...")
                self._compose_down()

            result.duration_seconds = round(time.time() - start, 2)
            self._save_result(result)

        return result

    def _compose_cmd_base(self) -> list[str]:
        """Build the docker compose command with optional crawlmaze overlay."""
        cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)]
        if self.include_crawlmaze:
            cmd.extend(["-f", str(COMPOSE_CRAWLMAZE_FILE)])
        return cmd

    def _compose_up(self) -> None:
        """Build and start the Docker Compose stack."""
        cmd = self._compose_cmd_base() + ["up", "-d", "--build", "--wait"]
        env = {**os.environ}
        if self.redcap_version:
            env["REDCAP_VERSION"] = self.redcap_version
        env["DAST_PORT"] = str(self.dast_port)
        subprocess.run(
            cmd,
            cwd=str(DAST_DIR),
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )

    def _compose_down(self) -> None:
        """Tear down the stack and remove volumes.

        Raises on failure — orphaned containers/volumes must not be
        left behind silently.
        """
        cmd = self._compose_cmd_base() + ["down", "-v", "--remove-orphans"]
        proc = subprocess.run(
            cmd,
            cwd=str(DAST_DIR),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            logger.error(
                "[DAST] docker compose down FAILED (rc=%d):\nstdout: %s\nstderr: %s",
                proc.returncode,
                proc.stdout,
                proc.stderr,
            )
            raise RuntimeError(
                f"Docker stack teardown failed (rc={proc.returncode}): "
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )

    def _wait_for_redcap(self, max_wait: int = 120) -> bool:
        """Poll REDCap until it responds with HTTP 200."""
        import urllib.request
        import urllib.error

        url = f"http://localhost:{self.dast_port}/redcap/"
        elapsed = 0

        last_error: str = ""
        while elapsed < max_wait:
            try:
                req = urllib.request.urlopen(url, timeout=5)
                if req.status == 200:
                    logger.info(f"[DAST] REDCap ready after {elapsed}s")
                    return True
                last_error = f"HTTP {req.status}"
            except urllib.error.URLError as exc:
                last_error = str(exc.reason)
                logger.debug("[DAST] REDCap not ready (%ds): %s", elapsed, last_error)
            except OSError as exc:
                last_error = str(exc)
                logger.debug("[DAST] REDCap not ready (%ds): %s", elapsed, last_error)

            time.sleep(3)
            elapsed += 3

        logger.error(
            "[DAST] REDCap NOT ready after %ds — last error: %s",
            max_wait,
            last_error,
        )
        return False

    def _run_suite(self, suite: str) -> list[dict]:
        """Run a single Playwright test suite inside Docker."""
        spec_file = self.SUITES[suite]

        try:
            # For crawlmaze suite, use the crawlmaze playwright container
            container_name = (
                "playwright-crawlmaze" if suite == "crawlmaze" else "playwright"
            )
            compose_cmd = self._compose_cmd_base()
            env_args = ["-e", "DAST_RESULTS_DIR=/results"]
            if self.redcap_version:
                env_args += ["-e", f"REDCAP_VERSION={self.redcap_version}"]
            proc = subprocess.run(
                compose_cmd + [
                    "run", "--rm",
                    *env_args,
                    container_name,
                    "npx", "playwright", "test",
                    spec_file,
                    "--reporter=json",
                ],
                cwd=str(DAST_DIR),
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Log stderr unconditionally — Playwright often writes
            # progress and error info there.
            if proc.stderr:
                logger.info(
                    "[DAST] Suite '%s' stderr:\n%s",
                    suite,
                    proc.stderr.rstrip(),
                )

            # Non-zero exit without output is a hard failure
            if proc.returncode != 0 and not proc.stdout.strip():
                raise RuntimeError(
                    f"Playwright exited with code {proc.returncode} "
                    f"and produced no JSON output.\n"
                    f"stderr: {proc.stderr[:1000]}"
                )

            # Parse Playwright JSON output
            return self._parse_playwright_json(proc.stdout, suite)

        except subprocess.TimeoutExpired:
            logger.error(f"[DAST] Suite '{suite}' timed out after {self.timeout}s")
            return [{
                "suite": suite,
                "status": "timeout",
                "error": f"Timed out after {self.timeout}s",
            }]
        except Exception as exc:
            logger.error(f"[DAST] Suite '{suite}' error: {exc}")
            return [{
                "suite": suite,
                "status": "error",
                "error": str(exc),
            }]

    def _parse_playwright_json(self, stdout: str, suite: str) -> list[dict]:
        """Parse Playwright JSON reporter output into REDACTS format."""
        results = []

        # Find JSON block in stdout
        try:
            # Playwright JSON output may have non-JSON preamble
            json_start = stdout.find("{")
            if json_start == -1:
                return [{
                    "suite": suite,
                    "status": "parse_error",
                    "raw_output": stdout[:500],
                }]

            data = json.loads(stdout[json_start:])

            for suite_data in data.get("suites", []):
                for spec in suite_data.get("specs", []):
                    for test_result in spec.get("tests", []):
                        for run in test_result.get("results", []):
                            results.append({
                                "suite": suite,
                                "test": spec.get("title", "unknown"),
                                "status": run.get("status", "unknown"),
                                "duration_ms": run.get("duration", 0),
                                "error": (
                                    run.get("error", {}).get("message", "")
                                    if run.get("status") == "failed"
                                    else None
                                ),
                                "annotations": test_result.get("annotations", []),
                            })

        except json.JSONDecodeError:
            results.append({
                "suite": suite,
                "status": "parse_error",
                "raw_output": stdout[:500],
            })

        return results

    def _collect_results(self, result: DASTResult) -> None:
        """Collect filesystem diffs, xdebug traces, and aggregate counts."""
        results_dir = DAST_DIR / "results"

        # Count test outcomes
        for tr in result.test_results:
            result.total_tests += 1
            status = tr.get("status", "")
            if status == "passed":
                result.passed += 1
            elif status == "failed":
                result.failed += 1
            elif status in ("skipped", "pending"):
                result.skipped += 1

        # Load filesystem diffs if present
        for diff_file in [
            "upgrade-edocs-diff.json",
            "upgrade-temp-diff.json",
        ]:
            fp = results_dir / diff_file
            if fp.exists():
                try:
                    data = json.loads(fp.read_text())
                    result.filesystem_diffs[diff_file] = data
                except Exception as exc:
                    err_msg = f"Failed to parse filesystem diff '{diff_file}': {exc}"
                    logger.error("[DAST] %s", err_msg)
                    result.errors.append(err_msg)

        # Collect xdebug trace summary
        xdebug_dir = results_dir / "xdebug"
        if xdebug_dir.exists():
            for trace_file in xdebug_dir.glob("*.xt"):
                result.xdebug_traces.append(str(trace_file.name))

    def _save_result(self, result: DASTResult) -> None:
        """Save aggregated DAST result as JSON.

        Raises on failure — losing the DAST report is never acceptable.
        """
        output_file = self.output_dir / "dast-report.json"
        output_file.write_text(
            json.dumps(result.to_dict(), indent=2)
        )
        logger.info(f"[DAST] Report saved: {output_file}")
