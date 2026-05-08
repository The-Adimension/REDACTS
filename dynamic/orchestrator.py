"""DAST orchestrator - bridge between the static pipeline and Playwright."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from static.core.sandbox import PathSecurity

logger = logging.getLogger(__name__)

DAST_DIR = Path(__file__).parent
COMPOSE_FILE = DAST_DIR / "docker-compose.dast.yml"
COMPOSE_CRAWLMAZE_FILE = DAST_DIR / "docker-compose.crawlmaze.yml"
DOCKERFILE_DAST = DAST_DIR / "Dockerfile.dast"
ENTRYPOINT_DAST = DAST_DIR / "dast-entrypoint.sh"


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
        self.compliance_results: list[dict] = []

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
                "compliance": self._build_compliance_summary(),
                "filesystem_diffs": self.filesystem_diffs,
                "network_anomalies": self.network_anomalies,
                "xdebug_traces": self.xdebug_traces,
                "errors": self.errors,
            }
        }

    def _build_compliance_summary(self) -> dict[str, Any]:
        """Build compliance section mapping tests to admin doc sections."""
        if not self.compliance_results:
            return {"status": "not_run", "controls": []}

        controls: list[dict[str, Any]] = []
        for cr in self.compliance_results:
            controls.append({
                "test": cr.get("test", ""),
                "doc_section": cr.get("doc_section", ""),
                "status": cr.get("status", "unknown"),
                "annotations": cr.get("annotations", []),
            })

        passed = sum(1 for c in controls if c["status"] == "passed")
        failed = sum(1 for c in controls if c["status"] == "failed")
        total = len(controls)

        return {
            "status": "all_passed" if failed == 0 else "has_failures",
            "total": total,
            "passed": passed,
            "failed": failed,
            "controls": controls,
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
        "compliance": "tests/compliance-monitoring.spec.ts",
        "governance": "tests/data-governance.spec.ts",
        "user-lifecycle": "tests/user-lifecycle.spec.ts",
        "workflow": "tests/workflow-lifecycle.spec.ts",
    }

    # Maps compliance suite tests to redcap-admin-docs sections
    COMPLIANCE_DOC_MAP = {
        # compliance-monitoring.spec.ts
        "session timeout is configured": "Sec.2.5.3 Session Timeout",
        "login event is recorded": "Sec.2.1 Audit Trails",
        "audit log tracks data export": "Sec.2.1 Audit Trails",
        "DAG configuration page": "Sec.2.7.5 Data Access Groups",
        "DAG page does not leak": "Sec.2.7.5 Data Access Groups",
        "API rejects requests with empty": "Sec.2.5 API Token Security",
        "API rejects cross-project": "Sec.2.5 API Token Security",
        "API user export requires": "Sec.2.3 Data Export",
        "export page offers de-identification": "Sec.2.3 Data Export",
        "User Rights page shows": "Sec.2.7.3 User Rights Matrix",
        "User Rights page does not expose": "Sec.2.7.3 User Rights Matrix",
        "Data Quality module": "Sec.2.2 Data Quality Rules",
        "External Modules page": "Sec.2.5.3 External Module Security",
        "Project Setup page shows": "Sec.2.6 Workflows",
        "security headers present": "Sec.2.5 HTTPS/TLS",
        "survey distribution page": "Sec.2.5 Survey Security",
        "cron jobs page shows": "Sec.Architecture 5 Backup Config",
        # data-governance.spec.ts
        "Online Designer page": "Sec.2.2 Online Designer",
        "Online Designer does not expose": "Sec.2.2 Online Designer",
        "Data Dictionary download": "Sec.2.2 Data Dictionary",
        "Data Dictionary upload validation": "Sec.2.2 Data Dictionary",
        "Data Entry field validation": "Sec.2.2 Data Collection",
        "Data Entry form does not leak": "Sec.2.2 Data Collection",
        "CSV Import page": "Sec.2.2 Data Import",
        "API import rejects": "Sec.2.2 Data Import",
        "API metadata export requires": "Sec.2.3 Metadata Export",
        "API report export requires": "Sec.2.3 Report Export",
        "API file export requires": "Sec.2.3 File Export",
        "Reports page does not expose": "Sec.2.3 Custom Reports",
        "Define Events page": "Sec.2.4 Longitudinal Events",
        "Designate Instruments page": "Sec.2.4 Instrument-Event Mapping",
        "Project Setup shows record": "Sec.2.4 Record ID Config",
        "API file upload rejects": "Sec.2.2 File Upload Security",
        "Branching logic in Online Designer": "Sec.A1 Branching Logic",
        # user-lifecycle.spec.ts
        "Add Users page is accessible": "Sec.2.7.1 Account Creation",
        "Add Users page does not expose": "Sec.2.7.1 Account Creation",
        "Browse Users page is accessible": "Sec.2.7.6 User Management",
        "Browse Users page does not expose": "Sec.2.7.6 User Management",
        "User Rights role assignment": "Sec.2.7.3 User Rights",
        "User Rights custom role creation": "Sec.2.7.4 Custom Roles",
        "DAG assignment interface": "Sec.2.7.5 Data Access Groups",
        "API user import requires": "Sec.2.7 API User Management",
        "API user role mapping requires": "Sec.2.7 API User Management",
        "API user role export requires": "Sec.2.7 API User Management",
        "Logging page shows user-specific": "Sec.2.1 Audit Trails",
        "Security settings account lockout": "Sec.2.5 Account Security",
        "Failed login does not enumerate": "Sec.2.5 User Enumeration",
        # workflow-lifecycle.spec.ts
        "Project Setup displays project status": "Sec.2.6 Project Status",
        "Project Setup shows Move to Production": "Sec.2.6 Production Transition",
        "Record Locking page is accessible": "Sec.Architecture 3 Record Locking",
        "Record Locking page does not expose": "Sec.Architecture 3 Record Locking",
        "Survey Distribution page is accessible": "Sec.A1 Survey Invitations",
        "Survey Distribution does not leak": "Sec.A1 Survey Invitations",
        "Randomization Module page": "Sec.A1 Randomization Module",
        "Calendar module is accessible": "Sec.A1 Calendar/Scheduling",
        "Project Setup shows logging": "Sec.2.6 Logging Config",
        "API project info requires": "Sec.2.3 API Project Info",
        "API instrument list requires": "Sec.2.6 API Instruments",
        "API event list requires": "Sec.2.4 API Events",
        "System Statistics page": "Sec.2.6.G Admin Monitoring",
        "Alerts & Notifications page": "Sec.2.6 Alerts/Notifications",
    }

    def __init__(
        self,
        output_dir: str = "results",
        suites: list[str] | None = None,
        keep_stack: bool = False,
        timeout: int = 600,
        include_crawlmaze: bool = False,
        redcap_version: str = "",
        dast_port: int = 0,
        package: str = "",
        runtime: str = "docker",
        admin_password: str = "",
    ):
        self.output_dir = Path(output_dir)
        self.results_dir = self.output_dir / "dast-results"
        self.suites = suites or list(self.SUITES.keys())
        self.keep_stack = keep_stack
        self.timeout = timeout
        self.include_crawlmaze = include_crawlmaze or "crawlmaze" in self.suites
        # Configuration is contract-driven; environment variables
        # are not consulted for runtime values. Explicit constructor
        # arguments win, then the active contract, then a fixed default.
        from static.core import runtime_context as _rc
        _ctx = _rc.get_optional_contract()
        self.redcap_version = redcap_version or ""
        if dast_port:
            self.dast_port = dast_port
        elif _ctx is not None:
            self.dast_port = _ctx.dynamic.port
        else:
            self.dast_port = 8585
        self.package = package
        self.runtime = runtime
        self.admin_password = admin_password
        self._build_context: Path | None = None
        self._preflight_dast()

    def _preflight_dast(self) -> None:
        """Verify DAST-specific dependencies are importable."""
        missing = []
        for mod in ("playwright", "pytest_asyncio"):
            try:
                __import__(mod)
            except ImportError:
                missing.append(mod)
        if missing:
            print(
                f"ERROR: Missing DAST dependencies: {', '.join(missing)}\n"
                f"Run: {sys.executable} -m pip install " + " ".join(missing),
                file=sys.stderr,
            )
            raise RuntimeError(f"Missing DAST dependencies: {', '.join(missing)}")

    def run(self) -> DASTResult:
        """Execute the full DAST workflow."""
        result = DASTResult()
        start = time.time()

        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        try:
            # Build and start the container stack.
            logger.info("[DAST] Building Docker stack...")
            self._compose_up()

            # Wait for REDCap readiness.
            logger.info("[DAST] Waiting for REDCap to be ready...")
            if not self._wait_for_redcap():
                result.errors.append("REDCap not ready within timeout")
                return result

            # Container entrypoint bootstraps schema + config when
            # the package is provided. Allow REDCap a moment to settle.
            if self.package:
                logger.info("[DAST] REDCap provisioned by container entrypoint")
                time.sleep(3)

            # Run test suites.
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

            # Collect runtime evidence.
            logger.info("[DAST] Collecting results...")
            self._collect_results(result)

        except Exception as exc:
            result.errors.append(f"DAST orchestration error: {str(exc)}")
            logger.error(f"[DAST] Error: {exc}")

        finally:
            if not self.keep_stack:
                logger.info("[DAST] Tearing down stack...")
                try:
                    self._compose_down()
                except Exception as teardown_exc:
                    # If we already recorded an orchestration error,
                    # surface the teardown error as a separate entry
                    # rather than re-raising and clobbering the
                    # original cause. If the up phase succeeded, a
                    # teardown failure is a real issue and we still
                    # want it visible without aborting the result.
                    msg = f"DAST teardown error: {teardown_exc}"
                    result.errors.append(msg)
                    logger.error("[DAST] %s", msg)
            self._cleanup_build_context()

            result.duration_seconds = round(time.time() - start, 2)
            self._save_result(result)

        return result

    def _compose_cmd_base(self) -> list[str]:
        """Build the docker compose command with optional crawlmaze overlay."""
        cmd = ["docker", "compose", "-f", str(COMPOSE_FILE)]
        if self.include_crawlmaze:
            cmd.extend(["-f", str(COMPOSE_CRAWLMAZE_FILE)])
        return cmd

    def _build_compose_env(self) -> dict[str, str]:
        """Build the env dict required by ``docker-compose.dast.yml``.

        The static compose file declares every credential and tunable as
        a *required* variable (``${X:?error}``); this helper is the
        single source that resolves them from the active contract so
        ``up`` and ``down`` see identical interpolation. Returning the
        same dict for both phases is what makes ``compose down`` work
        after a failed ``compose up`` - otherwise teardown fails with
        an interpolation error and masks the original cause.
        """
        from . import credentials as _creds
        from static.core import runtime_context as _rc
        from static.core import subprocess_env as _se

        extra: dict[str, str] = dict(_creds.compose_env())
        if self.redcap_version:
            extra["REDCAP_VERSION"] = self.redcap_version
        extra["DAST_PORT"] = str(self.dast_port)
        extra.setdefault("DAST_MARIADB_VERSION", "10.11")
        extra.setdefault("DOCKER_MARIADB_VERSION", "10.11")

        if self.package and self._build_context is not None:
            extra["DAST_BUILD_CONTEXT"] = str(self._build_context)
            extra["DAST_DOCKERFILE"] = "Dockerfile"

        contract = _rc.get_optional_contract()
        if contract is not None:
            return _se.build(contract, role="dast-compose", extra=extra)
        return _se.minimal_env(extra=extra)

    def _compose_up(self) -> None:
        """Build and start the Docker Compose stack.

        When a ``--package`` is provided, extracts the REDCap source into a
        transient build context and injects ``DAST_BUILD_CONTEXT`` /
        ``DAST_DOCKERFILE`` so the compose file builds from ``Dockerfile.dast``
        instead of requiring the external ``mirror/Dockerfile``.

        Only the DB and app services are started (Playwright runs on the host).
        """
        services = ["redcap-dast-db", "redcap-dast-app"]
        cmd = self._compose_cmd_base() + ["up", "-d", "--build", "--wait"] + services

        if self.package:
            self._build_context = self._prepare_build_context()

        env = self._build_compose_env()

        proc = subprocess.run(
            cmd,
            cwd=str(DAST_DIR),
            capture_output=True,
            text=True,
            timeout=1800,
            env=env,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            logger.error(
                "[DAST] docker compose up FAILED (rc=%d):\nstdout: %s\nstderr: %s",
                proc.returncode, stdout, stderr,
            )
            raise RuntimeError(
                f"Docker stack startup failed (rc={proc.returncode}): "
                f"{stderr or stdout or '<no output captured>'}"
            )

    def _prepare_build_context(self) -> Path:
        """Create a transient Docker build context from the user-provided package."""
        ctx = Path(tempfile.mkdtemp(prefix="redacts-dast-"))
        source_dir = ctx / "redcap-source"
        pkg = Path(self.package)

        if pkg.is_dir():
            shutil.copytree(pkg, source_dir)
        else:
            source_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            with zipfile.ZipFile(pkg) as archive:
                for member in archive.infolist():
                    if not PathSecurity.validate_zip_entry(member.filename):
                        raise ValueError(f"Unsafe ZIP entry: {member.filename}")
                    archive.extract(member, source_dir)
            # Flatten nested directory (ZIPs often wrap in one folder)
            direct_install = source_dir / "install.php"
            child_dirs = [c for c in source_dir.iterdir() if c.is_dir()]
            if not direct_install.exists() and len(child_dirs) == 1:
                nested = child_dirs[0]
                if (nested / "install.php").exists():
                    for child in nested.iterdir():
                        shutil.move(str(child), source_dir / child.name)
                    nested.rmdir()

        shutil.copy2(DOCKERFILE_DAST, ctx / "Dockerfile")
        if ENTRYPOINT_DAST.exists():
            shutil.copy2(ENTRYPOINT_DAST, ctx / "dast-entrypoint.sh")

        logger.info("[DAST] Build context prepared at %s", ctx)
        return ctx

    def _run_install_php(self) -> None:
        """POST to install.php to auto-install REDCap after container start."""
        import urllib.parse
        import urllib.request

        from .docker_runtime import build_install_payload
        from . import credentials as _creds

        admin_user = _creds.admin_user()
        admin_pass = self.admin_password or _creds.admin_password()
        admin_email = _creds.admin_email()
        base_url = f"http://localhost:{self.dast_port}/redcap/"

        payload = build_install_payload(
            base_url=base_url,
            admin_user=admin_user,
            admin_password=admin_pass,
            admin_email=admin_email,
        )
        data = urllib.parse.urlencode(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{base_url}install.php?sql=1&auto=1",
            data=data,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as resp:
                logger.info("[DAST] install.php returned HTTP %d", resp.status)
        except Exception as exc:
            logger.warning("[DAST] install.php POST failed: %s", exc)

    def _clear_temp_password(self) -> None:
        """Mark the admin password as permanent so REDCap skips the Set-Your-Password page."""
        from . import credentials as _creds

        admin_user = _creds.admin_user()
        db_password = _creds.db_password()
        sql = f"UPDATE redcap_auth SET temp_pwd = 0 WHERE username = '{admin_user}';"
        proc = subprocess.run(
            [
                "docker", "exec", "redacts-dast-db",
                "mariadb", "-u", "redcap", f"-p{db_password}",
                "redcap", "-e", sql,
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if proc.returncode != 0:
            logger.warning("[DAST] Could not clear temp_pwd flag: %s", proc.stderr.strip())
        else:
            logger.info("[DAST] Admin password marked as permanent (temp_pwd=0)")

    def _cleanup_build_context(self) -> None:
        """Remove the transient build context directory."""
        if self._build_context and self._build_context.exists():
            shutil.rmtree(self._build_context, ignore_errors=True)
            self._build_context = None

    def _compose_down(self) -> None:
        """Tear down the stack and remove volumes.

        Raises on failure - orphaned containers/volumes must not be
        left behind silently.
        """
        cmd = self._compose_cmd_base() + ["down", "-v", "--remove-orphans"]
        proc = subprocess.run(
            cmd,
            cwd=str(DAST_DIR),
            capture_output=True,
            text=True,
            timeout=60,
            env=self._build_compose_env(),
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
            "[DAST] REDCap NOT ready after %ds - last error: %s",
            max_wait,
            last_error,
        )
        return False

    def _run_suite(self, suite: str) -> list[dict]:
        """Run a single Playwright test suite.

        Runs tests on the host using the local npx/playwright install,
        pointing at the Dockerised REDCap instance.
        """
        spec_file = self.SUITES[suite]

        try:
            from . import credentials as _creds
            from static.core import runtime_context as _rc
            from static.core import subprocess_env as _se

            admin_user = _creds.admin_user()
            admin_pass = self.admin_password or _creds.admin_password()
            extra: dict[str, str] = {
                "REDCAP_BASE_URL": f"http://localhost:{self.dast_port}",
                "DAST_RESULTS_DIR": str(DAST_DIR / "results"),
                "REDCAP_ADMIN_USER": admin_user,
                "REDCAP_ADMIN_PASS": admin_pass,
            }
            if self.redcap_version:
                extra["REDCAP_VERSION"] = self.redcap_version

            contract = _rc.get_optional_contract()
            if contract is not None:
                env = _se.build(contract, role="dast-playwright", extra=extra)
            else:
                env = _se.minimal_env(extra=extra)

            proc = subprocess.run(
                [
                    "npx", "playwright", "test",
                    spec_file,
                    "--reporter=json",
                ],
                cwd=str(DAST_DIR),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=env,
                shell=True,
            )

            # Log stderr unconditionally - Playwright often writes
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

        def _extract_specs(suite_node: dict) -> None:
            """Recursively walk nested suites and extract specs."""
            for spec in suite_node.get("specs", []):
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
            for child in suite_node.get("suites", []):
                _extract_specs(child)

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
                _extract_specs(suite_data)

        except json.JSONDecodeError:
            results.append({
                "suite": suite,
                "status": "parse_error",
                "raw_output": stdout[:500],
            })

        return results

    def _collect_results(self, result: DASTResult) -> None:
        """Collect filesystem diffs, xdebug traces, compliance data, and aggregate counts."""
        results_dir = DAST_DIR / "results"

        # Count test outcomes
        for tr in result.test_results:
            result.total_tests += 1
            status = tr.get("status", "")
            if status == "passed":
                result.passed += 1
            elif status == "failed":
                result.failed += 1
            elif status == "error":
                result.failed += 1  # errors are actionable failures
            elif status in ("skipped", "pending"):
                result.skipped += 1

        # Extract compliance annotations from the compliance suite
        self._extract_compliance_results(result)

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

        Raises on failure - losing the DAST report is never acceptable.
        """
        self.results_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        output_file = self.results_dir / "dast-report.json"
        output_file.write_text(
            json.dumps(result.to_dict(), indent=2)
        )
        logger.info(f"[DAST] Report saved: {output_file}")

    def _extract_compliance_results(self, result: DASTResult) -> None:
        """Extract compliance annotations from test results and map to doc sections."""
        compliance_suites = {"compliance", "governance", "user-lifecycle", "workflow"}
        for tr in result.test_results:
            if tr.get("suite") not in compliance_suites:
                continue

            test_name = tr.get("test", "")
            doc_section = ""
            for pattern, section in self.COMPLIANCE_DOC_MAP.items():
                if pattern.lower() in test_name.lower():
                    doc_section = section
                    break

            result.compliance_results.append({
                "test": test_name,
                "doc_section": doc_section,
                "status": tr.get("status", "unknown"),
                "annotations": tr.get("annotations", []),
            })
