"""Semgrep adapter - AST + taint analysis for PHP.

Semgrep is the primary AST-based detector in the pipeline; the regex
regex scanner runs alongside it and only contributes findings the
AST layer cannot express (e.g. raw config-string IoCs).

Rulesets executed by default:

    * ``p/php-security`` - Semgrep's curated PHP security pack
    * ``p/php`` - language-level lint that often catches unsafe usage
    * ``p/security-audit`` - generic audit rules that apply to PHP

Results are read from Semgrep's native SARIF 2.1.0 output
(https://semgrep.dev/docs/cli-reference) and re-mapped into
:class:`UnifiedFinding` with CWE and MITRE ATT&CK enrichment.

Known limits:

    * No runtime context. A taint sink reachable only through
      reflection (``call_user_func``, dynamic ``include``) will not be
      flagged - the DAST stage covers that path.
    * Rule coverage is only as broad as the imported packs. Custom
      REDCap-specific rules live under ``static/scanners/rules/`` and
      are loaded via ``--config``.
    * Semgrep can OOM on very large generated files. The adapter
      enforces the framework-level timeout from
      :data:`DEFAULT_TOOL_TIMEOUT` and records partial output as a
      finding rather than aborting the whole scan.

Semgrep is a hard dependency; missing the binary raises with install
instructions instead of silently skipping.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path
from typing import Any

from .external import ExternalToolAdapter, ExternalToolResult
from ..core.findings import (
    Confidence,
    CvssVector,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)
from threat_base.mitre_mapping import get_mitre_attack
from .sarif import (
    count_by_severity,
    extract_sarif_results,
)

logger = logging.getLogger(__name__)

# Active Semgrep ruleset identifiers. The PHP role is covered by
# ``p/php`` plus ``p/phpcs-security-audit``. See
# https://semgrep.dev/explore for the canonical ruleset catalogue.
_DEFAULT_RULESETS: list[str] = [
    "p/php",                   # PHP language rules
    "p/phpcs-security-audit",  # PHP CodeSniffer security audit rules
    "p/owasp-top-ten",         # OWASP Top 10 coverage
    "p/security-audit",        # General security audit rules
]

# Map Semgrep severity to REDACTS SeverityLevel
_SEMGREP_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "ERROR": SeverityLevel.HIGH,
    "WARNING": SeverityLevel.MEDIUM,
    "INFO": SeverityLevel.LOW,
}

# Map SARIF level to SeverityLevel
_SARIF_LEVEL_MAP: dict[str, SeverityLevel] = {
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note": SeverityLevel.LOW,
    "none": SeverityLevel.INFO,
}


class SemgrepAdapter(ExternalToolAdapter):
    """AST-based PHP security scanner via Semgrep.

    Semgrep is the PRIMARY detection engine - no fallback.
    SecurityScanner regex rules are demoted to supplementary hints.
    """

    name = "semgrep"
    description = (
        "AST-based security analysis with taint tracking "
        "(replaces regex-based SecurityScanner as primary engine)"
    )
    install_hint = (
        "Install Semgrep: pip install semgrep  - "
        "or see https://semgrep.dev/docs/getting-started/"
    )

    def __init__(
        self,
        *,
        rulesets: list[str] | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._rulesets = rulesets or _DEFAULT_RULESETS
        self._extra_args = extra_args or []

    def _resolve_invocation(self) -> list[str] | None:
        """Return the prefix command that invokes Semgrep, or ``None``.

        Detection order:

        1. ``semgrep`` on PATH (``shutil.which``).
        2. The ``semgrep[.exe]`` console script in the active Python
           interpreter's *Scripts* / *bin* directory. ``pip install
           semgrep`` deposits the entry-point there, but on Windows
           that directory is often missing from PATH for venvs created
           outside the project, so PATH detection alone returns
           ``None`` even though Semgrep is installed.

        We deliberately do **not** fall back to
        ``python -m semgrep``: Semgrep ``>=1.38.0`` rejects that
        invocation with an exit-2 deprecation error, so an
        "importable but binary-less" install is *not* a runnable
        install and must surface as unavailable so the operator can
        fix it.
        """
        cli = shutil.which("semgrep")
        if cli:
            return [cli]
        # Probe the active interpreter's Scripts/bin dir for the
        # console script ``pip`` installs. ``sysconfig.get_path``
        # is stdlib and reflects the real location for venvs,
        # user-site, and pipx alike. We probe both the system scheme
        # and the platform's *user* scheme because ``pip install
        # --user`` deposits scripts under USER_BASE while the default
        # scheme reports the *system* Scripts dir for the same
        # interpreter.
        import sys as _sys
        import sysconfig as _sysconfig
        is_win = _sys.platform == "win32"
        bin_name = "Scripts" if is_win else "bin"
        user_scheme = "nt_user" if is_win else (
            "osx_framework_user" if _sys.platform == "darwin"
            and "osx_framework_user" in _sysconfig.get_scheme_names()
            else "posix_user"
        )
        candidates: list[Path] = []
        for getter in (
            lambda: _sysconfig.get_path("scripts"),
            lambda: _sysconfig.get_path("scripts", scheme=user_scheme),
        ):
            try:
                d = getter()
            except (KeyError, ValueError):  # pragma: no cover - defensive
                continue
            if d:
                candidates.append(Path(d))
        # Belt-and-braces for venvs where get_path differs from the
        # interpreter's actual Scripts dir.
        candidates.append(Path(_sys.prefix) / bin_name)
        exe_names = ("semgrep.exe", "semgrep") if is_win else ("semgrep",)
        seen: set[Path] = set()
        for d in candidates:
            if d in seen:
                continue
            seen.add(d)
            for name in exe_names:
                p = d / name
                if p.is_file():
                    return [str(p)]
        return None

    def is_available(self) -> bool:
        return self._resolve_invocation() is not None

    def get_version(self) -> str:
        prefix = self._resolve_invocation()
        if prefix is None:
            return ""
        out, _, rc = self._run_subprocess(
            prefix + ["--version"], timeout=15
        )
        return out.strip() if rc == 0 else ""

    def run(
        self,
        target_path: Path,
        config: dict[str, Any] | None = None,
    ) -> ExternalToolResult:
        """Run Semgrep with SARIF output and parse results.

        Config options:
            rulesets: list[str] - override default rulesets
            baseline_ref: str - git ref for baseline comparison
            timeout: int - per-rule timeout in seconds
            max_target_bytes: int - skip files larger than this
            exclude: list[str] - glob patterns to exclude
        """
        if not self.is_available():
            return ExternalToolResult(
                tool_name=self.name,
                available=False,
                errors=[
                    f"Semgrep is NOT installed. {self.install_hint}  "
                    f"Semgrep is REQUIRED - REDACTS cannot perform "
                    f"reliable PHP security analysis without it."
                ],
            )

        cfg = config or {}
        timeout: int = cfg.get("timeout", 300)
        rulesets = cfg.get("rulesets", self._rulesets)
        baseline_ref: str | None = cfg.get("baseline_ref")
        exclude_patterns: list[str] = cfg.get(
            "exclude", ["vendor", "node_modules", ".git"]
        )
        version = self.get_version()
        start = time.monotonic()

        # Build command
        invocation = self._resolve_invocation() or ["semgrep"]
        cmd: list[str] = list(invocation) + ["--sarif", "--quiet"]
        for ruleset in rulesets:
            cmd.extend(["--config", ruleset])
        if baseline_ref:
            cmd.extend(["--baseline-commit", baseline_ref])
        for pattern in exclude_patterns:
            cmd.extend(["--exclude", pattern])
        cmd.extend(self._extra_args)
        # Always resolve to absolute path so Semgrep is not sensitive
        # to the working directory of the subprocess.
        cmd.append(str(Path(target_path).resolve()))

        logger.debug("Semgrep command: %s", cmd)
        out, err, rc = self._run_subprocess(cmd, timeout=timeout)
        elapsed = time.monotonic() - start

        errors: list[str] = []
        if err.strip():
            # Filter out non-error stderr (Semgrep prints progress there)
            for line in err.strip().splitlines():
                if any(kw in line.lower() for kw in ("error", "fatal", "exception")):
                    errors.append(line)

        # Extract errors embedded in SARIF toolExecutionNotifications
        # (Semgrep with --sarif routes config/download errors here,
        # NOT to stderr - so we must inspect the JSON output.)
        if out.strip() and rc not in (0, 1):
            try:
                sarif_err = json.loads(out)
                for run in sarif_err.get("runs", []):
                    for inv in run.get("invocations", []):
                        for note in inv.get("toolExecutionNotifications", []):
                            msg = note.get("message", {}).get("text", "")
                            if msg:
                                errors.append(msg)
            except json.JSONDecodeError:
                errors.append(out.strip() or "Semgrep returned invalid SARIF")

        # Provide a specific diagnosis for exit code 7 (MISSING_CONFIG)
        if rc == 7 and not errors:
            errors.append(
                f"Semgrep exited with code 7 (MISSING_CONFIG). "
                f"One or more --config rulesets could not be fetched. "
                f"Rulesets used: {rulesets!r}. "
                f"Check network connectivity and that the ruleset "
                f"names are still valid at https://semgrep.dev/r"
            )
        elif rc not in (0, 1) and not errors:
            errors.append(
                f"Semgrep exited with code {rc}. "
                f"stderr (last 500 chars): {err.strip()[-500:]}"
            )

        # Parse SARIF output
        sarif_data: dict[str, Any] = {}
        unified_findings: list[UnifiedFinding] = []
        raw_results: list[dict[str, Any]] = []

        if out.strip():
            try:
                sarif_data = json.loads(out)
                raw_results = extract_sarif_results(sarif_data)
                unified_findings = [
                    self._sarif_result_to_finding(r, version=version)
                    for r in raw_results
                ]
            except json.JSONDecodeError as exc:
                errors.append(f"Failed to parse Semgrep SARIF output: {exc}")

        return ExternalToolResult(
            tool_name=self.name,
            tool_version=version,
            available=True,
            success=rc in (0, 1),  # 0 = no findings, 1 = findings found
            execution_time_seconds=elapsed,
            raw_output=out[:50000] if out else "",  # Cap raw output
            parsed_data={
                "sarif": sarif_data,
                "results_count": len(raw_results),
                "unified_findings": unified_findings,
                "findings_by_severity": count_by_severity(unified_findings),
                "rules_used": self._extract_rules(sarif_data),
            },
            errors=errors,
            files_analyzed=self._count_files_scanned(sarif_data),
        )

    @staticmethod
    def _extract_sarif_results(
        sarif: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Extract result objects from SARIF output.

        Delegates to :func:`investigation.sarif_utils.extract_sarif_results`.
        """
        return extract_sarif_results(sarif)

    @staticmethod
    def _extract_rules(sarif: dict[str, Any]) -> list[dict[str, str]]:
        """Extract rule definitions from SARIF tool.driver.rules."""
        rules: list[dict[str, str]] = []
        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                rules.append({
                    "id": rule.get("id", ""),
                    "name": rule.get("name", ""),
                    "shortDescription": (
                        rule.get("shortDescription", {}).get("text", "")
                    ),
                })
        return rules

    @staticmethod
    def _count_files_scanned(sarif: dict[str, Any]) -> int:
        """Count unique files in SARIF artifacts or results."""
        files: set[str] = set()
        for run in sarif.get("runs", []):
            for artifact in run.get("artifacts", []):
                uri = artifact.get("location", {}).get("uri", "")
                if uri:
                    files.add(uri)
            for result in run.get("results", []):
                for loc in result.get("locations", []):
                    uri = (
                        loc.get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri", "")
                    )
                    if uri:
                        files.add(uri)
        return len(files)

    def _sarif_result_to_finding(
        self,
        result: dict[str, Any],
        *,
        version: str = "",
    ) -> UnifiedFinding:
        """Convert a SARIF result to a UnifiedFinding."""
        rule_id = result.get("ruleId", "unknown")
        level = result.get("level", "warning")
        message = result.get("message", {}).get("text", "")

        # Extract location
        file_path = ""
        line_start = 0
        line_end = 0
        column_start = 0
        column_end = 0
        snippet = ""

        locations = result.get("locations", [])
        if locations:
            phys = locations[0].get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            line_start = region.get("startLine", 0)
            line_end = region.get("endLine", 0)
            column_start = region.get("startColumn", 0)
            column_end = region.get("endColumn", 0)
            snippet = region.get("snippet", {}).get("text", "")

        # Extract CWE from SARIF taxa or properties
        cwe_id = ""
        for taxa in result.get("taxa", []):
            component = taxa.get("toolComponent", {}).get("name", "")
            if component.upper() == "CWE":
                cwe_id = f"CWE-{taxa.get('id', '')}"
                break
        if not cwe_id:
            # Try properties
            props = result.get("properties", {})
            cwe_id = props.get("cwe", "")

        # Extract fingerprint
        fingerprints = result.get("fingerprints", {})

        # MITRE ATT&CK mapping
        semgrep_key = f"semgrep:{rule_id}"
        mitre_id, mitre_name = get_mitre_attack(semgrep_key)
        if not mitre_id:
            mitre_id, mitre_name = self._infer_mitre_from_rule(rule_id, message)

        # CVSS - Semgrep doesn't provide CVSS, so we map from severity
        severity = _SARIF_LEVEL_MAP.get(level, SeverityLevel.MEDIUM)
        cvss_score = {
            SeverityLevel.CRITICAL: 9.5,
            SeverityLevel.HIGH: 8.0,
            SeverityLevel.MEDIUM: 5.5,
            SeverityLevel.LOW: 3.0,
            SeverityLevel.INFO: 0.0,
        }.get(severity, 5.5)

        return UnifiedFinding(
            id="",
            rule_id=rule_id,
            title=f"[Semgrep] {message[:120]}",
            description=message,
            severity=severity,
            confidence=Confidence.HIGH,  # AST-based = high confidence
            source=FindingSource.SEMGREP,
            category=self._infer_category(rule_id, message),
            cwe_id=cwe_id,
            mitre_attack_id=mitre_id,
            mitre_attack_name=mitre_name,
            cvss=CvssVector(base_score=cvss_score) if cvss_score > 0 else None,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            column_start=column_start,
            column_end=column_end,
            snippet=snippet,
            tool_name="semgrep",
            tool_version=version,
            tool_rule_url=f"https://semgrep.dev/r/{rule_id}",
        )

    @staticmethod
    def _infer_category(rule_id: str, message: str) -> str:
        """Infer finding category from rule ID and message text."""
        text = f"{rule_id} {message}".lower()
        categories = [
            ("sql", "injection"),
            ("sqli", "injection"),
            ("command-injection", "rce"),
            ("os-command", "rce"),
            ("xss", "xss"),
            ("cross-site", "xss"),
            ("ssrf", "ssrf"),
            ("path-traversal", "path_traversal"),
            ("directory-traversal", "path_traversal"),
            ("xxe", "xxe"),
            ("deserialization", "deserialization"),
            ("ldap", "injection"),
            ("hardcoded", "credentials"),
            ("credential", "credentials"),
            ("secret", "credentials"),
            ("password", "credentials"),
            ("open-redirect", "redirect"),
            ("file-inclusion", "file_inclusion"),
            ("eval", "rce"),
            ("exec", "rce"),
            ("upload", "upload"),
            ("csrf", "csrf"),
        ]
        for keyword, category in categories:
            if keyword in text:
                return category
        return "security"

    @staticmethod
    def _infer_mitre_from_rule(
        rule_id: str, message: str
    ) -> tuple[str, str]:
        """Infer MITRE ATT&CK technique from rule content."""
        text = f"{rule_id} {message}".lower()
        inferences = [
            (("sql", "injection"), ("T1190", "Exploit Public-Facing Application")),
            (("command", "exec", "system"), ("T1059.004", "Unix Shell")),
            (("eval", "code-injection"), ("T1059.004", "Unix Shell")),
            (("xss", "cross-site"), ("T1189", "Drive-by Compromise")),
            (("ssrf",), ("T1090", "Proxy")),
            (("path-traversal", "directory"), ("T1083", "File and Directory Discovery")),
            (("deserialization",), ("T1059.004", "Unix Shell")),
            (("hardcoded", "credential", "secret"), ("T1552.001", "Credentials In Files")),
            (("upload",), ("T1105", "Ingress Tool Transfer")),
            (("xxe",), ("T1190", "Exploit Public-Facing Application")),
        ]
        for keywords, mapping in inferences:
            if any(kw in text for kw in keywords):
                return mapping
        return ("", "")

    @staticmethod
    def _count_by_severity(
        findings: list[UnifiedFinding],
    ) -> dict[str, int]:
        """Count findings grouped by severity.

        Delegates to :func:`investigation.sarif_utils.count_by_severity`.
        """
        return count_by_severity(findings)
