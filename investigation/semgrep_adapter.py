"""
REDACTS Semgrep Adapter — AST-based PHP security analysis.

Semgrep replaces REDACTS's regex-based SecurityScanner as the PRIMARY
detection engine for PHP vulnerabilities.  It provides:

    - Real AST pattern matching (not regex)
    - Taint analysis (tracks data from sources to sinks)
    - 2000+ community PHP security rules (``p/php-security``)
    - Baseline comparison via ``--baseline-commit``
    - Native SARIF output

This adapter is NOT optional — Semgrep is a MUST dependency.
If Semgrep is not installed, REDACTS raises with install instructions
rather than silently degrading.

Usage::

    adapter = SemgrepAdapter()
    result = adapter.run(Path("/path/to/redcap"))
    for finding in result.parsed_data["unified_findings"]:
        print(finding.title, finding.cwe_id, finding.mitre_attack_id)
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from pathlib import Path
from typing import Any

from .external_tools import ExternalToolAdapter, ExternalToolResult
from ..core.models import (
    Confidence,
    CvssVector,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)
from ..knowledge.mitre_mapping import get_mitre_attack
from .sarif_utils import (
    count_by_severity,
    extract_sarif_results,
)

logger = logging.getLogger(__name__)

# Semgrep rulesets to run — these cover PHP security comprehensively
# NOTE: "p/php-security" was removed from the Semgrep registry (~2025).
# Use "p/php" (general PHP rules) and "p/phpcs-security-audit" instead.
_DEFAULT_RULESETS: list[str] = [
    "p/php",                   # PHP-specific rules (successor to p/php-security)
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

    Semgrep is the PRIMARY detection engine — no fallback.
    SecurityScanner regex rules are demoted to supplementary hints.
    """

    name = "semgrep"
    description = (
        "AST-based security analysis with taint tracking "
        "(replaces regex-based SecurityScanner as primary engine)"
    )
    install_hint = (
        "Install Semgrep: pip install semgrep  — "
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

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def get_version(self) -> str:
        out, _, rc = self._run_subprocess(
            ["semgrep", "--version"], timeout=15
        )
        return out.strip() if rc == 0 else ""

    def run(
        self,
        target_path: Path,
        config: dict[str, Any] | None = None,
    ) -> ExternalToolResult:
        """Run Semgrep with SARIF output and parse results.

        Config options:
            rulesets: list[str] — override default rulesets
            baseline_ref: str — git ref for baseline comparison
            timeout: int — per-rule timeout in seconds
            max_target_bytes: int — skip files larger than this
            exclude: list[str] — glob patterns to exclude
        """
        if not self.is_available():
            return ExternalToolResult(
                tool_name=self.name,
                available=False,
                errors=[
                    f"Semgrep is NOT installed. {self.install_hint}  "
                    f"Semgrep is REQUIRED — REDACTS cannot perform "
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
        cmd: list[str] = ["semgrep", "--sarif", "--quiet"]
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
        # NOT to stderr — so we must inspect the JSON output.)
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
                pass

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

        Delegates to :func:`investigation.sarif_utils.extract_sarif_results`
        (canonical implementation, DUP-007).
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

        # CVSS — Semgrep doesn't provide CVSS, so we map from severity
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

        Delegates to :func:`investigation.sarif_utils.count_by_severity`
        (canonical implementation, DUP-008).
        """
        return count_by_severity(findings)
