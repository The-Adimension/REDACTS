"""
REDACTS Trivy Adapter — Dependency CVE & secret scanning.

Trivy (Aqua Security) scans for:
    - Known CVEs in Composer dependencies (composer.lock)
    - Leaked secrets in files
    - SBOM (Software Bill of Materials) generation
    - Dockerfile / IaC misconfigurations

CRITICAL: Trivy does NOT analyze PHP code semantics.  It cannot detect
``eval(base64_decode(...))``.  It is purely version-matching against
CVE databases.  It complements Semgrep; it does not replace it.

Trivy outputs SARIF natively, enabling direct ingest into REDACTS's
unified finding model.

Usage::

    adapter = TrivyAdapter()
    result = adapter.run(Path("/path/to/redcap"))
    for finding in result.parsed_data["unified_findings"]:
        print(finding.cve_id, finding.title, finding.cvss.base_score)
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from .external_tools import DEFAULT_TOOL_TIMEOUT, ExternalToolAdapter, ExternalToolResult, _resolve_venv_tool
from .sarif_utils import (
    count_by_severity,
    extract_sarif_results,
)
from ..core.models import (
    Confidence,
    CvssVector,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)

logger = logging.getLogger(__name__)

# Trivy scanners to enable
_DEFAULT_SCANNERS: list[str] = ["vuln", "secret"]

# Map Trivy severity to REDACTS
_TRIVY_SEVERITY_MAP: dict[str, SeverityLevel] = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "UNKNOWN": SeverityLevel.INFO,
}


class TrivyAdapter(ExternalToolAdapter):
    """Dependency CVE scanner and secret detector via Trivy.

    Trivy is a MUST dependency for:
        1. Composer lockfile CVE scanning (REDACTS has zero dep scanning today)
        2. Secret detection (complements sensitive_data.py)
        3. SBOM generation for supply chain visibility
    """

    name = "trivy"
    description = (
        "Dependency CVE scanning, secret detection, and SBOM generation "
        "(Aqua Security Trivy)"
    )
    install_hint = (
        "Install Trivy: brew install trivy  — "
        "or Docker: docker run aquasec/trivy  — "
        "or see https://github.com/aquasecurity/trivy"
    )

    def __init__(
        self,
        *,
        scanners: list[str] | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._scanners = scanners or _DEFAULT_SCANNERS
        self._extra_args = extra_args or []

    def is_available(self) -> bool:
        return _resolve_venv_tool("trivy") is not None

    def get_version(self) -> str:
        binary = _resolve_venv_tool("trivy") or "trivy"
        out, _, rc = self._run_subprocess(
            [binary, "version", "--format", "json"], timeout=15
        )
        if rc == 0 and out.strip():
            try:
                data = json.loads(out)
                return data.get("Version", out.strip().split("\n")[0])
            except (json.JSONDecodeError, KeyError):
                return out.strip().split("\n")[0]
        return ""

    def run(
        self,
        target_path: Path,
        config: dict[str, Any] | None = None,
    ) -> ExternalToolResult:
        """Run Trivy filesystem scan with SARIF output.

        Config options:
            scanners: list[str] — override scanners (vuln, secret, misconfig)
            timeout: int — timeout in seconds
            skip_dirs: list[str] — directories to skip
            severity: str — minimum severity filter (e.g. "MEDIUM,HIGH,CRITICAL")
        """
        if not self.is_available():
            return ExternalToolResult(
                tool_name=self.name,
                available=False,
                errors=[
                    f"Trivy is NOT installed. {self.install_hint}  "
                    f"Trivy is REQUIRED for dependency CVE scanning — "
                    f"REDACTS has zero dependency vulnerability detection without it."
                ],
            )

        cfg = config or {}
        timeout: int = cfg.get("timeout", 300)
        scanners = cfg.get("scanners", self._scanners)
        skip_dirs: list[str] = cfg.get("skip_dirs", [".git", "node_modules"])
        severity_filter: str = cfg.get("severity", "")
        version = self.get_version()
        start = time.monotonic()

        # Build command — filesystem scan with SARIF output
        binary = _resolve_venv_tool("trivy") or "trivy"
        cmd: list[str] = [
            binary, "filesystem",
            "--format", "sarif",
            "--scanners", ",".join(scanners),
        ]
        for skip_dir in skip_dirs:
            cmd.extend(["--skip-dirs", skip_dir])
        if severity_filter:
            cmd.extend(["--severity", severity_filter])
        cmd.extend(self._extra_args)
        cmd.append(str(target_path))

        out, err, rc = self._run_subprocess(cmd, timeout=timeout)
        elapsed = time.monotonic() - start

        errors: list[str] = []
        if err.strip():
            for line in err.strip().splitlines():
                if any(kw in line.lower() for kw in ("fatal", "error", "panic")):
                    errors.append(line)

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
                errors.append(f"Failed to parse Trivy SARIF output: {exc}")

        # Separate CVE findings from secret findings
        cve_findings = [
            f for f in unified_findings if f.cve_id
        ]
        secret_findings = [
            f for f in unified_findings if not f.cve_id
        ]

        return ExternalToolResult(
            tool_name=self.name,
            tool_version=version,
            available=True,
            success=rc == 0,
            execution_time_seconds=elapsed,
            raw_output=out[:50000] if out else "",
            parsed_data={
                "sarif": sarif_data,
                "results_count": len(raw_results),
                "unified_findings": unified_findings,
                "cve_findings_count": len(cve_findings),
                "secret_findings_count": len(secret_findings),
                "findings_by_severity": count_by_severity(unified_findings),
                "cve_ids": [f.cve_id for f in cve_findings if f.cve_id],
            },
            errors=errors,
        )

    def run_sbom(
        self,
        target_path: Path,
        output_path: Path,
        *,
        timeout: int = DEFAULT_TOOL_TIMEOUT,
    ) -> ExternalToolResult:
        """Generate SBOM (Software Bill of Materials) in CycloneDX format.

        Produces a machine-readable inventory of all dependencies,
        critical for supply chain forensics.
        """
        if not self.is_available():
            return self._empty_result()

        version = self.get_version()
        start = time.monotonic()

        binary = _resolve_venv_tool("trivy") or "trivy"
        cmd = [
            binary, "filesystem",
            "--format", "cyclonedx",
            "--output", str(output_path),
            str(target_path),
        ]
        out, err, rc = self._run_subprocess(cmd, timeout=timeout)
        elapsed = time.monotonic() - start

        errors = [err.strip()] if err.strip() else []
        sbom_exists = output_path.is_file()

        return ExternalToolResult(
            tool_name=self.name,
            tool_version=version,
            available=True,
            success=rc == 0 and sbom_exists,
            execution_time_seconds=elapsed,
            raw_output=out,
            parsed_data={
                "sbom_path": str(output_path),
                "sbom_generated": sbom_exists,
                "sbom_size_bytes": output_path.stat().st_size if sbom_exists else 0,
                "format": "CycloneDX",
            },
            errors=errors,
        )

    @staticmethod
    def _extract_sarif_results(
        sarif: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Extract result objects from Trivy SARIF output.

        Delegates to :func:`investigation.sarif_utils.extract_sarif_results`
        (canonical implementation, DUP-007).
        """
        return extract_sarif_results(sarif)

    def _sarif_result_to_finding(
        self,
        result: dict[str, Any],
        *,
        version: str = "",
    ) -> UnifiedFinding:
        """Convert a Trivy SARIF result to a UnifiedFinding."""
        rule_id = result.get("ruleId", "unknown")
        level = result.get("level", "warning")
        message = result.get("message", {}).get("text", "")

        # Extract location
        file_path = ""
        line_start = 0
        locations = result.get("locations", [])
        if locations:
            phys = locations[0].get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            line_start = region.get("startLine", 0)

        # Determine if this is a CVE or secret finding
        cve_id = ""
        if rule_id.startswith("CVE-") or rule_id.startswith("GHSA-"):
            cve_id = rule_id

        # Extract CVSS from properties if available
        props = result.get("properties", {})
        cvss_score = props.get("cvss_score", 0.0)
        cvss_vector = props.get("cvss_vector", "")

        # Determine severity
        severity_str = props.get("severity", "")
        if severity_str and severity_str.upper() in _TRIVY_SEVERITY_MAP:
            severity = _TRIVY_SEVERITY_MAP[severity_str.upper()]
        else:
            severity = {
                "error": SeverityLevel.HIGH,
                "warning": SeverityLevel.MEDIUM,
                "note": SeverityLevel.LOW,
                "none": SeverityLevel.INFO,
            }.get(level, SeverityLevel.MEDIUM)

        # CVSS vector construction
        cvss: CvssVector | None = None
        if cvss_score > 0:
            cvss = CvssVector(
                vector_string=cvss_vector,
                base_score=float(cvss_score),
            )
        elif cve_id:
            # Estimate from severity if Trivy doesn't provide CVSS
            score_est = {
                SeverityLevel.CRITICAL: 9.5,
                SeverityLevel.HIGH: 8.0,
                SeverityLevel.MEDIUM: 5.5,
                SeverityLevel.LOW: 3.0,
            }.get(severity, 5.5)
            cvss = CvssVector(base_score=score_est)

        # CWE extraction
        cwe_id = ""
        for taxa in result.get("taxa", []):
            component = taxa.get("toolComponent", {}).get("name", "")
            if component.upper() == "CWE":
                cwe_id = f"CWE-{taxa.get('id', '')}"
                break

        # Category determination
        if cve_id:
            category = "dependency_vulnerability"
            mitre_id = "T1195.001"
            mitre_name = "Supply Chain Compromise: Compromise Software Dependencies and Development Tools"
        else:
            category = "secret_exposure"
            mitre_id = "T1552.001"
            mitre_name = "Unsecured Credentials: Credentials In Files"

        return UnifiedFinding(
            id="",
            rule_id=rule_id,
            title=f"[Trivy] {message[:120]}",
            description=message,
            severity=severity,
            confidence=Confidence.CONFIRMED,  # CVE database = confirmed
            source=FindingSource.TRIVY,
            category=category,
            cwe_id=cwe_id,
            cve_id=cve_id,
            mitre_attack_id=mitre_id,
            mitre_attack_name=mitre_name,
            cvss=cvss,
            file_path=file_path,
            line_start=line_start,
            tool_name="trivy",
            tool_version=version,
            references=[
                f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "",
            ],
        )

    @staticmethod
    def _count_by_severity(
        findings: list[UnifiedFinding],
    ) -> dict[str, int]:
        """Count findings grouped by severity.

        Delegates to :func:`investigation.sarif_utils.count_by_severity`
        (canonical implementation, DUP-008).
        """
        return count_by_severity(findings)
