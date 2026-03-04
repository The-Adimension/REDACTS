"""
Normalizers — convert tool-specific findings to :class:`UnifiedFinding`.

Extracted from :mod:`core.models` (Step 5.3) to separate data-model
definitions from business-logic transformation functions.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .models import (
    Confidence,
    CvssVector,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Normalizers — convert tool-specific findings to UnifiedFinding
# ═══════════════════════════════════════════════════════════════════════════


def normalize_security_finding(
    finding: Any,
    *,
    mitre_map: Optional[dict[str, tuple[str, str]]] = None,
    cvss_map: Optional[dict[str, CvssVector]] = None,
) -> UnifiedFinding:
    """Normalize a ``SecurityFinding`` from security_scanner.py.

    Args:
        finding: SecurityFinding dataclass instance
        mitre_map: rule_id → (technique_id, technique_name) mapping
        cvss_map: rule_id → CvssVector mapping
    """
    mitre_map = mitre_map or {}
    cvss_map = cvss_map or {}

    mitre_id, mitre_name = mitre_map.get(finding.rule, ("", ""))
    cvss = cvss_map.get(finding.rule)

    return UnifiedFinding(
        id="",
        rule_id=finding.rule,
        title=finding.message,
        description=f"{finding.message} in {finding.file}:{finding.line}",
        severity=SeverityLevel.from_string(finding.severity),
        confidence=Confidence.MEDIUM,  # Regex-based = medium confidence
        source=FindingSource.SECURITY_SCANNER,
        category=finding.category,
        cwe_id=finding.cwe or "",
        mitre_attack_id=mitre_id,
        mitre_attack_name=mitre_name,
        cvss=cvss,
        file_path=finding.file,
        line_start=finding.line,
        snippet=finding.snippet,
        recommendation=finding.recommendation,
    )


def normalize_magika_mismatch(
    result: Any, *, file_path: str = ""
) -> Optional[UnifiedFinding]:
    """Normalize a Magika content-type mismatch into a finding."""
    if result.content_type_match:
        return None

    severity_map = {
        "critical": SeverityLevel.CRITICAL,
        "suspicious": SeverityLevel.HIGH,
        "info": SeverityLevel.LOW,
        "none": SeverityLevel.INFO,
    }

    return UnifiedFinding(
        id="",
        rule_id=f"MAGIKA-{result.label.upper()}-MISMATCH",
        title=f"Content-type masquerading: {result.extension_label} → {result.label}",
        description=result.mismatch_detail,
        severity=severity_map.get(result.mismatch_severity, SeverityLevel.MEDIUM),
        confidence=Confidence.HIGH,  # Magika ML model = high confidence
        source=FindingSource.MAGIKA,
        category="content_type_masquerading",
        cwe_id="CWE-434",  # Unrestricted Upload of File with Dangerous Type
        mitre_attack_id="T1036.008",  # Masquerading: File Type
        mitre_attack_name="Masquerading: Masquerade File Type",
        file_path=file_path,
        magika_file_type=result.label,
        magika_mismatch=True,
        evidence={
            "expected_type": result.extension_label,
            "actual_type": result.label,
            "mime_type": result.mime_type,
            "confidence_score": result.score,
            "description": result.description,
        },
    )


def normalize_yara_match(
    match: dict[str, str],
    *,
    rule_metadata: Optional[dict[str, Any]] = None,
) -> UnifiedFinding:
    """Normalize a YARA match dict to a UnifiedFinding."""
    meta = rule_metadata or {}
    return UnifiedFinding(
        id="",
        rule_id=f"YARA-{match.get('rule', 'UNKNOWN')}",
        title=f"YARA match: {match.get('rule', 'unknown')}",
        description=meta.get("description", f"YARA rule '{match.get('rule')}' matched"),
        severity=SeverityLevel.from_string(meta.get("severity", "HIGH")),
        confidence=Confidence.HIGH,  # YARA pattern match = high confidence
        source=FindingSource.YARA,
        category=meta.get("category", "malware"),
        cwe_id=meta.get("cwe", ""),
        mitre_attack_id=meta.get("mitre_attack", "T1505.003"),
        mitre_attack_name=meta.get("mitre_attack_name", "Web Shell"),
        file_path=match.get("target", ""),
        references=meta.get("references", []),
        tool_name="yara",
    )


def normalize_dast_result(
    test_result: dict[str, Any],
    *,
    suite: str = "",
) -> Optional[UnifiedFinding]:
    """Normalize a DAST test result to a UnifiedFinding.

    Only FAILED tests produce findings — passed tests are evidence
    the application is secure at that point.

    Args:
        test_result: Dict with keys: suite, test, status, error, annotations
        suite: DAST suite name (admin, export, upgrade)
    """
    status = test_result.get("status", "")
    if status != "failed":
        return None  # Only failures are findings

    test_name = test_result.get("test", "unknown")
    error_msg = test_result.get("error", "")
    suite_name = test_result.get("suite", suite)

    # Map test names to SEC rules and MITRE techniques
    rule_mapping = _DAST_RULE_MAP.get(suite_name, {})
    rule_info = None
    for keyword, info in rule_mapping.items():
        if keyword.lower() in test_name.lower():
            rule_info = info
            break

    rule_id = rule_info["rule_id"] if rule_info else f"DAST-{suite_name.upper()}"
    mitre_id = rule_info["mitre"] if rule_info else "T1190"
    mitre_name = rule_info["mitre_name"] if rule_info else "Exploit Public-Facing Application"
    cwe = rule_info["cwe"] if rule_info else "CWE-693"
    category = rule_info["category"] if rule_info else "runtime-security"

    return UnifiedFinding(
        id="",
        rule_id=rule_id,
        title=f"DAST [{suite_name}]: {test_name}",
        description=(
            f"Dynamic test FAILED — {test_name}. "
            f"Error: {error_msg[:300]}" if error_msg else
            f"Dynamic test FAILED — {test_name}"
        ),
        severity=SeverityLevel.HIGH,  # DAST failures = runtime-confirmed
        confidence=Confidence.CONFIRMED,  # Runtime-verified
        source=FindingSource.DAST,
        category=category,
        cwe_id=cwe,
        mitre_attack_id=mitre_id,
        mitre_attack_name=mitre_name,
        tool_name="playwright-dast",
        evidence={"suite": suite_name, "test": test_name, "error": error_msg},
    )


# DAST test → SEC rule mapping
_DAST_RULE_MAP: dict[str, dict[str, dict[str, str]]] = {
    "admin": {
        "Control Center": {"rule_id": "SEC077", "mitre": "T1078", "mitre_name": "Valid Accounts", "cwe": "CWE-285", "category": "access-control"},
        "unauthenticated": {"rule_id": "SEC021", "mitre": "T1078", "mitre_name": "Valid Accounts", "cwe": "CWE-306", "category": "authentication"},
        "API": {"rule_id": "SEC077", "mitre": "T1550", "mitre_name": "Use Alternate Auth Material", "cwe": "CWE-287", "category": "authentication"},
        "cookie": {"rule_id": "SEC071", "mitre": "T1539", "mitre_name": "Steal Web Session Cookie", "cwe": "CWE-614", "category": "session"},
        "config": {"rule_id": "SEC065", "mitre": "T1082", "mitre_name": "System Information Discovery", "cwe": "CWE-200", "category": "information-disclosure"},
        "audit": {"rule_id": "SEC021", "mitre": "T1078", "mitre_name": "Valid Accounts", "cwe": "CWE-778", "category": "logging"},
    },
    "export": {
        "CSV": {"rule_id": "SEC070", "mitre": "T1059.004", "mitre_name": "Unix Shell", "cwe": "CWE-94", "category": "injection"},
        "PDF": {"rule_id": "SEC074", "mitre": "T1203", "mitre_name": "Exploitation for Client Execution", "cwe": "CWE-79", "category": "injection"},
        "XSS": {"rule_id": "SEC010", "mitre": "T1059.007", "mitre_name": "JavaScript", "cwe": "CWE-79", "category": "xss"},
        "info leak": {"rule_id": "SEC031", "mitre": "T1082", "mitre_name": "System Information Discovery", "cwe": "CWE-200", "category": "information-disclosure"},
        "export": {"rule_id": "SEC076", "mitre": "T1530", "mitre_name": "Data from Cloud Storage", "cwe": "CWE-862", "category": "authorization"},
    },
    "upgrade": {
        "filesystem": {"rule_id": "SEC060", "mitre": "T1505.003", "mitre_name": "Web Shell", "cwe": "CWE-506", "category": "persistence"},
        "PHP file": {"rule_id": "SEC060", "mitre": "T1505.003", "mitre_name": "Web Shell", "cwe": "CWE-506", "category": "persistence"},
        "suspicious": {"rule_id": "SEC062", "mitre": "T1027", "mitre_name": "Obfuscated Files or Information", "cwe": "CWE-506", "category": "persistence"},
        "external network": {"rule_id": "SEC061", "mitre": "T1071.001", "mitre_name": "Web Protocols", "cwe": "CWE-506", "category": "c2"},
        "cron": {"rule_id": "SEC063", "mitre": "T1053", "mitre_name": "Scheduled Task/Job", "cwe": "CWE-506", "category": "persistence"},
    },
}
