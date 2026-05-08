"""Unified finding model.

Every scanner in REDACTS \u2014 the in-house regex/SEC* rules, the tree-sitter\nPHP analyser, and the external integrations (Semgrep, Trivy, YARA,\nMagika) \u2014 emits findings into a single ``UnifiedFinding`` shape.\nNormalisation happens at the boundary so downstream code (HTML report,\nSARIF) never has to ``isinstance``-check.

The fields look SARIF-shaped on purpose: that is what the security team\nimporting our reports into their existing pipelines is going to ask for\nfirst, and SARIF is also what GitHub Code Scanning consumes.

Note on CVSS: vectors are stored as parsed objects (``CvssVector``), not\nstrings. Anyone scoring rules by hand should put the numeric vector in\nthe rule YAML; the qualitative band (``HIGH`` / ``MEDIUM`` / ...) is a\nderived view, not the source of truth.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

logger = logging.getLogger(__name__)


# Uppercase severity-string used by Tier-2 finding dataclasses
# (InvestigationFinding, SecurityFinding, BaselineIntegrityFinding,
# UpgradeFinding, DatabaseForensicsFinding). The SARIF-aligned
# ``SeverityLevel`` enum below uses lowercase values and is the
# canonical type for ``UnifiedFinding``.
SeverityStr = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class SeverityLevel(Enum):
    """SARIF-compatible severity levels with CVSS 3.1 base score ranges."""

    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"  # CVSS 7.0-8.9
    MEDIUM = "medium"  # CVSS 4.0-6.9
    LOW = "low"  # CVSS 0.1-3.9
    INFO = "info"  # CVSS 0.0 (informational)

    @property
    def sarif_level(self) -> str:
        """Map to SARIF result.level vocabulary."""
        return {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }[self.value]

    @property
    def numeric_rank(self) -> int:
        """Numeric rank for sorting (higher = more severe)."""
        return {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }[self.value]

    @classmethod
    def from_string(cls, s: str) -> "SeverityLevel":
        """Parse a severity string (case-insensitive)."""
        normalized = s.strip().lower()
        for member in cls:
            if member.value == normalized:
                return member
        # Handle common aliases
        aliases = {
            "error": cls.HIGH,
            "warning": cls.MEDIUM,
            "note": cls.LOW,
            "none": cls.INFO,
        }
        if normalized in aliases:
            return aliases[normalized]
        raise ValueError(
            f"Unknown severity: '{s}'. "
            f"Valid: {', '.join(m.value for m in cls)}"
        )

    @classmethod
    def from_cvss(cls, score: float) -> "SeverityLevel":
        """Derive severity from a CVSS 3.1 base score."""
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 0.1:
            return cls.LOW
        return cls.INFO


class Confidence(Enum):
    """Confidence level in a finding's accuracy."""

    CONFIRMED = "confirmed"  # Multiple tools agree or tool is definitive
    HIGH = "high"  # Single authoritative tool with strong signal
    MEDIUM = "medium"  # Heuristic-based detection
    LOW = "low"  # Pattern match only, needs verification
    TENTATIVE = "tentative"  # Weak signal, likely false positive


class FindingSource(Enum):
    """Which tool/module produced the finding."""

    SEMGREP = "semgrep"
    TRIVY = "trivy"
    YARA = "yara"
    MAGIKA = "magika"
    TREE_SITTER = "tree_sitter"
    SECURITY_SCANNER = "security_scanner"  # Regex rules
    IOC_DATABASE = "ioc_database"
    SENSITIVE_DATA = "sensitive_data"
    PHP_LINT = "php_lint"
    CLAMAV = "clamav"
    LIZARD = "lizard"
    COMPARISON = "comparison"  # Baseline diff findings
    DAST = "dast"  # Dynamic Application Security Testing (Playwright)
    MANUAL = "manual"




@dataclass(frozen=True)
class CvssVector:
    """CVSS 3.1 base score vector.

    Stores the vector string and pre-computed base score.
    Full CVSS 3.1 computation is complex; we store known mappings
    for REDACTS rules and parse Semgrep/Trivy-provided scores directly.
    """

    vector_string: str = ""  # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    base_score: float = 0.0

    @property
    def severity(self) -> SeverityLevel:
        return SeverityLevel.from_cvss(self.base_score)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "severity": self.severity.value,
        }




@dataclass
class UnifiedFinding:
    """Canonical finding produced by any REDACTS scanner or external tool.

    Every tool-specific finding (SEC* regex, tree-sitter, Semgrep, Trivy,
    YARA, IoC) is normalised to this shape before reporting and SARIF
    export. Field names align deliberately with SARIF ``result`` and
    STIX ``indicator`` SDOs so the export layer is mechanical, not
    interpretive.
    """

    # Identity
    id: str  # Unique ID: "{source}-{rule_id}-{hash}"
    rule_id: str  # Tool-specific rule: "SEC001", "semgrep:php-sqli", "CVE-2024-1234"
    title: str  # Human-readable one-liner
    description: str  # Full description with context

    # Classification
    severity: SeverityLevel
    confidence: Confidence
    source: FindingSource  # Which tool produced this
    category: str  # "injection", "webshell", "credential", "cve", etc.

    # Standards Mapping
    cwe_id: str = ""  # "CWE-89", "CWE-94", etc.
    cwe_name: str = ""  # "Improper Neutralization of Special Elements ..."
    mitre_attack_id: str = ""  # "T1505.003", "T1059.004", etc.
    mitre_attack_name: str = ""  # "Web Shell", "Unix Shell", etc.
    cvss: CvssVector | None = None  # CVSS 3.1 vector + score
    cve_id: str = ""  # "CVE-2024-1234" (from Trivy/NVD)

    # Location
    file_path: str = ""  # Relative path to affected file
    line_start: int = 0  # Start line (1-based, 0 = unknown)
    line_end: int = 0  # End line (0 = same as start)
    column_start: int = 0  # Start column (0 = unknown)
    column_end: int = 0  # End column (0 = unknown)
    snippet: str = ""  # Code snippet at the location

    # Evidence
    recommendation: str = ""  # Remediation guidance
    evidence: dict[str, Any] = field(default_factory=dict)  # Tool-specific data
    related_finding_ids: list[str] = field(default_factory=list)  # Cross-references
    references: list[str] = field(default_factory=list)  # URLs, docs

    # Tool Metadata
    tool_name: str = ""  # "semgrep", "trivy", "yara", etc.
    tool_version: str = ""  # Version that produced this finding
    tool_rule_url: str = ""  # URL to rule documentation

    # Cross-Tool Enrichment
    corroborated_by: list[str] = field(default_factory=list)  # Other tools confirming
    magika_file_type: str = ""  # Magika's detected content type
    magika_mismatch: bool = False  # Whether Magika flagged type mismatch

    # Timestamps
    detected_at: str = ""  # ISO 8601 timestamp

    def __post_init__(self) -> None:
        if not self.detected_at:
            self.detected_at = datetime.now(timezone.utc).isoformat()
        if not self.id:
            self.id = self._generate_id()

    def _generate_id(self) -> str:
        """Generate a deterministic finding ID from key fields."""
        content = f"{self.source.value}:{self.rule_id}:{self.file_path}:{self.line_start}"
        digest = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"{self.source.value.upper()}-{digest}"

    @property
    def sarif_level(self) -> str:
        """SARIF result.level for this finding."""
        return self.severity.sarif_level

    @property
    def fingerprint(self) -> str:
        """Stable fingerprint for deduplication across runs."""
        content = f"{self.rule_id}:{self.file_path}:{self.line_start}:{self.snippet[:50]}"
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["source"] = self.source.value
        if self.cvss:
            d["cvss"] = self.cvss.to_dict()
        return d

    def to_sarif_result(self) -> dict[str, Any]:
        """Convert to a SARIF v2.1.0 result object."""
        result: dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.sarif_level,
            "message": {"text": self.description},
            "fingerprints": {
                "redacts/v1": self.fingerprint,
            },
            "properties": {
                "source": self.source.value,
                "confidence": self.confidence.value,
                "category": self.category,
            },
        }

        # Location
        if self.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": self.file_path,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
            if self.line_start > 0:
                region: dict[str, Any] = {"startLine": self.line_start}
                if self.line_end > 0:
                    region["endLine"] = self.line_end
                if self.column_start > 0:
                    region["startColumn"] = self.column_start
                if self.column_end > 0:
                    region["endColumn"] = self.column_end
                if self.snippet:
                    region["snippet"] = {"text": self.snippet}
                location["physicalLocation"]["region"] = region
            result["locations"] = [location]

        # Standards mapping in properties
        if self.cwe_id:
            result["properties"]["cwe"] = self.cwe_id
            taxa_entry: dict[str, Any] = {
                "toolComponent": {"name": "CWE"},
                "id": self.cwe_id.replace("CWE-", ""),
            }
            if self.cwe_name:
                taxa_entry["properties"] = {"name": self.cwe_name}
            result["taxa"] = [taxa_entry]
        if self.mitre_attack_id:
            result["properties"]["mitre_attack"] = {
                "technique_id": self.mitre_attack_id,
                "technique_name": self.mitre_attack_name,
            }
        if self.cvss:
            result["properties"]["cvss"] = self.cvss.to_dict()
        if self.cve_id:
            result["properties"]["cve"] = self.cve_id

        # Cross-tool enrichment
        if self.corroborated_by:
            result["properties"]["corroborated_by"] = self.corroborated_by
        if self.magika_file_type:
            result["properties"]["magika_file_type"] = self.magika_file_type
            result["properties"]["magika_mismatch"] = self.magika_mismatch

        return result




def normalize_security_finding(
    finding: Any,
    *,
    mitre_map: dict[str, tuple[str, str]] | None = None,
    cvss_map: dict[str, CvssVector] | None = None,
) -> UnifiedFinding:
    """Normalize a ``SecurityFinding`` from security_scanner.py.

    Args:
        finding: SecurityFinding dataclass instance
        mitre_map: rule_id -> (technique_id, technique_name) mapping
        cvss_map: rule_id -> CvssVector mapping
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
) -> UnifiedFinding | None:
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
        title=f"Content-type masquerading: {result.extension_label} -> {result.label}",
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
    rule_metadata: dict[str, Any] | None = None,
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
) -> UnifiedFinding | None:
    """Normalize a DAST test result to a UnifiedFinding.

    Only FAILED tests produce findings - passed tests are evidence
    the application is secure at that point.

    Args:
        test_result: Dict with keys: suite, test, status, error, annotations
        suite: DAST suite name (admin, export, upgrade)
    """
    status = test_result.get("status", "")
    if status not in ("failed", "error"):
        return None  # Only failures / errors are findings

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

    is_error = status == "error"
    severity = SeverityLevel.MEDIUM if is_error else SeverityLevel.HIGH
    confidence = Confidence.HIGH if is_error else Confidence.CONFIRMED
    verb = "ERROR" if is_error else "FAILED"

    return UnifiedFinding(
        id="",
        rule_id=rule_id,
        title=f"DAST [{suite_name}]: {test_name}",
        description=(
            f"Dynamic test {verb} - {test_name}. "
            f"Error: {error_msg[:300]}" if error_msg else
            f"Dynamic test {verb} - {test_name}"
        ),
        severity=severity,
        confidence=confidence,
        source=FindingSource.DAST,
        category=category,
        cwe_id=cwe,
        mitre_attack_id=mitre_id,
        mitre_attack_name=mitre_name,
        tool_name="playwright-dast",
        evidence={"suite": suite_name, "test": test_name, "error": error_msg},
    )


# DAST test -> SEC rule mapping
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




@dataclass
class FindingCollection:
    """Aggregated collection of unified findings from all tools.

    Provides deduplication, severity ranking, cross-tool correlation,
    and export to SARIF/STIX formats.
    """

    findings: list[UnifiedFinding] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    scan_started: str = ""
    scan_completed: str = ""
    target_path: str = ""
    baseline_path: str = ""

    def __post_init__(self) -> None:
        if not self.scan_started:
            self.scan_started = datetime.now(timezone.utc).isoformat()

    def add(self, finding: UnifiedFinding) -> None:
        """Add a finding, checking for duplicates by fingerprint."""
        existing_fps = {f.fingerprint for f in self.findings}
        if finding.fingerprint not in existing_fps:
            self.findings.append(finding)

    def add_many(self, findings: list[UnifiedFinding]) -> int:
        """Add multiple findings, returning count of new (non-duplicate) ones."""
        added = 0
        for f in findings:
            before = len(self.findings)
            self.add(f)
            if len(self.findings) > before:
                added += 1
        return added

    def correlate(self) -> None:
        """Cross-reference findings from different tools on the same location.

        Findings are grouped by a *normalized* (path, line) key:

        * The path is converted to forward-slash form, made relative
          to ``self.target_path`` when an absolute path lies under it,
          and (on Windows-style paths) lower-cased.
        * The line number is bucketed to a 3-line window so adjacent
          reports of the same issue from two tools (e.g. Semgrep at
          line 42, regex at line 43) still corroborate.

        When two distinct tools land in the same bucket, every finding
        in the bucket is upgraded to ``Confidence.CONFIRMED`` and gets
        the other tools' ``source.value`` recorded in
        ``corroborated_by``.
        """
        from pathlib import PurePath

        target_root: PurePath | None = None
        if self.target_path:
            try:
                target_root = PurePath(self.target_path)
            except (TypeError, ValueError):
                target_root = None

        def _normalize_path(raw: str) -> str:
            if not raw:
                return ""
            p = PurePath(raw)
            rel: PurePath = p
            if target_root is not None and p.is_absolute():
                try:
                    rel = p.relative_to(target_root)
                except ValueError:
                    rel = p
            text = rel.as_posix()
            if "\\" in raw or (len(raw) > 1 and raw[1] == ":"):
                text = text.lower()
            return text

        WINDOW = 3
        by_location: dict[tuple[str, int], list[UnifiedFinding]] = {}
        for f in self.findings:
            if not f.file_path:
                continue
            normalized = _normalize_path(f.file_path)
            line = f.line_start if f.line_start > 0 else 0
            bucket = line // WINDOW if line > 0 else 0
            key = (normalized, bucket)
            by_location.setdefault(key, []).append(f)

        for _key, group in by_location.items():
            if len(group) < 2:
                continue
            sources = {f.source.value for f in group}
            if len(sources) < 2:
                continue
            for f in group:
                others = [
                    g.source.value for g in group
                    if g.source != f.source
                ]
                f.corroborated_by = list(set(f.corroborated_by + others))
                if f.confidence != Confidence.CONFIRMED:
                    f.confidence = Confidence.CONFIRMED

    def enrich_with_magika(
        self, magika_results: dict[str, Any]
    ) -> None:
        """Enrich findings with Magika file-type intelligence.

        Args:
            magika_results: Dict mapping file_path -> MagikaResult
        """
        for f in self.findings:
            if f.file_path in magika_results:
                mr = magika_results[f.file_path]
                f.magika_file_type = mr.label if hasattr(mr, "label") else str(mr.get("label", ""))
                if hasattr(mr, "content_type_match"):
                    f.magika_mismatch = not mr.content_type_match
                elif isinstance(mr, dict):
                    f.magika_mismatch = not mr.get("content_type_match", True)

    @property
    def by_severity(self) -> dict[str, list[UnifiedFinding]]:
        """Group findings by severity level."""
        groups: dict[str, list[UnifiedFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.severity.value, []).append(f)
        return groups

    @property
    def by_source(self) -> dict[str, list[UnifiedFinding]]:
        """Group findings by source tool."""
        groups: dict[str, list[UnifiedFinding]] = {}
        for f in self.findings:
            groups.setdefault(f.source.value, []).append(f)
        return groups

    @property
    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {s.value: 0 for s in SeverityLevel}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def corroborated_findings(self) -> list[UnifiedFinding]:
        """Findings confirmed by multiple tools."""
        return [f for f in self.findings if f.corroborated_by]

    def summary(self) -> dict[str, Any]:
        """Generate a summary dict."""
        return {
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "source_counts": {k: len(v) for k, v in self.by_source.items()},
            "corroborated_count": len(self.corroborated_findings),
            "tool_versions": self.tool_versions,
            "scan_started": self.scan_started,
            "scan_completed": self.scan_completed,
            "target_path": self.target_path,
            "baseline_path": self.baseline_path,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return {
            "summary": self.summary(),
            "findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda x: x.severity.numeric_rank,
                reverse=True,
            )],
        }
