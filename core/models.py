"""
REDACTS Unified Finding Model — Standards-compliant base for all findings.

Provides a common ``FindingBase`` that all finding types can be normalized
to, with fields for:

    - CVSS 3.1 scoring (numeric, not qualitative strings)
    - CWE identifiers (mandatory, not optional)
    - MITRE ATT&CK technique IDs
    - SARIF-compatible severity levels
    - Source tool attribution
    - Confidence scoring
    - Evidence chain references

This module is the bridge between REDACTS's internal finding types and
the interoperable output formats (SARIF v2.1.0, STIX v2.1).

All tools (Semgrep, Trivy, YARA, Magika, tree-sitter, SecurityScanner)
produce findings that are normalized through this model before export.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════


class SeverityLevel(Enum):
    """SARIF-compatible severity levels with CVSS 3.1 base score ranges."""

    CRITICAL = "critical"  # CVSS 9.0–10.0
    HIGH = "high"  # CVSS 7.0–8.9
    MEDIUM = "medium"  # CVSS 4.0–6.9
    LOW = "low"  # CVSS 0.1–3.9
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
    SECURITY_SCANNER = "security_scanner"  # Legacy regex rules
    IOC_DATABASE = "ioc_database"
    SENSITIVE_DATA = "sensitive_data"
    PHP_LINT = "php_lint"
    CLAMAV = "clamav"
    LIZARD = "lizard"
    COMPARISON = "comparison"  # Baseline diff findings
    DAST = "dast"  # Dynamic Application Security Testing (Playwright)
    MANUAL = "manual"


# ═══════════════════════════════════════════════════════════════════════════
# CVSS 3.1 Vector Support
# ═══════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════
# Unified Finding Model
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class UnifiedFinding:
    """Standards-compliant finding produced by any REDACTS tool.

    This is the canonical representation. All tool-specific findings
    are normalized to this format before SARIF/STIX export.

    Fields map directly to SARIF ``result`` objects and STIX ``indicator``
    SDOs for seamless interoperability.
    """

    # ── Identity ──────────────────────────────────────────────────────────
    id: str  # Unique ID: "{source}-{rule_id}-{hash}"
    rule_id: str  # Tool-specific rule: "SEC001", "semgrep:php-sqli", "CVE-2024-1234"
    title: str  # Human-readable one-liner
    description: str  # Full description with context

    # ── Classification ────────────────────────────────────────────────────
    severity: SeverityLevel
    confidence: Confidence
    source: FindingSource  # Which tool produced this
    category: str  # "injection", "webshell", "credential", "cve", etc.

    # ── Standards Mapping ─────────────────────────────────────────────────
    cwe_id: str = ""  # "CWE-89", "CWE-94", etc.
    cwe_name: str = ""  # "Improper Neutralization of Special Elements ..."
    mitre_attack_id: str = ""  # "T1505.003", "T1059.004", etc.
    mitre_attack_name: str = ""  # "Web Shell", "Unix Shell", etc.
    cvss: Optional[CvssVector] = None  # CVSS 3.1 vector + score
    cve_id: str = ""  # "CVE-2024-1234" (from Trivy/NVD)

    # ── Location ──────────────────────────────────────────────────────────
    file_path: str = ""  # Relative path to affected file
    line_start: int = 0  # Start line (1-based, 0 = unknown)
    line_end: int = 0  # End line (0 = same as start)
    column_start: int = 0  # Start column (0 = unknown)
    column_end: int = 0  # End column (0 = unknown)
    snippet: str = ""  # Code snippet at the location

    # ── Evidence ──────────────────────────────────────────────────────────
    recommendation: str = ""  # Remediation guidance
    evidence: dict[str, Any] = field(default_factory=dict)  # Tool-specific data
    related_finding_ids: list[str] = field(default_factory=list)  # Cross-references
    references: list[str] = field(default_factory=list)  # URLs, docs

    # ── Tool Metadata ─────────────────────────────────────────────────────
    tool_name: str = ""  # "semgrep", "trivy", "yara", etc.
    tool_version: str = ""  # Version that produced this finding
    tool_rule_url: str = ""  # URL to rule documentation

    # ── Cross-Tool Enrichment ─────────────────────────────────────────────
    corroborated_by: list[str] = field(default_factory=list)  # Other tools confirming
    magika_file_type: str = ""  # Magika's detected content type
    magika_mismatch: bool = False  # Whether Magika flagged type mismatch

    # ── Timestamps ────────────────────────────────────────────────────────
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
                taxa_entry["name"] = self.cwe_name
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


# ═══════════════════════════════════════════════════════════════════════════
# Normalizers — re-exported from core.normalizers for backward compatibility
# ═══════════════════════════════════════════════════════════════════════════

from .normalizers import (  # noqa: E402, F401 — backward-compat re-exports
    normalize_dast_result,
    normalize_magika_mismatch,
    normalize_security_finding,
    normalize_yara_match,
)


# ═══════════════════════════════════════════════════════════════════════════
# Finding Collection
# ═══════════════════════════════════════════════════════════════════════════


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

        When multiple tools flag the same file:line, mark each finding's
        ``corroborated_by`` list and upgrade confidence to CONFIRMED.
        """
        # Group by (file_path, line_start)
        by_location: dict[tuple[str, int], list[UnifiedFinding]] = {}
        for f in self.findings:
            if f.file_path and f.line_start > 0:
                key = (f.file_path, f.line_start)
                by_location.setdefault(key, []).append(f)

        for _loc, group in by_location.items():
            if len(group) < 2:
                continue
            # Multiple tools flagged the same location — corroborate
            sources = {f.source.value for f in group}
            if len(sources) < 2:
                continue
            for f in group:
                others = [
                    g.source.value for g in group
                    if g.source != f.source
                ]
                f.corroborated_by = list(set(f.corroborated_by + others))
                # Upgrade confidence when corroborated
                if f.confidence != Confidence.CONFIRMED:
                    f.confidence = Confidence.CONFIRMED

    def enrich_with_magika(
        self, magika_results: dict[str, Any]
    ) -> None:
        """Enrich findings with Magika file-type intelligence.

        Args:
            magika_results: Dict mapping file_path → MagikaResult
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
