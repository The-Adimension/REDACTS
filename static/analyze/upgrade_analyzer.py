"""
REDACTS Upgrade Process Analyzer - Detects persistence via upgrade hijacking.

INFINITERED modifies upgrade routines to:
  1. Inject backdoor code into new files during upgrade
  2. Skip deletion of compromised files
  3. Modify upgrade verification steps
  4. Create persistence in .htaccess or php.ini during upgrade

This analyzer detects anomalies in upgrade infrastructure.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.file_utils import _read_text_capped
from ..core.findings import SeverityStr

logger = logging.getLogger(__name__)


@dataclass
class UpgradeAnomaly:
    """An anomaly in upgrade infrastructure."""

    severity: SeverityStr
    category: str  # Logic hijack, file modification, skip logic, etc.
    file: str
    line: int
    message: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class UpgradeAnalysisReport:
    """Result of upgrade process analysis."""

    total_anomalies: int = 0
    critical: int = 0
    high: int = 0
    anomalies: list[UpgradeAnomaly] = field(default_factory=list)

    # Specific findings
    has_upgrade_hijack: bool = False
    has_skip_logic: bool = False
    has_persistence_injection: bool = False
    has_file_deletion_bypass: bool = False

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


class UpgradeAnalyzer:
    """Analyzes upgrade routines for persistence mechanisms."""

    RULES = [
        {
            "id": "UPG001",
            "severity": "CRITICAL",
            "category": "upgrade_hijack",
            "files": ["Upgrade.php", "upgrade.php"],
            "pattern": re.compile(
                r"""(?:eval|assert|create_function)\s*\(\s*\$(?:sql|query|patch|upgrade|code)""",
                re.IGNORECASE
            ),
            "message": "Dynamic code execution in upgrade process",
            "recommendation": "Verify upgrade logic is not dynamically evaluated. Rebuild from source.",
        },
        {
            "id": "UPG002",
            "severity": "CRITICAL",
            "category": "upgrade_hijack",
            "files": ["Upgrade.php"],
            "pattern": re.compile(
                r"""preg_replace\s*\([^)]*\/[eimsxADSUXJu]*e[eimsxADSUXJu]*['\"]""",
                re.IGNORECASE
            ),
            "message": "preg_replace with /e modifier in upgrade (code execution)",
            "recommendation": "Remove /e modifier. Use preg_replace_callback instead.",
        },
        {
            "id": "UPG003",
            "severity": "CRITICAL",
            "category": "upgrade_hijack",
            "files": ["Upgrade.php"],
            "pattern": re.compile(
                r"""\$\{?\$[a-zA-Z_][a-zA-Z0-9_]*\}?\s*\(""",
                re.IGNORECASE
            ),
            "message": "Variable function call in upgrade ($var())",
            "recommendation": "Use explicit function names instead of variables.",
        },

        # ===== FILE DELETION BYPASS =====
        {
            "id": "UPG010",
            "severity": "HIGH",
            "category": "file_deletion_bypass",
            "files": ["Upgrade.php"],
            "pattern": re.compile(
                r"""if\s*\([^)]*\$\w+\s*(!==?|===?|in_array)""",
                re.IGNORECASE
            ),
            "message": "Conditional file deletion (may skip infected files)",
            "recommendation": "Verify all files listed for deletion are actually deleted.",
        },
        # UPG011 (bare `@?unlink(...)`) was removed: REDCap's own upgrade routine
        # deletes files as normal housekeeping, so the rule fired on every
        # upgrade script and buried the real signals below.

        # ===== INFINITERED UPGRADE-ARCHIVE INJECTION (GTIG) =====
        # Published mechanism: the dropper opens the REDCap upgrade archive,
        # pulls the hooks/auth/upgrade members, and rewrites them so the implant
        # is re-injected on every upgrade. Strings are verbatim from GTIG YARA
        # G_Backdoor_INFINITERED_1 ($u4-$u9, $marker).
        # Source: https://cloud.google.com/blog/topics/threat-intelligence/prc-targets-us-medical-research
        # Retrieved: 2026-07-28
        {
            "id": "UPG060",
            "severity": "CRITICAL",
            "category": "infinitered",
            "files": ["Upgrade.php", "upgrade.php"],
            "pattern": re.compile(
                r"""\$zip->getFromName\s*\(\s*\$file_(?:hooks|auth|upgrade)\s*\)"""
            ),
            "message": "INFINITERED upgrade-archive injection: reads hooks/auth/upgrade from the upgrade ZIP (GTIG)",
            "recommendation": (
                "GTIG-published INFINITERED persistence mechanism. Preserve the file "
                "and timestamps, isolate the host, and verify the integrity of your "
                "REDCap upgrade packages before re-running them."
            ),
        },
        {
            "id": "UPG061",
            "severity": "CRITICAL",
            "category": "infinitered",
            "files": ["Upgrade.php", "upgrade.php"],
            "pattern": re.compile(
                r"""str_replace\s*\(\s*\$search_content\s*,\s*\$(?:hooks|auth|upgrade)_decode\s*,"""
            ),
            "message": "INFINITERED upgrade-archive rewrite: re-injects implant into upgrade content (GTIG)",
            "recommendation": (
                "GTIG-published INFINITERED re-injection step. Same handling as UPG050."
            ),
        },
        {
            "id": "UPG062",
            "severity": "CRITICAL",
            "category": "infinitered",
            "files": ["Upgrade.php", "upgrade.php"],
            "pattern": re.compile(
                r"""b49e334d-9c01-463e-9bc5-00a6920fb66e""",
                re.IGNORECASE
            ),
            "message": "INFINITERED GUID marker in upgrade routine (GTIG)",
            "recommendation": (
                "GTIG-published delimiter GUID used by the INFINITERED dropper. "
                "Confirmed family evidence - follow your incident-response process."
            ),
        },

        # ===== PERSISTENCE INJECTION =====
        {
            "id": "UPG020",
            "severity": "CRITICAL",
            "category": "persistence_injection",
            "files": ["Upgrade.php", ".htaccess"],
            "pattern": re.compile(
                r"""auto_prepend_file|auto_append_file|php_value|SetHandler|AddHandler""",
                re.IGNORECASE
            ),
            "message": "PHP config modification during upgrade",
            "recommendation": "Verify no config changes are injected via upgrade.",
        },
        {
            "id": "UPG021",
            "severity": "CRITICAL",
            "category": "persistence_injection",
            "files": ["Upgrade.php"],
            "pattern": re.compile(
                r"""fopen\s*\([^)]*\.(?:htaccess|user\.ini|php\.ini)""",
                re.IGNORECASE
            ),
            "message": "Writing to web config during upgrade",
            "recommendation": "Verify upgrade does not modify .htaccess, .user.ini, etc.",
        },

        # ===== SKIP LOGIC / VERIFICATION BYPASS =====
        # UPG030 (bare `return|die|exit|skip|continue`) was removed: it matched
        # ordinary control flow in every PHP file, producing noise rather than
        # evidence. UPG031 keeps the specific "skip if empty" shape.
        {
            "id": "UPG031",
            "severity": "HIGH",
            "category": "skip_logic",
            "files": ["Upgrade.php"],
            "pattern": re.compile(
                r"""if\s*\(!\$\w+\)\s*return|if\s*\(empty\(\$\w+\)\)\s*return""",
                re.IGNORECASE
            ),
            "message": "Skips upgrade if variable empty (could be manipulated)",
            "recommendation": "Validate inputs before early returns.",
        },

        # ===== OBFUSCATION / ENCODING IN UPGRADE =====
        {
            "id": "UPG040",
            "severity": "CRITICAL",
            "category": "obfuscation",
            "files": ["Upgrade.php"],
            "pattern": re.compile(
                r"""(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(""",
                re.IGNORECASE
            ),
            "message": "Obfuscated/compressed code in upgrade",
            "recommendation": "Decode and inspect. Obfuscation has no place in upgrade.",
        },

        # ===== CREDENTIAL/CONFIG TAMPERING =====
        {
            "id": "UPG050",
            "severity": "HIGH",
            "category": "config_tampering",
            "files": ["Upgrade.php", "database.php"],
            "pattern": re.compile(
                r"""\$db_password|\$db_user|\$db_connection|database\.php""",
                re.IGNORECASE
            ),
            "message": "Database credentials accessed during upgrade",
            "recommendation": "Verify upgrade doesn't read/modify database.php.",
        },
    ]

    def analyze_directory(self, root: Path) -> UpgradeAnalysisReport:
        """Analyze all upgrade-related files in a directory."""
        report = UpgradeAnalysisReport()

        # Find all upgrade-related files
        upgrade_files = self._find_upgrade_files(root)

        for file_path in upgrade_files:
            anomalies = self._analyze_file(file_path, root)
            report.anomalies.extend(anomalies)

        # Aggregate
        report.total_anomalies = len(report.anomalies)
        report.critical = sum(1 for a in report.anomalies if a.severity == "CRITICAL")
        report.high = sum(1 for a in report.anomalies if a.severity == "HIGH")

        # Risk categorization
        report.has_upgrade_hijack = any(
            a.category == "upgrade_hijack" for a in report.anomalies
        )
        report.has_skip_logic = any(
            a.category == "skip_logic" for a in report.anomalies
        )
        report.has_persistence_injection = any(
            a.category == "persistence_injection" for a in report.anomalies
        )
        report.has_file_deletion_bypass = any(
            a.category == "file_deletion_bypass" for a in report.anomalies
        )

        return report

    def _find_upgrade_files(self, root: Path) -> list[Path]:
        """Find all upgrade-related files."""
        upgrade_patterns = {
            "**/Upgrade.php",
            "**/upgrade.php",
            "**/Classes/Upgrade.php",
            "**/.htaccess",
            "**/database.php",
        }

        found = []
        for pattern in upgrade_patterns:
            found.extend(root.glob(pattern))

        return list(set(found))

    def _analyze_file(self, file_path: Path, root: Path) -> list[UpgradeAnomaly]:
        """Analyze a single file for upgrade anomalies."""
        anomalies = []

        try:
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path)

        try:
            content = _read_text_capped(file_path)
        except Exception:
            return anomalies

        lines = content.splitlines()

        for rule in self.RULES:
            # Check if this rule applies to this file
            if rule["files"]:
                file_matches = any(
                    file_path.name.lower() == f.lower()
                    for f in rule["files"]
                )
                if not file_matches:
                    continue

            for match in rule["pattern"].finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""

                # Skip comments
                if self._is_in_comment(content, match.start()):
                    continue

                anomaly = UpgradeAnomaly(
                    severity=rule["severity"],
                    category=rule["category"],
                    file=rel_path,
                    line=line_no,
                    message=rule["message"],
                    evidence=snippet[:150],
                    recommendation=rule.get("recommendation", ""),
                )
                anomalies.append(anomaly)

        return anomalies

    def _is_in_comment(self, content: str, pos: int) -> bool:
        """Check if position is inside a comment."""
        # Block comments
        block_open = content.rfind("/*", 0, pos)
        if block_open != -1:
            block_close = content.find("*/", block_open)
            if block_close == -1 or block_close > pos:
                return True

        # Line comments
        line_start = content.rfind("\n", 0, pos) + 1
        line_text = content[line_start:pos]
        if "//" in line_text or "#" in line_text:
            return True

        return False
