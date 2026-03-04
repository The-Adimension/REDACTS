"""
REDACTS Security Scanner - Security-focused code analysis.
"""

from __future__ import annotations

import logging
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.constants import get_scannable_extensions, get_skip_dirs
from .security_rules import SECURITY_RULES

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """A single security finding."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # injection, xss, credentials, etc.
    rule: str  # Rule identifier
    file: str  # File path
    line: int  # Line number
    message: str  # Description
    snippet: str = ""  # Code snippet
    recommendation: str = ""  # Fix recommendation
    cwe: str = ""  # CWE identifier if applicable


@dataclass
class SecurityReport:
    """Security scan report."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    findings: list[SecurityFinding] = field(default_factory=list)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    scanned_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


class SecurityScanner:
    """Security scanner for PHP/web codebases."""

    RULES = SECURITY_RULES
    """Security rules loaded from :mod:`forensics.security_rules`."""

    #: Skip files larger than 10 MB to avoid catastrophic regex backtracking
    #: on generated report files or other large artefacts.
    MAX_SCAN_FILE_BYTES: int = 10 * 1024 * 1024

    # Webshell signature rules — loaded once from the knowledge base.
    # These complement the static RULES list with IoC-database-sourced patterns.
    _WEBSHELL_RULES: list[dict] | None = None

    @classmethod
    def _load_webshell_rules(cls) -> list[dict]:
        """Load and compile WEBSHELL_SIGNATURES from the knowledge base.

        Returns cached rules on subsequent calls. Each signature is
        converted into the same dict format used by cls.RULES so the
        scan loop can process them uniformly.
        """
        if cls._WEBSHELL_RULES is not None:
            return cls._WEBSHELL_RULES

        try:
            from ..knowledge.ioc_database import WEBSHELL_SIGNATURES
        except ImportError:
            cls._WEBSHELL_RULES = []
            return cls._WEBSHELL_RULES

        rules: list[dict] = []
        for idx, sig in enumerate(WEBSHELL_SIGNATURES):
            try:
                compiled = re.compile(sig["pattern"], re.IGNORECASE)
                rules.append(
                    {
                        "id": f"WEB{idx:03d}",
                        "severity": sig.get("severity", "HIGH"),
                        "category": "webshell",
                        "pattern": compiled,
                        "message": f"Webshell signature: {sig['name']}",
                        "cwe": "CWE-506",
                        "recommendation": (
                            f"Matched webshell signature '{sig['name']}' "
                            f"(conclusiveness: {sig.get('conclusiveness', 'suspicious')}). "
                            "Investigate immediately."
                        ),
                    }
                )
            except re.error as exc:
                logger.warning(
                    "Failed to compile webshell signature %s: %s",
                    sig.get("name", f"#{idx}"),
                    exc,
                )

        cls._WEBSHELL_RULES = rules
        logger.debug("Loaded %d webshell signature rules from knowledge base", len(rules))
        return cls._WEBSHELL_RULES

    def scan_file(self, file_path: Path, root: Path) -> list[SecurityFinding]:
        """Scan a single file for security issues."""
        findings = []

        try:
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_path = str(file_path)

        # Guard: skip files that are unreasonably large for source code.
        try:
            file_size = file_path.stat().st_size
        except OSError:
            return findings
        if file_size > self.MAX_SCAN_FILE_BYTES:
            logger.debug(
                "Skipping %s (%d MB) — exceeds MAX_SCAN_FILE_BYTES",
                rel_path,
                file_size // (1024 * 1024),
            )
            return findings

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        lines = content.splitlines()

        # Combine static RULES with dynamically-loaded webshell signatures
        # from the knowledge base — ensures WEBSHELL_SIGNATURES is not dead data
        all_rules = list(self.RULES) + self._load_webshell_rules()

        for rule in all_rules:
            for match in rule["pattern"].finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""

                # Skip matches inside block comments (/* ... */) or line comments (//)
                if self._is_in_comment(content, match.start()):
                    continue

                rule_id = rule["id"]

                # SEC012/SEC070: Skip safe unserialize with allowed_classes=>false
                if rule_id in ("SEC012", "SEC070"):
                    context_after = content[match.start() : match.start() + 200]
                    if re.search(
                        r"""allowed_classes\s*(?:=>|=)\s*false""",
                        context_after,
                        re.IGNORECASE,
                    ):
                        continue

                # SEC004: Skip const declarations (enum constants, not real credentials)
                if rule_id == "SEC004":
                    line_text = lines[line_no - 1] if line_no <= len(lines) else ""
                    if re.search(r"""\bconst\b""", line_text, re.IGNORECASE):
                        continue

                finding = SecurityFinding(
                    severity=rule["severity"],
                    category=rule["category"],
                    rule=rule["id"],
                    file=rel_path,
                    line=line_no,
                    message=rule["message"],
                    snippet=snippet[:120],
                    recommendation=rule.get("recommendation", ""),
                    cwe=rule.get("cwe", ""),
                )
                findings.append(finding)

        # Check for obfuscated code (high entropy in PHP)
        if file_path.suffix.lower() in (".php", ".inc"):
            entropy = self._check_obfuscation(content)
            if entropy > 5.5:
                findings.append(
                    SecurityFinding(
                        severity="INFO",
                        category="obfuscation",
                        rule="SEC050",
                        file=rel_path,
                        line=1,
                        message=f"High entropy code detected ({entropy:.2f}/8.0) - possible obfuscation",
                        recommendation="Review file for obfuscated/packed code",
                    )
                )

        return findings

    def scan_directory(self, root: Path) -> SecurityReport:
        """Scan entire directory for security issues."""
        report = SecurityReport()
        severity_counts = Counter()
        category_counts = Counter()

        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            ext = file_path.suffix.lower()
            name_lower = file_path.name.lower()
            # Scan code files AND configuration files for persistence indicators
            if ext not in get_scannable_extensions() and name_lower not in get_scannable_extensions():
                continue
            # Skip non-scannable directories (canonical set)
            parts = file_path.relative_to(root).parts
            if any(p in get_skip_dirs() for p in parts):
                continue

            report.scanned_files += 1
            findings = self.scan_file(file_path, root)
            report.findings.extend(findings)

            for f in findings:
                severity_counts[f.severity] += 1
                category_counts[f.category] += 1

        report.total_findings = len(report.findings)
        report.critical = severity_counts.get("CRITICAL", 0)
        report.high = severity_counts.get("HIGH", 0)
        report.medium = severity_counts.get("MEDIUM", 0)
        report.low = severity_counts.get("LOW", 0)
        report.info = severity_counts.get("INFO", 0)
        report.findings_by_category = dict(category_counts.most_common())

        return report

    def scan_files(
        self, root: Path, only_files: set[str]
    ) -> SecurityReport:
        """Scan *only* the files whose relative paths are in *only_files*.

        This is the audit-mode entry point: downstream callers first diff
        the target against a clean reference and pass in only the delta set
        (added + modified files).  Files with identical checksums are never
        scanned, eliminating virtually all false positives on stock code.
        """
        report = SecurityReport()
        severity_counts: Counter[str] = Counter()
        category_counts: Counter[str] = Counter()

        for rel in sorted(only_files):
            file_path = root / rel.replace("/", os.sep)
            if not file_path.is_file():
                continue
            report.scanned_files += 1
            findings = self.scan_file(file_path, root)
            report.findings.extend(findings)
            for f in findings:
                severity_counts[f.severity] += 1
                category_counts[f.category] += 1

        report.total_findings = len(report.findings)
        report.critical = severity_counts.get("CRITICAL", 0)
        report.high = severity_counts.get("HIGH", 0)
        report.medium = severity_counts.get("MEDIUM", 0)
        report.low = severity_counts.get("LOW", 0)
        report.info = severity_counts.get("INFO", 0)
        report.findings_by_category = dict(category_counts.most_common())
        return report

    def _is_in_comment(self, content: str, match_start: int) -> bool:
        """Check if a match position is inside a block comment or line comment."""
        # Check for block comments /* ... */
        block_open = content.rfind("/*", 0, match_start)
        if block_open != -1:
            block_close = content.find("*/", block_open)
            if block_close == -1 or block_close > match_start:
                return True

        # Check for line comments //
        line_start = content.rfind("\n", 0, match_start) + 1
        line_before = content[line_start:match_start]
        if "//" in line_before:
            return True

        return False

    def _check_obfuscation(self, content: str) -> float:
        """Compute entropy of PHP code (high = possibly obfuscated)."""
        # Only check PHP code blocks
        php_blocks = re.findall(r"<\?php(.*?)(?:\?>|$)", content, re.DOTALL)
        if not php_blocks:
            return 0.0

        php_code = " ".join(php_blocks)
        if len(php_code) < 100:
            return 0.0

        counts = Counter(php_code.encode("utf-8", errors="replace"))
        total = sum(counts.values())
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
