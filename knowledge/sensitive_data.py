"""
REDACTS Sensitive Data Scanner — detection and reporting of sensitive data exposure.

This module scans REDCap filesystem snapshots for exposed sensitive data
including PHI, credentials, PII, and financial data. It is a DETECTION-ONLY
tool: findings are reported with redacted snippets so that evidence is
preserved intact on disk while reports never leak raw values.

HIPAA defines 18 identifiers that constitute Protected Health Information (PHI):
    1.  Names
    2.  Geographic data smaller than a state
    3.  Dates (except year) related to an individual
    4.  Phone numbers
    5.  Fax numbers
    6.  Email addresses
    7.  Social Security Numbers
    8.  Medical record numbers
    9.  Health plan beneficiary numbers
    10. Account numbers
    11. Certificate / license numbers
    12. Vehicle identifiers and serial numbers
    13. Device identifiers and serial numbers
    14. Web URLs
    15. IP addresses
    16. Biometric identifiers
    17. Full-face photographs and comparable images
    18. Any other unique identifying number, characteristic, or code

Design invariant:
    This scanner DETECTS and FLAGS sensitive data but NEVER removes or modifies
    source files.  The original evidence must remain untouched.  Detected values
    are masked in report snippets only (``***REDACTED***``).
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# File-scanning constraints
# ---------------------------------------------------------------------------

MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MB

SCANNABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".php",
        ".inc",
        ".js",
        ".json",
        ".yml",
        ".yaml",
        ".xml",
        ".sql",
        ".txt",
        ".csv",
        ".html",
        ".htm",
        ".conf",
        ".ini",
        ".env",
        ".log",
        ".md",
        ".htaccess",
        ".user.ini",
        ".py",
        ".sh",
    }
)

# We also scan dot-files whose full name matches (e.g. ``.htaccess``).
SCANNABLE_DOT_FILES: frozenset[str] = frozenset(
    {
        ".htaccess",
        ".env",
        ".user.ini",
    }
)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class SensitiveDataFinding:
    """A single instance of detected sensitive data."""

    file_path: str  # Relative to scan root
    line: int  # 1-based line number
    column: int  # 0-based column offset
    data_type: str  # e.g. "ssn", "email", "api_token", "password"
    category: str  # PHI | CREDENTIAL | PII | FINANCIAL | INFRASTRUCTURE
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    snippet_redacted: str  # Source line with the matched value masked
    original_length: int  # Length of the raw matched value (forensic doc)
    assessment: str  # Human-readable explanation
    hipaa_identifier: bool  # True when the finding maps to one of the 18 identifiers


@dataclass
class SensitiveDataReport:
    """Aggregated report produced by ``SensitiveDataScanner.scan_directory``."""

    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    scanned_files: int = 0
    findings: list[SensitiveDataFinding] = field(default_factory=list)
    hipaa_exposure_summary: str = ""

    # -- helpers -------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise to a plain ``dict`` suitable for JSON output."""
        return {
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "findings_by_category": dict(self.findings_by_category),
            "findings_by_severity": dict(self.findings_by_severity),
            "scanned_files": self.scanned_files,
            "hipaa_exposure_summary": self.hipaa_exposure_summary,
            "findings": [
                {
                    "file_path": f.file_path,
                    "line": f.line,
                    "column": f.column,
                    "data_type": f.data_type,
                    "category": f.category,
                    "severity": f.severity,
                    "snippet_redacted": f.snippet_redacted,
                    "original_length": f.original_length,
                    "assessment": f.assessment,
                    "hipaa_identifier": f.hipaa_identifier,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Each entry: (compiled_regex, data_type, category, severity, assessment_template,
#               hipaa_identifier, group_index_for_value)
# ``group_index_for_value`` selects which regex group contains the actual
# sensitive value to redact.  ``0`` means the entire match.

_PatternTuple = tuple[re.Pattern[str], str, str, str, str, bool, int]


def _build_patterns() -> list[_PatternTuple]:
    """Compile detection patterns once at import time."""

    patterns: list[_PatternTuple] = []

    def _add(
        regex: str,
        data_type: str,
        category: str,
        severity: str,
        assessment: str,
        hipaa: bool,
        group: int = 0,
        flags: int = re.IGNORECASE,
    ) -> None:
        patterns.append(
            (
                re.compile(regex, flags),
                data_type,
                category,
                severity,
                assessment,
                hipaa,
                group,
            )
        )

    # --- a. Social Security Numbers (HIPAA #7) ---
    _add(
        r"\b(\d{3}-\d{2}-\d{4})\b",
        "ssn",
        "PII",
        "CRITICAL",
        "Social Security Number in XXX-XX-XXXX format detected.",
        hipaa=True,
        group=1,
    )
    _add(
        r"(?<!\d)(\d{9})(?!\d)",
        "ssn_compact",
        "PII",
        "HIGH",
        "Possible 9-digit SSN (compact format) detected.",
        hipaa=True,
        group=1,
    )

    # --- b. Email addresses (HIPAA #6) ---
    _add(
        r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b",
        "email",
        "PII",
        "MEDIUM",
        "Email address detected.",
        hipaa=True,
        group=1,
    )

    # --- c. Phone numbers (HIPAA #4) ---
    _add(
        r"(\(\d{3}\)\s?\d{3}[.\-]\d{4})",
        "phone",
        "PII",
        "MEDIUM",
        "Phone number in (XXX) XXX-XXXX format detected.",
        hipaa=True,
        group=1,
    )
    _add(
        r"\b(\d{3}[.\-]\d{3}[.\-]\d{4})\b",
        "phone",
        "PII",
        "MEDIUM",
        "Phone number in XXX-XXX-XXXX format detected.",
        hipaa=True,
        group=1,
    )
    _add(
        r"(\+1\d{10})\b",
        "phone",
        "PII",
        "MEDIUM",
        "Phone number in +1XXXXXXXXXX format detected.",
        hipaa=True,
        group=1,
    )

    # --- d. Credit card numbers (HIPAA #10 — account numbers) ---
    # Visa
    _add(
        r"\b(4\d{3}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b",
        "credit_card_visa",
        "FINANCIAL",
        "CRITICAL",
        "Possible Visa credit card number detected.",
        hipaa=True,
        group=1,
    )
    # MasterCard
    _add(
        r"\b(5[1-5]\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b",
        "credit_card_mc",
        "FINANCIAL",
        "CRITICAL",
        "Possible MasterCard credit card number detected.",
        hipaa=True,
        group=1,
    )
    # Amex
    _add(
        r"\b(3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5})\b",
        "credit_card_amex",
        "FINANCIAL",
        "CRITICAL",
        "Possible American Express credit card number detected.",
        hipaa=True,
        group=1,
    )
    # Discover
    _add(
        r"\b(6(?:011|5\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b",
        "credit_card_discover",
        "FINANCIAL",
        "CRITICAL",
        "Possible Discover credit card number detected.",
        hipaa=True,
        group=1,
    )

    # --- e. IP addresses (HIPAA #15) ---
    _add(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
        "ip_address",
        "INFRASTRUCTURE",
        "MEDIUM",
        "IPv4 address detected.",
        hipaa=True,
        group=1,
    )

    # --- f. REDCap API tokens (32-char hex — HIPAA #18 unique identifier) ---
    _add(
        r"\b([0-9A-Fa-f]{32})\b",
        "api_token",
        "CREDENTIAL",
        "CRITICAL",
        "32-character hex string detected — possible REDCap API token.",
        hipaa=True,
        group=1,
    )

    # --- g. Passwords in source code ---
    # PHP style: $password = 'value';
    _add(
        r"""\$(?:password|passwd|pwd)\s*=\s*['"](.+?)['"]""",
        "password",
        "CREDENTIAL",
        "CRITICAL",
        "Hard-coded password assignment detected (PHP variable).",
        hipaa=False,
        group=1,
    )
    # Generic assignment: password = "value", password: "value"
    _add(
        r"""(?:password|passwd|pwd)\s*[:=]\s*['"](.+?)['"]""",
        "password",
        "CREDENTIAL",
        "CRITICAL",
        "Hard-coded password assignment detected.",
        hipaa=False,
        group=1,
    )

    # --- h. Database credentials (PHP $hostname, $db, $username, $password) ---
    _add(
        r"""\$(?:hostname|db|username|database_host|database_name|database_user)"""
        r"""\s*=\s*['"](.+?)['"]""",
        "db_credential",
        "CREDENTIAL",
        "HIGH",
        "Database connection variable with embedded credential detected.",
        hipaa=False,
        group=1,
    )

    # --- i. AWS keys ---
    _add(
        r"\b(AKIA[0-9A-Z]{16})\b",
        "aws_access_key",
        "CREDENTIAL",
        "CRITICAL",
        "AWS Access Key ID detected.",
        hipaa=False,
        group=1,
    )
    _add(
        r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?"""
        r"""([A-Za-z0-9/+=]{40})['"]?""",
        "aws_secret_key",
        "CREDENTIAL",
        "CRITICAL",
        "AWS Secret Access Key detected.",
        hipaa=False,
        group=1,
    )

    # --- j. Private keys ---
    _add(
        r"(-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----)",
        "private_key_rsa",
        "CREDENTIAL",
        "CRITICAL",
        "RSA private key header detected.",
        hipaa=False,
        group=1,
    )
    _add(
        r"(-----BEGIN\s+EC\s+PRIVATE\s+KEY-----)",
        "private_key_ec",
        "CREDENTIAL",
        "CRITICAL",
        "EC private key header detected.",
        hipaa=False,
        group=1,
    )
    _add(
        r"(-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----)",
        "private_key_openssh",
        "CREDENTIAL",
        "CRITICAL",
        "OpenSSH private key header detected.",
        hipaa=False,
        group=1,
    )

    # --- k. Base64-encoded blobs (50+ chars) in config/PHP files ---
    _add(
        r"(?:=\s*|:\s*|'|\")" r"([A-Za-z0-9+/]{50,}={0,2})" r"(?:'|\"|\s|;|$)",
        "base64_blob",
        "CREDENTIAL",
        "HIGH",
        "Long Base64-encoded blob detected — may contain encoded credentials.",
        hipaa=False,
        group=1,
    )

    # --- l. Dates of birth (HIPAA #3) ---
    _add(
        r"(?:dob|date.of.birth|birth.?date|DOB)\s*[:=]\s*"
        r"""['"]?(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})['"]?""",
        "date_of_birth",
        "PHI",
        "HIGH",
        "Date of birth value detected.",
        hipaa=True,
        group=1,
    )

    # --- m. Medical record numbers (HIPAA #8) ---
    _add(
        r"(?:mrn|medical.record|MRN|record.number)\s*[:=]\s*"
        r"""['"]?([A-Za-z0-9]{6,10})['"]?""",
        "medical_record_number",
        "PHI",
        "HIGH",
        "Medical record number pattern detected.",
        hipaa=True,
        group=1,
    )

    # --- n. Names in structured data (HIPAA #1) ---
    _add(
        r"""(?:patient_name|first_name|last_name|patientName|firstName|lastName)"""
        r"""\s*[:=]\s*['"]([A-Za-z\s\-'.]{2,60})['"]""",
        "person_name",
        "PHI",
        "HIGH",
        "Patient/person name value assigned in source code.",
        hipaa=True,
        group=1,
    )

    # --- o. JWT tokens (HIPAA #18 — unique identifier) ---
    _add(
        r"\b(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)\b",
        "jwt_token",
        "CREDENTIAL",
        "HIGH",
        "JSON Web Token (JWT) detected.",
        hipaa=True,
        group=1,
    )

    return patterns


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SensitiveDataScanner:
    """Detects sensitive data in REDCap filesystem snapshots.

    **Design invariant**: this scanner only *reports* findings.  It never
    mutates, removes, or otherwise alters the files it inspects.  Matched
    values are replaced with ``***REDACTED***`` only inside the report
    snippet, preserving the original evidence on disk.
    """

    # Pre-compiled patterns (shared across instances).
    _PATTERNS: ClassVar[list[_PatternTuple]] = _build_patterns()

    # Regex for pre-filtering lines that *cannot* contain anything interesting.
    # This is a cheap gate to avoid running 20+ regexes on every line.
    _QUICK_GATE: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:"
        r"\d{3}[\-]\d{2}[\-]\d{4}"  # SSN
        r"|@"  # email
        r"|\(\d{3}\)"  # phone (xxx)
        r"|\+1\d{10}"  # phone +1…
        r"|\d{4}[\s\-]?\d{4}[\s\-]?\d{4}"  # CC prefix
        r"|AKIA"  # AWS key
        r"|BEGIN.{0,10}PRIVATE"  # PEM header
        r"|password|passwd|pwd"  # passwords
        r"|\$hostname|\$db|\$username"  # DB creds
        r"|aws_secret"  # AWS secret
        r"|eyJ[A-Za-z0-9_\-]{10}"  # JWT
        r"|dob|birth|DOB"  # DOB context
        r"|mrn|MRN|medical.record"  # MRN context
        r"|patient_name|first_name|last_name"
        r"|patientName|firstName|lastName"
        r"|[A-Za-z0-9+/]{50}"  # base64 blob
        r"|[0-9a-fA-F]{32}"  # hex token
        r")",
        re.IGNORECASE,
    )

    _REDACTED: ClassVar[str] = "***REDACTED***"

    # Credit-card data_type prefixes requiring Luhn validation.
    _CC_TYPES: ClassVar[frozenset[str]] = frozenset(
        {
            "credit_card_visa",
            "credit_card_mc",
            "credit_card_amex",
            "credit_card_discover",
        }
    )

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #

    def scan_directory(self, root: Path) -> SensitiveDataReport:
        """Walk *root* recursively and scan every eligible file.

        Returns a fully populated :class:`SensitiveDataReport`.
        """
        all_findings: list[SensitiveDataFinding] = []
        scanned = 0

        root = root.resolve()
        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            if not self._is_scannable(file_path):
                continue
            try:
                findings = self._scan_file(file_path, root)
                all_findings.extend(findings)
                scanned += 1
            except Exception:
                log.warning("Failed to scan %s", file_path, exc_info=True)

        report = self._build_report(all_findings, scanned)
        log.info(
            "Scan complete: %d findings across %d files.",
            report.total_findings,
            report.scanned_files,
        )
        return report

    def scan_files(
        self, root: Path, only_files: set[str]
    ) -> SensitiveDataReport:
        """Scan *only* the files whose relative paths are in *only_files*.

        This is the audit-mode entry point: the baseline diff determines
        exactly which files need inspection, so we skip the rest.
        """
        import os as _os

        all_findings: list[SensitiveDataFinding] = []
        scanned = 0
        root = root.resolve()

        for rel in sorted(only_files):
            file_path = root / rel.replace("/", _os.sep)
            if not file_path.is_file():
                continue
            try:
                findings = self._scan_file(file_path, root)
                all_findings.extend(findings)
                scanned += 1
            except Exception:
                log.warning("Failed to scan %s", file_path, exc_info=True)

        report = self._build_report(all_findings, scanned)
        log.info(
            "Audit-mode scan: %d findings across %d/%d delta files.",
            report.total_findings,
            report.scanned_files,
            len(only_files),
        )
        return report

    def _scan_file(
        self,
        file_path: Path,
        root: Path,
    ) -> list[SensitiveDataFinding]:
        """Scan a single file and return a list of findings.

        Parameters
        ----------
        file_path:
            Absolute path to the file.
        root:
            Scan root — used to compute relative paths for findings.
        """
        findings: list[SensitiveDataFinding] = []

        try:
            size = file_path.stat().st_size
        except OSError:
            log.debug("Cannot stat %s — skipping.", file_path)
            return findings

        if size > MAX_FILE_SIZE:
            log.debug("Skipping %s — exceeds %d-byte limit.", file_path, MAX_FILE_SIZE)
            return findings

        if self._is_binary(file_path):
            return findings

        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log.debug("Cannot read %s — skipping.", file_path)
            return findings

        try:
            rel_path = str(file_path.relative_to(root))
        except ValueError:
            rel_path = str(file_path)

        for line_no, line in enumerate(text.splitlines(), start=1):
            if not self._QUICK_GATE.search(line):
                continue
            findings.extend(self._scan_line(line, line_no, rel_path))

        return findings

    # ------------------------------------------------------------------ #
    # Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _scan_line(
        self,
        line: str,
        line_no: int,
        rel_path: str,
    ) -> list[SensitiveDataFinding]:
        """Run every pattern against *line* and yield findings."""

        findings: list[SensitiveDataFinding] = []
        seen_spans: list[tuple[int, int]] = []

        for (
            pat,
            data_type,
            category,
            severity,
            assessment,
            hipaa,
            grp,
        ) in self._PATTERNS:
            for m in pat.finditer(line):
                value = m.group(grp) if grp else m.group(0)
                span = m.span(grp) if grp else m.span(0)

                # Avoid duplicate findings when spans overlap.
                if any(
                    s_start <= span[0] < s_end or s_start < span[1] <= s_end
                    for s_start, s_end in seen_spans
                ):
                    continue

                # Luhn check for credit-card patterns.
                if data_type in self._CC_TYPES:
                    digits = re.sub(r"[\s\-]", "", value)
                    if not self._luhn_check(digits):
                        continue

                snippet = self._redact(m, line, grp)
                findings.append(
                    SensitiveDataFinding(
                        file_path=rel_path,
                        line=line_no,
                        column=span[0],
                        data_type=data_type,
                        category=category,
                        severity=severity,
                        snippet_redacted=snippet,
                        original_length=len(value),
                        assessment=assessment,
                        hipaa_identifier=hipaa,
                    )
                )
                seen_spans.append(span)

        return findings

    # -- redaction --------------------------------------------------------

    @staticmethod
    def _redact(match: re.Match[str], context_line: str, group: int = 0) -> str:
        """Return *context_line* with the matched value replaced by a
        redaction marker.

        Only the portion captured by *group* is replaced so that
        surrounding syntax (quotes, operators) remains visible in the
        snippet for forensic context.
        """
        start, end = match.span(group) if group else match.span(0)
        return context_line[:start] + "***REDACTED***" + context_line[end:]

    # -- Luhn algorithm ---------------------------------------------------

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Validate a numeric string using the Luhn algorithm.

        Returns ``True`` if *number* passes the check (plausible CC number).
        Non-digit characters are silently ignored.
        """
        digits = [int(ch) for ch in number if ch.isdigit()]
        if len(digits) < 12:
            return False

        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d

        return total % 10 == 0

    # -- file helpers -----------------------------------------------------

    @staticmethod
    def _is_scannable(file_path: Path) -> bool:
        """Return *True* when the file extension (or name) is in scope."""
        name = file_path.name.lower()
        if name in SCANNABLE_DOT_FILES:
            return True
        # Handle compound extensions like .user.ini
        suffixes = file_path.suffixes
        if suffixes:
            ext = "".join(suffixes).lower()
            if ext in SCANNABLE_EXTENSIONS:
                return True
            ext = suffixes[-1].lower()
            if ext in SCANNABLE_EXTENSIONS:
                return True
        return False

    @staticmethod
    def _is_binary(file_path: Path) -> bool:
        """Heuristic: read the first 8 KiB and look for null bytes."""
        try:
            chunk = file_path.read_bytes()[:8192]
            return b"\x00" in chunk
        except OSError:
            return True

    # -- report assembly --------------------------------------------------

    def _build_report(
        self,
        findings: list[SensitiveDataFinding],
        scanned_files: int,
    ) -> SensitiveDataReport:
        """Aggregate raw findings into a :class:`SensitiveDataReport`."""

        by_type: Counter[str] = Counter()
        by_category: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()
        hipaa_types: Counter[str] = Counter()

        for f in findings:
            by_type[f.data_type] += 1
            by_category[f.category] += 1
            by_severity[f.severity] += 1
            if f.hipaa_identifier:
                hipaa_types[f.data_type] += 1

        hipaa_summary = self._hipaa_summary(hipaa_types, len(findings))

        return SensitiveDataReport(
            total_findings=len(findings),
            findings_by_type=dict(by_type),
            findings_by_category=dict(by_category),
            findings_by_severity=dict(by_severity),
            scanned_files=scanned_files,
            findings=findings,
            hipaa_exposure_summary=hipaa_summary,
        )

    @staticmethod
    def _hipaa_summary(hipaa_types: Counter[str], total: int) -> str:
        """Produce a human-readable summary of HIPAA-relevant exposure."""
        if not hipaa_types:
            return "No HIPAA-relevant sensitive data detected."

        hipaa_total = sum(hipaa_types.values())
        parts: list[str] = []
        for dtype, count in hipaa_types.most_common():
            parts.append(f"{dtype}: {count}")

        pct = (hipaa_total / total * 100) if total else 0.0

        return (
            f"{hipaa_total} HIPAA-relevant finding(s) "
            f"({pct:.1f}% of {total} total). "
            f"Breakdown — {', '.join(parts)}."
        )
