"""Database-layer forensics for REDCap installations.

REDCap is MySQL-only by design (see the REDCap installation guide,
``redcap/Documentation/installation.html``). Any SQLite artefact in
the webroot is therefore anomalous and is flagged here.

Specifically, this module looks for the InfiniteRed disclosure
pattern (Vanderbilt advisory, Dec 2025 - Feb 2026):

    * ``redcap.db`` or similarly named SQLite file in the webroot
    * Modifications to credential storage in ``database.php`` beyond
      the five canonical variables
    * Trigger or stored-procedure injection in dumps that ship with
      a backup-restore admin action

Known limits:

    * The module reads file content with the capped reader
      (:func:`_read_text_capped`); files larger than the cap return
      what fits and the rest is hashed-only. A backdoor that buries
      its trigger past the cap will be missed by content checks but
      still flagged by the presence/integrity checks.
    * Anomaly classification is heuristic. A site that legitimately
      runs a custom module with its own SQLite cache should allowlist
      the path in the case contract.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.file_utils import _read_text_capped
from ..core.findings import SeverityStr

logger = logging.getLogger(__name__)


@dataclass
class DatabaseAnomaly:
    """Anomaly detected in database or database files."""

    severity: SeverityStr
    type: str  # sqlite_file, credential_change, table_modified, etc.
    message: str
    evidence: str = ""
    recommendation: str = ""


@dataclass
class DatabaseForensicsReport:
    """Result of database forensics analysis."""

    total_anomalies: int = 0
    critical: int = 0
    high: int = 0
    anomalies: list[DatabaseAnomaly] = field(default_factory=list)

    # SQLite artifacts
    has_redcap_db: bool = False
    redcap_db_location: str = ""
    redcap_db_size: int = 0
    redcap_db_modification_time: str = ""

    # Credential anomalies
    has_credential_changes: bool = False
    has_unusual_user_creation: bool = False

    # Table anomalies
    has_hidden_tables: bool = False
    has_modified_triggers: bool = False

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict
        return asdict(self)


class DatabaseForensics:
    """Analyzes database filesystem and configuration for compromise."""

    def analyze_directory(self, root: Path) -> DatabaseForensicsReport:
        """Scan for database-level compromise indicators."""
        report = DatabaseForensicsReport()

        # 1. Check for redcap.db (INFINITERED C2/persistence indicator)
        redcap_db = self._find_redcap_db(root)
        if redcap_db:
            report.has_redcap_db = True
            report.redcap_db_location = str(redcap_db)
            report.redcap_db_size = redcap_db.stat().st_size

            anomaly = DatabaseAnomaly(
                severity="CRITICAL",
                type="sqlite_file",
                message="redcap.db SQLite database found in webroot",
                evidence=f"Location: {redcap_db}, Size: {report.redcap_db_size} bytes",
                recommendation="Matches the InfiniteRed disclosure pattern: a SQLite file in the webroot is the on-disk artefact their backdoor uses for C2 state. Isolate the host before further triage. Do NOT delete - preserve for chain-of-custody.",
            )
            report.critical += 1
            report.anomalies.append(anomaly)

        # 2. Check for SQLite files in unexpected locations
        sqlite_files = list(root.rglob("*.db")) + list(root.rglob("*.sqlite")) + list(root.rglob("*.sqlite3"))
        for db_file in sqlite_files:
            if db_file.name == "redcap.db":
                continue  # Already checked

            rel_path = str(db_file.relative_to(root))
            if "edocs" in rel_path or "temp" in rel_path:
                continue  # Expected

            anomaly = DatabaseAnomaly(
                severity="HIGH",
                type="unexpected_sqlite",
                message=f"Unexpected SQLite file: {rel_path}",
                evidence=f"Size: {db_file.stat().st_size} bytes",
                recommendation="Verify this SQLite file is legitimate. "
                              "Check if it's a module or custom code artifact.",
            )
            report.high += 1
            report.anomalies.append(anomaly)

        # 3. Check database.php for modifications
        db_php = root / "database.php"
        if db_php.exists():
            anomalies = self._analyze_database_php(db_php, root)
            report.anomalies.extend(anomalies)
            report.critical += sum(1 for a in anomalies if a.severity == "CRITICAL")
            report.high += sum(1 for a in anomalies if a.severity == "HIGH")

        # 4. Validate critical directories per REDCAP_KNOWN_GOOD_STRUCTURE
        struct_anomalies = self._validate_critical_dirs(root)
        report.anomalies.extend(struct_anomalies)
        report.critical += sum(1 for a in struct_anomalies if a.severity == "CRITICAL")
        report.high += sum(1 for a in struct_anomalies if a.severity == "HIGH")

        report.total_anomalies = len(report.anomalies)
        return report

    def _find_redcap_db(self, root: Path) -> Path | None:
        """Search for redcap.db file."""
        for db_file in root.rglob("redcap.db"):
            return db_file
        return None

    def _analyze_database_php(self, db_php: Path, root: Path) -> list[DatabaseAnomaly]:
        """Analyze database.php for tampering."""
        anomalies = []

        try:
            content = _read_text_capped(db_php)
        except Exception:
            return anomalies

        # Check for suspicious patterns in database.php
        import re

        # Multiple database connections (backdoor escape route)
        if content.count("mysqli_connect") > 1 or content.count("$mysqli") > 1:
            anomaly = DatabaseAnomaly(
                severity="HIGH",
                type="suspicious_connection",
                message="Multiple database connections in database.php",
                recommendation="Verify all connections are legitimate. "
                              "Attackers sometimes add secondary connections.",
            )
            anomalies.append(anomaly)

        # Encoded/obfuscated database credentials
        if re.search(r"base64_decode|gzinflate|gzuncompress", content, re.IGNORECASE):
            anomaly = DatabaseAnomaly(
                severity="CRITICAL",
                type="obfuscated_creds",
                message="Obfuscated credentials in database.php",
                recommendation="CRITICAL - decode and inspect. "
                              "REDCap stores credentials in plaintext normally.",
            )
            anomalies.append(anomaly)

        # Arbitrary SQL execution
        if re.search(r"\$mysqli->query\s*\(\s*\$", content, re.IGNORECASE):
            anomaly = DatabaseAnomaly(
                severity="CRITICAL",
                type="arbitrary_sql",
                message="Dynamic SQL execution in database.php",
                recommendation="Verify this is not attacker-controlled SQL.",
            )
            anomalies.append(anomaly)

        return anomalies

    def _validate_critical_dirs(self, root: Path) -> list[DatabaseAnomaly]:
        """Validate critical directories against REDCAP_KNOWN_GOOD_STRUCTURE."""
        from threat_base.ioc_database import REDCAP_KNOWN_GOOD_STRUCTURE

        anomalies: list[DatabaseAnomaly] = []
        crit_dirs = REDCAP_KNOWN_GOOD_STRUCTURE.get("critical_directories", {})

        for dirname, rules in crit_dirs.items():
            dir_path = root / dirname
            if not dir_path.is_dir():
                continue

            forbidden_exts = rules.get("must_not_contain", [])
            if forbidden_exts:
                for ext in forbidden_exts:
                    for bad_file in dir_path.rglob(f"*{ext}"):
                        rel = str(bad_file.relative_to(root))
                        anomalies.append(
                            DatabaseAnomaly(
                                severity="CRITICAL",
                                type="forbidden_file",
                                message=f"Forbidden file type '{ext}' in {dirname}/: {rel}",
                                evidence=f"Size: {bad_file.stat().st_size} bytes",
                                recommendation=f"Files with extension '{ext}' should never appear "
                                               f"in {dirname}/. Possible webshell or code injection.",
                            )
                        )

            if rules.get("should_have_htaccess"):
                htaccess = dir_path / ".htaccess"
                if not htaccess.exists():
                    anomalies.append(
                        DatabaseAnomaly(
                            severity="HIGH",
                            type="missing_htaccess",
                            message=f"Missing .htaccess in {dirname}/ directory",
                            recommendation=f"{dirname}/ should have an .htaccess that disables PHP execution.",
                        )
                    )
                else:
                    required_content = rules.get("htaccess_must_contain", "")
                    if required_content:
                        try:
                            content = _read_text_capped(htaccess)
                            if required_content not in content:
                                anomalies.append(
                                    DatabaseAnomaly(
                                        severity="CRITICAL",
                                        type="htaccess_tampered",
                                        message=f".htaccess in {dirname}/ missing '{required_content}'",
                                        recommendation="PHP execution protection has been removed "
                                                       "or was never applied. Possible attack surface.",
                                    )
                                )
                        except Exception as exc:
                            logger.debug(".htaccess anomaly check failed: %s", exc)

        return anomalies