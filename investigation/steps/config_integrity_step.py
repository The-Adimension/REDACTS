"""
Configuration integrity step — validates critical REDCap config files.

Extracted from ``Investigator._check_config_integrity`` and its helpers.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from ..step_protocol import InvestigationContext, StepResult, rel_path, sha256
from ..step_protocol import ConfigIntegrityResult, InvestigationFinding
from ...knowledge import HOOK_FUNCTION_NAMES, IoCDatabase
from ...forensics.tree_sitter_analyzer import TreeSitterAnalyzer

logger = logging.getLogger(__name__)


class ConfigIntegrityStep:
    """Validate critical configuration files.

    Checks ``database.php``, ``.htaccess``, ``.user.ini``,
    ``hook_functions.php`` and ``cron.php``.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "config_integrity"

    def __init__(
        self, ioc_db: IoCDatabase, php_analyzer: TreeSitterAnalyzer
    ) -> None:
        self._ioc_db = ioc_db
        self._php_analyzer = php_analyzer

    # ── protocol entry point ─────────────────────────────────────────────

    def execute(self, context: InvestigationContext) -> StepResult:
        config_result = self._check_config_integrity(context.root)
        findings = self._config_integrity_to_findings(config_result)
        return StepResult(
            findings=findings,
            report_updates={"config_integrity": config_result},
        )

    # ── implementation (moved verbatim from Investigator) ────────────────

    def _check_config_integrity(self, root: Path) -> ConfigIntegrityResult:
        """Validate critical configuration files."""
        result = ConfigIntegrityResult()

        # 1. database.php
        result.database_php = self._check_database_php(root)

        # 2. .htaccess files
        result.htaccess_files = self._check_htaccess_files(root)

        # 3. .user.ini files
        result.user_ini_files = self._check_user_ini_files(root)

        # 4. hook_functions.php
        result.hook_functions = self._check_hook_functions(root)

        # 5. cron.php
        result.cron_php = self._check_cron_php(root)

        return result

    def _check_database_php(self, root: Path) -> dict[str, Any]:
        """Find and validate database.php."""
        candidates = list(root.glob("**/database.php"))
        if not candidates:
            return {"found": False, "violations": [], "path": ""}

        # Use the first (usually only) database.php
        db_php = candidates[0]
        rel = rel_path(db_php, root)
        try:
            content = db_php.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            return {
                "found": True,
                "path": rel,
                "violations": [],
                "error": str(exc),
            }

        violations = self._ioc_db.validate_database_php(content)
        sha = sha256(db_php)

        return {
            "found": True,
            "path": rel,
            "sha256": sha,
            "size_bytes": db_php.stat().st_size,
            "violations": violations,
        }

    def _check_htaccess_files(self, root: Path) -> list[dict[str, Any]]:
        """Find and analyse all .htaccess files."""
        results: list[dict[str, Any]] = []
        dangerous_directives = re.compile(
            r"php_value\s+auto_(?:prepend|append)_file"
            r"|php_flag\s+engine\s+on"
            r"|AddType\s+application/x-httpd-php"
            r"|SetHandler\s+application/x-httpd-php",
            re.IGNORECASE,
        )

        for htaccess in root.rglob(".htaccess"):
            rel = rel_path(htaccess, root)
            try:
                content = htaccess.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                results.append({"path": rel, "error": str(exc)})
                continue

            dangerous_matches: list[dict[str, Any]] = []
            for match in dangerous_directives.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                dangerous_matches.append({"line": line_no, "directive": match.group(0)})

            results.append(
                {
                    "path": rel,
                    "sha256": sha256(htaccess),
                    "size_bytes": htaccess.stat().st_size,
                    "dangerous_directives": dangerous_matches,
                    "line_count": content.count("\n") + 1,
                }
            )

        return results

    def _check_user_ini_files(self, root: Path) -> list[dict[str, Any]]:
        """Find all .user.ini files (any presence is anomalous for REDCap)."""
        results: list[dict[str, Any]] = []

        for user_ini in root.rglob(".user.ini"):
            rel = rel_path(user_ini, root)
            try:
                content = user_ini.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                results.append({"path": rel, "error": str(exc)})
                continue

            results.append(
                {
                    "path": rel,
                    "sha256": sha256(user_ini),
                    "size_bytes": user_ini.stat().st_size,
                    "content_preview": content[:500],
                    "has_auto_prepend": bool(
                        re.search(r"auto_prepend_file\s*=", content, re.IGNORECASE)
                    ),
                    "has_auto_append": bool(
                        re.search(r"auto_append_file\s*=", content, re.IGNORECASE)
                    ),
                }
            )

        return results

    def _check_hook_functions(self, root: Path) -> dict[str, Any]:
        """Find and validate hook_functions.php."""
        candidates = list(root.glob("**/hook_functions.php"))
        if not candidates:
            return {"found": False, "path": "", "violations": []}

        hook_file = candidates[0]
        rel = rel_path(hook_file, root)
        try:
            ast = self._php_analyzer.parse_file(hook_file, root)
        except Exception as exc:
            return {"found": True, "path": rel, "error": str(exc), "violations": []}

        function_names = [fn.name for fn in ast.functions]
        violations = self._ioc_db.validate_hook_functions(function_names)

        return {
            "found": True,
            "path": rel,
            "sha256": sha256(hook_file),
            "total_functions": len(function_names),
            "known_hooks": [n for n in function_names if n in HOOK_FUNCTION_NAMES],
            "unknown_functions": [
                n for n in function_names if n not in HOOK_FUNCTION_NAMES
            ],
            "violations": violations,
        }

    def _check_cron_php(self, root: Path) -> dict[str, Any]:
        """Record hash of cron.php for baseline comparison."""
        candidates = list(root.glob("**/cron.php"))
        if not candidates:
            return {"found": False, "path": ""}

        cron_file = candidates[0]
        rel = rel_path(cron_file, root)
        return {
            "found": True,
            "path": rel,
            "sha256": sha256(cron_file),
            "size_bytes": cron_file.stat().st_size,
        }

    def _config_integrity_to_findings(
        self, result: ConfigIntegrityResult
    ) -> list[InvestigationFinding]:
        """Convert ConfigIntegrityResult into InvestigationFindings."""
        findings: list[InvestigationFinding] = []

        # database.php violations
        if result.database_php.get("found") and result.database_php.get("violations"):
            for v in result.database_php["violations"]:
                findings.append(
                    InvestigationFinding(
                        id="",
                        source="config_check",
                        severity=v.get("severity", "CRITICAL"),
                        title=f"database.php: {v.get('type', 'violation')}",
                        description=v.get("message", ""),
                        file_path=result.database_php.get("path", "database.php"),
                        line=int(v.get("line", 0)),
                        conclusiveness="conclusive",
                        category="config_tamper",
                        recommendation="database.php must contain ONLY $hostname, $db, $username, $password, $salt.",
                        evidence={"violation": v},
                        related_ioc_ids=["IOC-CFG-001"],
                    )
                )

        # Dangerous .htaccess directives
        for ht in result.htaccess_files:
            for directive in ht.get("dangerous_directives", []):
                findings.append(
                    InvestigationFinding(
                        id="",
                        source="config_check",
                        severity="CRITICAL",
                        title=f".htaccess dangerous directive: {directive['directive'][:60]}",
                        description=f"Dangerous PHP directive in {ht['path']}",
                        file_path=ht.get("path", ".htaccess"),
                        line=directive.get("line", 0),
                        conclusiveness="conclusive",
                        category="persistence",
                        recommendation="Review .htaccess for auto_prepend/append_file and engine directives.",
                        evidence={"directive": directive["directive"]},
                        related_ioc_ids=["IOC-CFG-003"],
                    )
                )

        # .user.ini files (any = anomalous)
        for ui in result.user_ini_files:
            severity = (
                "CRITICAL"
                if ui.get("has_auto_prepend") or ui.get("has_auto_append")
                else "HIGH"
            )
            findings.append(
                InvestigationFinding(
                    id="",
                    source="config_check",
                    severity=severity,
                    title=f"Anomalous .user.ini file: {ui.get('path', '')}",
                    description="REDCap ships NO .user.ini files. Any instance is anomalous.",
                    file_path=ui.get("path", ".user.ini"),
                    line=0,
                    conclusiveness=(
                        "conclusive" if severity == "CRITICAL" else "suspicious"
                    ),
                    category="persistence",
                    recommendation="Investigate and remove. Check for auto_prepend_file settings.",
                    evidence={
                        "has_auto_prepend": ui.get("has_auto_prepend", False),
                        "has_auto_append": ui.get("has_auto_append", False),
                        "sha256": ui.get("sha256", ""),
                    },
                    related_ioc_ids=["IOC-CFG-002"],
                )
            )

        # hook_functions.php unknown functions
        if result.hook_functions.get("found") and result.hook_functions.get(
            "violations"
        ):
            for v in result.hook_functions["violations"]:
                findings.append(
                    InvestigationFinding(
                        id="",
                        source="config_check",
                        severity="CRITICAL",
                        title=f"Injected hook function: {v.get('function', '')}",
                        description=v.get(
                            "message", "Unknown function in hook_functions.php"
                        ),
                        file_path=result.hook_functions.get(
                            "path", "hook_functions.php"
                        ),
                        line=0,
                        conclusiveness="conclusive",
                        category="persistence",
                        recommendation="Compare function names against HOOK_FUNCTION_NAMES whitelist.",
                        evidence={"violation": v},
                        related_ioc_ids=["IOC-INF-003"],
                    )
                )

        return findings
