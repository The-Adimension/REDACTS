"""
REDACTS IoC Database — Indicators of Compromise for REDCap environments.

This module contains structured knowledge about:
    1. Known-good REDCap file/directory structure
    2. Known REDCap hook function names (legitimate vs injected)
    3. database.php expected structure (exactly 5 variables, nothing else)
    4. Files/extensions/patterns that should NEVER exist in a REDCap webroot
    5. Configuration directives that indicate persistence
    6. Webshell signatures and obfuscation patterns

Each IoC includes conclusiveness rating, severity, and references.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Conclusiveness(Enum):
    """How definitive an indicator is."""

    CONCLUSIVE = "conclusive"  # Confirmed compromise indicator
    SUSPICIOUS = "suspicious"  # Requires context / further investigation
    INFORMATIONAL = "informational"  # Noteworthy but not necessarily malicious


class IoCCategory(Enum):
    """Categories of IoC."""

    FILE_PRESENCE = "file_presence"  # Files that shouldn't exist
    FILE_CONTENT = "file_content"  # Malicious content in files
    CONFIG_TAMPER = "config_tamper"  # Modified configuration files
    PERSISTENCE = "persistence"  # Persistence mechanisms
    OBFUSCATION = "obfuscation"  # Code obfuscation/packing
    CREDENTIAL = "credential"  # Credential exposure/theft
    WEBSHELL = "webshell"  # Web shell indicators
    SUPPLY_CHAIN = "supply_chain"  # Dependency tampering
    INFINITERED = "infinitered"  # INFINITERED-specific campaign indicators


@dataclass
class IoC:
    """A single Indicator of Compromise."""

    id: str  # e.g., "IOC-FP-001"
    name: str
    description: str
    category: IoCCategory
    conclusiveness: Conclusiveness
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    detection_method: str  # How to detect (file_exists, regex, hash_compare, etc.)
    pattern: Optional[str] = None  # Regex or glob pattern
    compiled_pattern: Optional[re.Pattern] = None  # Pre-compiled regex
    filesystem_artifact: str = ""  # What to look for on disk
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str = ""


# =============================================================================
# REDCap Known-Good Structure
# =============================================================================

# Top-level directories expected in a standard REDCap installation
REDCAP_KNOWN_DIRECTORIES: set[str] = {
    "Authentication",
    "Classes",
    "Config",
    "Controllers",
    "DataEntry",
    "DataExport",
    "DataImport",
    "DataQuality",
    "Design",
    "ExternalModules",
    "FileRepository",
    "Home",
    "IdentifierCheck",
    "Install",
    "LanguageUpdater",
    "Languages",
    "Libraries",
    "Logging",
    "Locking",
    "Messenger",
    "MyCap",
    "PDF",
    "ProjectGeneral",
    "ProjectSetup",
    "Randomization",
    "Reports",
    "Resources",
    "Surveys",
    "SharedLibrary",
    "UserRights",
    "api",
    "cron.php",
    "edocs",
    "index.php",
    "modules",
    "plugins",
    "redcap_connect.php",
    "redcap_v{version}",
    "temp",
    "vendor",
}

# Known-good structure definition
REDCAP_KNOWN_GOOD_STRUCTURE: dict[str, Any] = {
    "description": "Standard REDCap installation file structure",
    "critical_files": {
        "database.php": {
            "expected_content": "EXACTLY <?php and 5 variable assignments: $hostname, $db, $username, $password, $salt",
            "max_variables": 5,
            "allowed_variables": {"hostname", "db", "username", "password", "salt"},
            "forbidden_patterns": [
                "function ",
                "class ",
                "include",
                "require",
                "eval",
                "exec",
                "system",
                "passthru",
                "shell_exec",
                "popen",
                "proc_open",
                "base64_decode",
                "gzinflate",
            ],
        },
        "cron.php": {
            "description": "REDCap cron entry point — hash must match distribution",
            "comparison_type": "hash",
        },
        "index.php": {
            "description": "Main entry point — hash must match distribution",
            "comparison_type": "hash",
        },
        "redcap_connect.php": {
            "description": "Bootstrap connector — hash must match distribution",
            "comparison_type": "hash",
        },
    },
    "critical_directories": {
        "edocs": {
            "must_not_contain": [".php", ".phtml", ".phar", ".php5", ".php7", ".inc"],
            "should_have_htaccess": True,
            "htaccess_must_contain": "php_flag engine off",
        },
        "temp": {
            "must_not_contain": [".php", ".phtml", ".phar"],
        },
        "modules": {
            "description": "External Modules directory — each module has config.json",
        },
    },
}


# =============================================================================
# REDCap Hook Function Names (Legitimate)
# =============================================================================

# These are the ONLY function names that should appear in hook_functions.php
# Any other function name is a potential injection
HOOK_FUNCTION_NAMES: set[str] = {
    "redcap_every_page_top",
    "redcap_every_page_before_render",
    "redcap_data_entry_form",
    "redcap_data_entry_form_top",
    "redcap_survey_page",
    "redcap_survey_page_top",
    "redcap_survey_complete",
    "redcap_save_record",
    "redcap_add_edit_records_page",
    "redcap_custom_verify",
    "redcap_user_rights",
    "redcap_module_system_enable",
    "redcap_module_system_disable",
    "redcap_module_project_enable",
    "redcap_module_project_disable",
    "redcap_module_configure_button_display",
    "redcap_module_save_configuration",
    "redcap_module_link_check_display",
    "redcap_email",
    "redcap_pdf",
}


# =============================================================================
# database.php Validation
# =============================================================================

DATABASE_PHP_ALLOWED_VARIABLES: set[str] = {
    "hostname",
    "db",
    "username",
    "password",
    "salt",
}

DATABASE_PHP_VALIDATION_REGEX = re.compile(
    r"^\s*\$(" + "|".join(DATABASE_PHP_ALLOWED_VARIABLES) + r")\s*=\s*",
    re.MULTILINE,
)

DATABASE_PHP_FORBIDDEN_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bfunction\s+\w+\s*\(", re.IGNORECASE),
    re.compile(r"\bclass\s+\w+", re.IGNORECASE),
    re.compile(r'\b(?:include|require)(?:_once)?\s*[\(\'"]', re.IGNORECASE),
    re.compile(
        r"\b(?:eval|exec|system|passthru|shell_exec|popen|proc_open)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(r"\bbase64_decode\s*\(", re.IGNORECASE),
    re.compile(r"\bgzinflate\s*\(", re.IGNORECASE),
    re.compile(r"\bfile_get_contents\s*\(", re.IGNORECASE),
    re.compile(r"\bcurl_exec\s*\(", re.IGNORECASE),
    re.compile(r"\bstream_wrapper_register\s*\(", re.IGNORECASE),
    re.compile(r"\bini_set\s*\(", re.IGNORECASE),
    re.compile(r"\bset_include_path\s*\(", re.IGNORECASE),
]


# =============================================================================
# Configuration Persistence IoCs
# =============================================================================

HTACCESS_DANGEROUS_DIRECTIVES: list[dict[str, str]] = [
    {
        "pattern": r"php_value\s+auto_prepend_file",
        "severity": "CRITICAL",
        "message": "auto_prepend_file directive — persistent code execution on every request",
        "conclusiveness": "conclusive",
    },
    {
        "pattern": r"php_value\s+auto_append_file",
        "severity": "CRITICAL",
        "message": "auto_append_file directive — persistent code execution after every request",
        "conclusiveness": "conclusive",
    },
    {
        "pattern": r"AddHandler\s+.*php",
        "severity": "HIGH",
        "message": "AddHandler enabling PHP execution — may allow PHP in upload directories",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"SetHandler\s+.*php",
        "severity": "HIGH",
        "message": "SetHandler enabling PHP execution",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"php_flag\s+engine\s+on",
        "severity": "HIGH",
        "message": "PHP engine explicitly enabled — dangerous in upload directories",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"RewriteRule\s+.*https?://",
        "severity": "MEDIUM",
        "message": "RewriteRule redirecting to external URL — potential C2 or phishing",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"ProxyPass\s+",
        "severity": "MEDIUM",
        "message": "ProxyPass directive — potential reverse proxy to C2",
        "conclusiveness": "suspicious",
    },
]

USER_INI_DANGEROUS_DIRECTIVES: list[dict[str, str]] = [
    {
        "pattern": r"auto_prepend_file\s*=",
        "severity": "CRITICAL",
        "message": "auto_prepend_file in .user.ini — persistent invisible backdoor",
        "conclusiveness": "conclusive",
    },
    {
        "pattern": r"auto_append_file\s*=",
        "severity": "CRITICAL",
        "message": "auto_append_file in .user.ini — persistent invisible backdoor",
        "conclusiveness": "conclusive",
    },
    {
        "pattern": r"include_path\s*=",
        "severity": "HIGH",
        "message": "include_path override — potential include path hijacking",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"open_basedir\s*=",
        "severity": "HIGH",
        "message": "open_basedir override — weakening security restrictions",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"disable_functions\s*=",
        "severity": "HIGH",
        "message": "disable_functions override — potentially removing function restrictions",
        "conclusiveness": "suspicious",
    },
    {
        "pattern": r"allow_url_include\s*=",
        "severity": "CRITICAL",
        "message": "allow_url_include enabled — remote file inclusion possible",
        "conclusiveness": "conclusive",
    },
]


# =============================================================================
# Webshell Signatures
# =============================================================================

WEBSHELL_SIGNATURES: list[dict[str, Any]] = [
    {
        "name": "Generic eval webshell",
        "pattern": r"\beval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "System command webshell",
        "pattern": r"\b(?:system|exec|passthru|shell_exec)\s*\(\s*\$_(GET|POST|REQUEST)",
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "Base64 eval chain",
        "pattern": r"\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(",
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "Variable function call",
        "pattern": r"\$\w+\s*\(\s*\$_(GET|POST|REQUEST)",
        "severity": "HIGH",
        "conclusiveness": "suspicious",
    },
    {
        "name": "Assert backdoor",
        "pattern": r"\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "preg_replace /e backdoor",
        "pattern": r'preg_replace\s*\(\s*[\'"][^\'"]*/e[\'"]',
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "create_function backdoor",
        "pattern": r'\bcreate_function\s*\(\s*[\'"].*?[\'"]\s*,\s*\$',
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "File write webshell",
        "pattern": r"file_put_contents\s*\(.*\$_(GET|POST|REQUEST)",
        "severity": "CRITICAL",
        "conclusiveness": "conclusive",
    },
    {
        "name": "Socket reverse shell",
        "pattern": r"(?:fsockopen|stream_socket_client)\s*\(\s*\$",
        "severity": "CRITICAL",
        "conclusiveness": "suspicious",
    },
    {
        "name": "PHP backdoor with __halt_compiler",
        "pattern": r"__halt_compiler\s*\(\s*\)",
        "severity": "HIGH",
        "conclusiveness": "suspicious",
    },
]


# =============================================================================
# IoC Database
# =============================================================================


class IoCDatabase:
    """
    Structured knowledge base of Indicators of Compromise.

    This is queried by the investigation module (Tier 2) during analysis.
    It does not perform scanning — it provides the knowledge for scanners.
    """

    def __init__(self) -> None:
        self._iocs: list[IoC] = []
        self._by_id: dict[str, IoC] = {}
        self._by_category: dict[IoCCategory, list[IoC]] = {}
        self._build_database()

    def _build_database(self) -> None:
        """Populate the IoC database with all known indicators."""
        iocs = [
            # INFINITERED Campaign
            IoC(
                id="IOC-INF-001",
                name="INFINITERED redcap.db file",
                description="SQLite database planted in REDCap directories as C2/persistence layer",
                category=IoCCategory.INFINITERED,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="file_exists",
                pattern="**/redcap.db",
                filesystem_artifact="redcap.db or redcap_.db files in any directory",
                recommendation="Isolate immediately. Inspect SQLite contents for exfiltrated data.",
                references=["REDCap Community Forum Dec 2025-Feb 2026"],
            ),
            IoC(
                id="IOC-INF-002",
                name="INFINITERED SQLite WAL/journal",
                description="SQLite write-ahead log or journal sidecar — proves active database writes",
                category=IoCCategory.INFINITERED,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="file_exists",
                pattern="**/*-wal|**/*-journal|**/*-shm",
                filesystem_artifact="redcap.db-wal, redcap.db-journal, redcap.db-shm files",
                recommendation="Sidecar files prove ACTIVE writes, not just a dropped file. Prioritize incident response.",
            ),
            IoC(
                id="IOC-INF-003",
                name="INFINITERED hook injection",
                description="Injected functions in hook_functions.php that don't match known REDCap hook names",
                category=IoCCategory.INFINITERED,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="function_enum",
                filesystem_artifact="Functions in hook_functions.php not in HOOK_FUNCTION_NAMES",
                recommendation="Compare function names against HOOK_FUNCTION_NAMES whitelist.",
            ),
            IoC(
                id="IOC-INF-004",
                name="INFINITERED eval chain",
                description="eval(gzinflate(base64_decode())) payload delivery pattern",
                category=IoCCategory.INFINITERED,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="regex",
                pattern=r"eval\s*\(\s*(?:gzinflate|gzuncompress)\s*\(\s*base64_decode",
                compiled_pattern=re.compile(
                    r"eval\s*\(\s*(?:gzinflate|gzuncompress)\s*\(\s*base64_decode",
                    re.IGNORECASE,
                ),
                recommendation="Known INFINITERED payload delivery. Isolate and analyze.",
            ),
            # Configuration Persistence
            IoC(
                id="IOC-CFG-001",
                name="database.php poisoning",
                description="Extra executable code beyond the 5 standard variables in database.php",
                category=IoCCategory.CONFIG_TAMPER,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="structure_validation",
                filesystem_artifact="database.php containing functions, classes, includes, or eval",
                recommendation="database.php must contain ONLY $hostname, $db, $username, $password, $salt.",
            ),
            IoC(
                id="IOC-CFG-002",
                name=".user.ini auto_prepend_file",
                description="PHP .user.ini with auto_prepend_file — invisible persistent backdoor",
                category=IoCCategory.PERSISTENCE,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="file_content",
                pattern=r"auto_prepend_file\s*=",
                compiled_pattern=re.compile(r"auto_prepend_file\s*=", re.IGNORECASE),
                filesystem_artifact=".user.ini files in any REDCap directory",
                recommendation="REDCap ships NO .user.ini files. Any instance is anomalous.",
            ),
            IoC(
                id="IOC-CFG-003",
                name=".htaccess auto_prepend/append_file",
                description=".htaccess with php_value auto_prepend_file or auto_append_file",
                category=IoCCategory.PERSISTENCE,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="file_content",
                pattern=r"php_value\s+auto_(?:prepend|append)_file",
                compiled_pattern=re.compile(
                    r"php_value\s+auto_(?:prepend|append)_file", re.IGNORECASE
                ),
                recommendation="Persistent invisible execution on every request. Immediate incident response.",
            ),
            # File Presence
            IoC(
                id="IOC-FP-001",
                name="PHP in upload directory",
                description="PHP files in edocs/uploads/temp — webshell delivery via upload",
                category=IoCCategory.WEBSHELL,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="file_location",
                filesystem_artifact=".php, .phtml, .phar files in edocs/, uploads/, temp/",
                recommendation="PHP files must NEVER exist in upload directories.",
            ),
            IoC(
                id="IOC-FP-002",
                name="Polyglot file",
                description="Image file containing embedded PHP code — bypasses extension filters",
                category=IoCCategory.WEBSHELL,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="content_check",
                filesystem_artifact=".jpg/.png/.gif files containing <?php tags",
                recommendation="Definitively malicious. Remove and investigate upload mechanism.",
            ),
            IoC(
                id="IOC-FP-003",
                name=".git directory in webroot",
                description="Git repository metadata exposed in webroot",
                category=IoCCategory.FILE_PRESENCE,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="HIGH",
                detection_method="directory_exists",
                pattern="**/.git",
                filesystem_artifact=".git/ directory in webroot",
                recommendation="Source code, credentials, and history exposed. Remove .git/ and block via server config.",
            ),
            IoC(
                id="IOC-FP-004",
                name="Certificate/key in webroot",
                description="TLS certificates or private keys stored in web-accessible directory",
                category=IoCCategory.CREDENTIAL,
                conclusiveness=Conclusiveness.SUSPICIOUS,
                severity="HIGH",
                detection_method="file_exists",
                pattern="**/*.{pem,crt,key,p12,pfx}",
                filesystem_artifact=".pem, .crt, .key files in webroot",
                recommendation="Private keys must never be in webroot. Rotate compromised keys.",
            ),
            # Supply Chain
            IoC(
                id="IOC-SC-001",
                name="Composer autoload tampering",
                description="Modified vendor/autoload.php — executes on every request",
                category=IoCCategory.SUPPLY_CHAIN,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="hash_compare",
                filesystem_artifact="vendor/autoload.php with manual modifications",
                recommendation="Regenerate vendor/ with composer install from clean composer.lock.",
            ),
            IoC(
                id="IOC-SC-002",
                name="External Module framework tampering",
                description="Modified files in ExternalModules/classes/ — affects all EM execution",
                category=IoCCategory.SUPPLY_CHAIN,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="hash_compare",
                filesystem_artifact="Modified AbstractExternalModule.php, Framework.php, etc.",
                recommendation="EM framework must exactly match its official release.",
            ),
            # Content-Type Masquerading (Magika-detected)
            IoC(
                id="IOC-CT-001",
                name="PHP content in non-PHP extension",
                description=(
                    "File extension does not indicate PHP but AI content-type "
                    "analysis (Magika) identifies the content as PHP source. "
                    "This is a hallmark of file-type masquerading used to evade "
                    "extension-based scanners and upload filters."
                ),
                category=IoCCategory.WEBSHELL,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="magika_content_type",
                filesystem_artifact="Any non-.php file whose content is PHP (e.g. .jpg, .css, .txt)",
                recommendation=(
                    "CONCLUSIVE webshell delivery via file-type masquerading. "
                    "Remove, quarantine, and trace upload origin."
                ),
                cwe="CWE-434",
            ),
            IoC(
                id="IOC-CT-002",
                name="SQLite content in non-database extension",
                description=(
                    "File does not have a .db/.sqlite extension but AI "
                    "content-type analysis identifies it as SQLite. "
                    "INFINITERED drops credential-harvesting SQLite databases "
                    "under camouflaged names to survive manual cleanup."
                ),
                category=IoCCategory.INFINITERED,
                conclusiveness=Conclusiveness.CONCLUSIVE,
                severity="CRITICAL",
                detection_method="magika_content_type",
                filesystem_artifact="Any non-.db file whose content is SQLite (e.g. .tmp, .dat, .log)",
                recommendation=(
                    "CONCLUSIVE data exfiltration indicator. Inspect SQLite "
                    "contents for harvested credentials or PHI. "
                    "REDCap uses MySQL exclusively — SQLite is anomalous."
                ),
            ),
            IoC(
                id="IOC-CT-003",
                name="Content-type masquerading (generic)",
                description=(
                    "AI content-type analysis detected that a file's actual "
                    "content does not match its extension. While not all "
                    "mismatches are malicious, active content (scripts, "
                    "executables) hidden behind passive extensions (images, "
                    "text, data) is a strong persistence/evasion indicator."
                ),
                category=IoCCategory.FILE_CONTENT,
                conclusiveness=Conclusiveness.SUSPICIOUS,
                severity="HIGH",
                detection_method="magika_content_type",
                filesystem_artifact="Files where extension-implied type != AI-detected type",
                recommendation=(
                    "Review mismatched files individually. Prioritise files "
                    "where active content hides behind passive extensions."
                ),
            ),
            IoC(
                id="IOC-CT-004",
                name="Polyglot file (AI-detected)",
                description=(
                    "Magika's deep-learning model detects content that is "
                    "structurally different from what the extension implies, "
                    "beyond what shallow byte-sniffing can catch. Polyglot "
                    "files can bypass both extension filters AND simple magic-"
                    "byte checks simultaneously."
                ),
                category=IoCCategory.WEBSHELL,
                conclusiveness=Conclusiveness.SUSPICIOUS,
                severity="HIGH",
                detection_method="magika_content_type",
                filesystem_artifact="Image or data files identified by AI as containing executable code",
                recommendation=(
                    "Traditional polyglot detection (checking first 8 KB for "
                    "<?php) misses advanced payloads. AI-based detection is "
                    "more reliable. Inspect and quarantine."
                ),
                cwe="CWE-434",
            ),
        ]

        for ioc in iocs:
            self._iocs.append(ioc)
            self._by_id[ioc.id] = ioc
            if ioc.category not in self._by_category:
                self._by_category[ioc.category] = []
            self._by_category[ioc.category].append(ioc)

    @property
    def all_iocs(self) -> list[IoC]:
        """All IoCs in the database."""
        return self._iocs

    def validate_database_php(self, content: str) -> list[dict[str, str]]:
        """
        Validate database.php content against known-good structure.

        Returns list of violations found.
        """
        violations: list[dict[str, str]] = []

        # Strip comments and blank lines
        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip()
            and not line.strip().startswith("//")
            and not line.strip().startswith("#")
        ]

        # Check for forbidden patterns
        for pattern in DATABASE_PHP_FORBIDDEN_PATTERNS:
            match = pattern.search(content)
            if match:
                line_no = content[: match.start()].count("\n") + 1
                violations.append(
                    {
                        "type": "forbidden_pattern",
                        "severity": "CRITICAL",
                        "line": str(line_no),
                        "matched": match.group(0),
                        "message": f"Forbidden executable code in database.php: {match.group(0)[:80]}",
                    }
                )

        # Check for undeclared variables
        var_defs = re.findall(r"^\s*\$(\w+)\s*=", content, re.MULTILINE)
        for var in var_defs:
            if var not in DATABASE_PHP_ALLOWED_VARIABLES:
                violations.append(
                    {
                        "type": "unexpected_variable",
                        "severity": "HIGH",
                        "variable": var,
                        "message": f"Unexpected variable ${var} in database.php (allowed: {', '.join(sorted(DATABASE_PHP_ALLOWED_VARIABLES))})",
                    }
                )

        return violations

    def validate_hook_functions(
        self, function_names: list[str]
    ) -> list[dict[str, str]]:
        """
        Validate hook_functions.php function names against whitelist.

        Returns list of unknown/suspicious function names.
        """
        violations: list[dict[str, str]] = []
        for name in function_names:
            if name not in HOOK_FUNCTION_NAMES:
                violations.append(
                    {
                        "type": "unknown_hook_function",
                        "severity": "CRITICAL",
                        "function": name,
                        "message": f"Unknown function '{name}' in hook_functions.php — not a standard REDCap hook",
                    }
                )
        return violations
