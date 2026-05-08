"""IoC catalogue for REDCap installations.

What the catalogue knows about:

    1. The known-good REDCap file/directory layout, per release.
    2. The list of legitimate hook function names
       (https://help.redcap.vanderbilt.edu/, External Modules docs);
       any function not in this list registered via
       ``hook_functions.php`` is an injection candidate.
    3. The ``database.php`` shape - exactly five variables, no extras.
    4. Files, extensions, and content patterns that should never
       appear in a REDCap webroot.
    5. Configuration directives (``.htaccess``, ``.user.ini``, PHP
       ``auto_prepend_file``) that indicate persistence.
    6. Webshell signatures and obfuscation patterns.

Each IoC carries a :class:`Conclusiveness` rating, severity, and
references (CVE / advisory URL where one exists).

Known limits:

    * IoC patterns are static. A renamed or repacked payload that
      does not match any of the published signatures will not be
      flagged here; that is what Magika content-typing and the
      AST/taint scanners are for. The IoC list is the cheap first
      pass, not the last word.
    * The signature set ages. Run :mod:`threat_base.updater` to pull
      the latest dataset before a high-stakes audit.

Data is loaded from ``data/yaml/ioc_indicators.yaml`` and
``data/yaml/redcap_baseline.yaml`` via the data loader.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .data_loader import load_ioc_indicators, load_redcap_baseline


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
    pattern: str | None = None  # Regex or glob pattern
    compiled_pattern: re.Pattern | None = None  # Pre-compiled regex
    filesystem_artifact: str = ""  # What to look for on disk
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    cwe: str = ""


# --- Load externalized data from YAML --------------

_ioc_data = load_ioc_indicators()
_baseline = load_redcap_baseline()
_db_val = _baseline.get("database_php_validation", {})

# --- REDCap Known-Good Structure  (from redcap_baseline.yaml) --------

REDCAP_KNOWN_DIRECTORIES: set[str] = set(_baseline.get("known_directories", []))

REDCAP_KNOWN_GOOD_STRUCTURE: dict[str, Any] = _baseline.get("known_good_structure", {})

# --- REDCap Hook Function Names  (from redcap_baseline.yaml) ---------

HOOK_FUNCTION_NAMES: set[str] = set(_baseline.get("hook_function_names", []))

# --- database.php Validation  (from redcap_baseline.yaml) ------------

DATABASE_PHP_ALLOWED_VARIABLES: set[str] = set(_db_val.get("allowed_variables", []))

DATABASE_PHP_VALIDATION_REGEX: re.Pattern = _db_val.get(  # type: ignore[assignment]
    "compiled_validation_regex",
    re.compile(
        r"^\s*\$(" + "|".join(DATABASE_PHP_ALLOWED_VARIABLES) + r")\s*=\s*",
        re.MULTILINE,
    ),
)

DATABASE_PHP_FORBIDDEN_PATTERNS: list[re.Pattern] = [
    fp["compiled_pattern"]
    for fp in _db_val.get("forbidden_patterns", [])
    if "compiled_pattern" in fp
]

# --- Configuration Persistence IoCs  (from ioc_indicators.yaml) ------

HTACCESS_DANGEROUS_DIRECTIVES: list[dict[str, str]] = _ioc_data.get(
    "htaccess_dangerous_directives", []
)

USER_INI_DANGEROUS_DIRECTIVES: list[dict[str, str]] = _ioc_data.get(
    "user_ini_dangerous_directives", []
)

# --- Webshell Signatures  (from ioc_indicators.yaml) -----------------

WEBSHELL_SIGNATURES: list[dict[str, Any]] = _ioc_data.get(
    "webshell_signatures", []
)


# --- IoC Database -----------------


class IoCDatabase:
    """
    Structured knowledge base of Indicators of Compromise.

    This is queried by the investigation module (Tier 2) during analysis.
    It does not perform scanning - it provides the knowledge for scanners.
    """

    def __init__(self) -> None:
        self._iocs: list[IoC] = []
        self._by_id: dict[str, IoC] = {}
        self._by_category: dict[IoCCategory, list[IoC]] = {}
        self._build_database()

    def _build_database(self) -> None:
        """Populate the IoC database from externalized YAML indicators."""
        _category_map = {e.value: e for e in IoCCategory}
        _conclus_map = {e.value: e for e in Conclusiveness}

        for raw in _ioc_data.get("iocs", []):
            pattern_str = raw.get("pattern")
            compiled = None
            if pattern_str and raw.get("detection_method") in ("regex", "file_content"):
                flags = 0
                flag_str = raw.get("pattern_flags")
                if flag_str:
                    for part in flag_str.split("|"):
                        part = part.strip()
                        if hasattr(re, part):
                            flags |= getattr(re, part)
                compiled = re.compile(pattern_str, flags)

            ioc = IoC(
                id=raw["id"],
                name=raw["name"],
                description=raw["description"],
                category=_category_map[raw["category"]],
                conclusiveness=_conclus_map[raw["conclusiveness"]],
                severity=raw["severity"],
                detection_method=raw["detection_method"],
                pattern=pattern_str,
                compiled_pattern=compiled,
                filesystem_artifact=raw.get("filesystem_artifact", ""),
                recommendation=raw.get("recommendation", ""),
                references=raw.get("references", []),
                cwe=raw.get("cwe", ""),
            )
            self._iocs.append(ioc)
            self._by_id[ioc.id] = ioc
            self._by_category.setdefault(ioc.category, []).append(ioc)

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

        # Strip comments and blank lines BEFORE running forbidden-pattern
        # checks, otherwise a benign commented-out ``// include 'foo.php';``
        # would be flagged as live executable code.
        raw_lines = content.splitlines()
        stripped_lines: list[str] = []
        in_block_comment = False
        for line in raw_lines:
            text = line
            # Handle ``/* ... */`` block comments spanning multiple lines.
            if in_block_comment:
                end = text.find("*/")
                if end == -1:
                    stripped_lines.append("")
                    continue
                text = text[end + 2 :]
                in_block_comment = False
            while True:
                start = text.find("/*")
                if start == -1:
                    break
                end = text.find("*/", start + 2)
                if end == -1:
                    text = text[:start]
                    in_block_comment = True
                    break
                text = text[:start] + text[end + 2 :]
            # Strip ``//`` and ``#`` line comments.
            for marker in ("//", "#"):
                idx = text.find(marker)
                if idx != -1:
                    text = text[:idx]
            stripped_lines.append(text)
        scrubbed = "\n".join(stripped_lines)

        # Check for forbidden patterns
        for pattern in DATABASE_PHP_FORBIDDEN_PATTERNS:
            match = pattern.search(scrubbed)
            if match:
                line_no = scrubbed[: match.start()].count("\n") + 1
                violations.append(
                    {
                        "type": "forbidden_pattern",
                        "severity": "CRITICAL",
                        "line": str(line_no),
                        "matched": match.group(0),
                        "message": f"Forbidden executable code in database.php: {match.group(0)[:80]}",
                    }
                )

        # Check for undeclared variables (operate on scrubbed content too).
        var_defs = re.findall(r"^\s*\$(\w+)\s*=", scrubbed, re.MULTILINE)
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
                        "message": f"Unknown function '{name}' in hook_functions.php - not a standard REDCap hook",
                    }
                )
        return violations
