"""YAML loader for the threat-knowledge datasets.

The ``data/yaml/`` directory holds the security rules, IoC indicators,
sensitive-data patterns, MITRE/CVSS/CWE mappings, REDCap baseline
structure, attack vectors, GTIG-attributed INFINITERED campaign data, and
REDCap Community Forum observations. This module
loads them, compiles their regex patterns at import time, and verifies
each file against ``data/checksums.json``.

File resolution: paths are resolved relative to this module so the
loader works both in editable installs and in wheel distributions.

Integrity:

    Each YAML is hashed (SHA-256) and compared to the entry in
    ``checksums.json`` at load time. A mismatch raises rather than
    loads partially. This catches accidental edits and on-disk
    corruption. It does NOT defend against an attacker who can
    rewrite both the YAML and the checksum manifest - the manifest
    is in the same directory and is not signed. For high-trust
    deployments, ship the package signed (PEP 740 / Sigstore) and
    pin the wheel hash in your installer.

Regex compilation: YAML stores patterns as plain strings with optional
``flags`` metadata (``IGNORECASE`` etc.). The loader compiles via
:func:`re.compile` with those flags applied; a malformed pattern is a
load-time error, not a scan-time surprise.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Data directory resolution

_DATA_DIR = Path(__file__).resolve().parent / "data"
_YAML_DIR = _DATA_DIR / "yaml"
_CHECKSUMS_PATH = _DATA_DIR / "checksums.json"


# Integrity verification


class IntegrityError(RuntimeError):
    """Raised when a data file fails SHA-256 verification."""


def _load_checksums() -> dict[str, str]:
    """Load the checksums manifest. Returns {relative_path: 'sha256:hex'}."""
    if not _CHECKSUMS_PATH.exists():
        logger.warning("checksums.json not found - integrity checks disabled")
        return {}
    with open(_CHECKSUMS_PATH, encoding="utf-8") as f:
        manifest = json.load(f)
    return manifest.get("files", {})


# Module-level cache - loaded once
_CHECKSUMS: dict[str, str] = _load_checksums()


def _verify_file(abs_path: Path) -> None:
    """Verify a data file against the SHA-256 checksum manifest.

    Raises ``IntegrityError`` with a FAIL-LOUD message if the hash does
    not match.  Silently passes if the manifest is empty (development
    mode) or the file is not listed in the manifest.
    """
    if not _CHECKSUMS:
        return  # No manifest - nothing to verify

    rel_key = abs_path.relative_to(_DATA_DIR).as_posix()
    expected = _CHECKSUMS.get(rel_key)
    if expected is None:
        return  # File not tracked - allow (updater may add new files)

    # Parse "sha256:<hex>"
    if not expected.startswith("sha256:"):
        logger.warning("Unknown checksum format for %s: %s", rel_key, expected)
        return
    expected_hex = expected[7:]

    actual_hex = hashlib.sha256(abs_path.read_bytes()).hexdigest()
    if actual_hex != expected_hex:
        raise IntegrityError(
            f"INTEGRITY FAILURE: {rel_key} has been tampered with.\n"
            f"  Expected SHA-256: {expected_hex}\n"
            f"  Actual SHA-256:   {actual_hex}\n"
            f"  This file may have been maliciously modified to bypass "
            f"security detection rules.\n"
            f"  Re-install REDACTS or run 'python main.py update all' to restore "
            f"trusted data files."
        )
    logger.debug("Integrity OK: %s", rel_key)


def regenerate_checksums() -> Path:
    """Regenerate checksums.json from current data files.

    Called by the updater CLI after verified atomic replacement of data
    files.  Returns the path to the written manifest.
    """
    checksums: dict[str, str] = {}
    d = _YAML_DIR
    if d.exists():
        for f in sorted(d.iterdir()):
            if f.is_file():
                h = hashlib.sha256(f.read_bytes()).hexdigest()
                checksums[f.relative_to(_DATA_DIR).as_posix()] = f"sha256:{h}"

    manifest = {
        "version": "1.0.0",
        "description": "SHA-256 integrity manifest for REDACTS knowledge data files",
        "files": checksums,
    }
    with open(_CHECKSUMS_PATH, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    # Refresh module-level cache
    _CHECKSUMS.clear()
    _CHECKSUMS.update(checksums)
    logger.info("Regenerated checksums.json with %d entries", len(checksums))
    return _CHECKSUMS_PATH

# Flag mapping

_RE_FLAGS: dict[str, int] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
}


def _compile_flags(flag_str: str | None) -> int:
    """Convert a flag name string (e.g. 'IGNORECASE') to ``re`` flag int."""
    if not flag_str:
        return 0
    flags = 0
    for part in flag_str.split("|"):
        part = part.strip()
        if part in _RE_FLAGS:
            flags |= _RE_FLAGS[part]
    return flags


# YAML loading primitives


def _load_yaml(filename: str) -> dict[str, Any]:
    """Load a YAML file from the data/yaml/ directory.

    Verifies SHA-256 integrity before parsing.
    """
    path = _YAML_DIR / filename
    _verify_file(path)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# Public Loaders


def load_security_rules() -> list[dict[str, Any]]:
    """Load security rules from YAML with compiled regex patterns.

    Returns a list of rule dicts. Each rule's ``pattern`` key is replaced
    with a compiled ``re.Pattern`` object, and ``pattern_flags`` is resolved
    to an ``int``.
    """
    data = _load_yaml("security_rules.yaml")
    rules = []
    for rule in data.get("rules", []):
        pattern_str = rule.get("pattern")
        flags = _compile_flags(rule.get("pattern_flags"))
        if pattern_str:
            rule["compiled_pattern"] = re.compile(pattern_str, flags)
        else:
            rule["compiled_pattern"] = None
        rules.append(rule)
    logger.debug("Loaded %d security rules from YAML", len(rules))
    return rules


def load_ioc_indicators() -> dict[str, Any]:
    """Load IoC indicators from YAML.

    Returns the full parsed dict with keys:
        indicators, webshell_signatures, htaccess_dangerous_directives,
        user_ini_dangerous_directives
    """
    data = _load_yaml("ioc_indicators.yaml")

    # Compile regex patterns in webshell signatures
    for sig in data.get("webshell_signatures", []):
        pattern_str = sig.get("pattern")
        if pattern_str:
            sig["compiled_pattern"] = re.compile(pattern_str)

    # Compile patterns in htaccess directives
    for directive in data.get("htaccess_dangerous_directives", []):
        pattern_str = directive.get("pattern")
        if pattern_str:
            directive["compiled_pattern"] = re.compile(pattern_str)

    # Compile patterns in user.ini directives
    for directive in data.get("user_ini_dangerous_directives", []):
        pattern_str = directive.get("pattern")
        if pattern_str:
            directive["compiled_pattern"] = re.compile(pattern_str)

    logger.debug(
        "Loaded %d IoC indicators from YAML",
        len(data.get("indicators", [])),
    )
    return data


def load_sensitive_data_patterns() -> dict[str, Any]:
    """Load sensitive data detection patterns from YAML.

    Returns the full parsed dict with keys:
        scan_constraints, quick_gate_pattern, patterns

    The ``quick_gate_pattern`` is compiled into a ``re.Pattern``.
    Individual pattern ``regex`` values are compiled at load time.
    """
    data = _load_yaml("sensitive_data_patterns.yaml")

    # Compile the quick-gate pattern
    qg = data.get("quick_gate_pattern")
    if qg:
        data["compiled_quick_gate"] = re.compile(qg, re.IGNORECASE)

    # Compile individual patterns
    for pat in data.get("patterns", []):
        regex_str = pat.get("pattern") or pat.get("regex")
        flags = _compile_flags(pat.get("pattern_flags") or pat.get("flags"))
        if regex_str:
            pat["compiled_regex"] = re.compile(regex_str, flags)

    logger.debug(
        "Loaded %d sensitive data patterns from YAML",
        len(data.get("patterns", [])),
    )
    return data


def load_mitre_mapping() -> dict[str, Any]:
    """Load MITRE ATT&CK, CVSS, and CWE mappings from YAML.

    Returns a dict with keys:
        mitre_attack_map, cvss_map, cwe_map, attack_tactics
    """
    data = _load_yaml("mitre_mapping.yaml")
    logger.debug(
        "Loaded MITRE mapping: %d ATT&CK, %d CVSS, %d CWE entries",
        len(data.get("mitre_attack_map", {})),
        len(data.get("cvss_map", {})),
        len(data.get("cwe_map", {})),
    )
    return data


def load_redcap_baseline() -> dict[str, Any]:
    """Load REDCap baseline structure from YAML.

    Returns a dict with keys:
        known_directories, known_good_structure, hook_function_names,
        database_php_validation

    The ``database_php_validation.forbidden_patterns`` entries have their
    ``pattern`` keys compiled into ``re.Pattern`` objects.
    """
    data = _load_yaml("redcap_baseline.yaml")

    # Compile forbidden patterns for database.php validation
    db_val = data.get("database_php_validation", {})
    for fp in db_val.get("forbidden_patterns", []):
        pattern_str = fp.get("pattern")
        flags = _compile_flags(fp.get("flags"))
        if pattern_str:
            fp["compiled_pattern"] = re.compile(pattern_str, flags)

    # Compile validation regex
    val_regex = db_val.get("validation_regex")
    if val_regex:
        db_val["compiled_validation_regex"] = re.compile(
            val_regex, re.MULTILINE
        )

    logger.debug(
        "Loaded REDCap baseline: %d known directories, %d hook functions",
        len(data.get("known_directories", [])),
        len(data.get("hook_function_names", [])),
    )
    return data


def load_attack_vectors() -> list[dict[str, Any]]:
    """Load attack vectors from YAML.

    Returns a list of dicts with keys:
        id, name, description, category, subcategory, filesystem_artifacts,
        detection_patterns, conclusiveness, severity, detection_method,
        redacts_coverage, related_iocs, out_of_scope_note
    """
    data = _load_yaml("attack_vectors.yaml")
    vectors = data.get("vectors", [])
    logger.debug("Loaded %d attack vectors from YAML", len(vectors))
    return vectors


def load_infinitered_campaign() -> dict[str, Any]:
    """Load GTIG-attributed INFINITERED campaign data from YAML.

    Indicators here are published by the Google Threat Intelligence Group for
    the INFINITERED family / UNC6508, so a hit is family evidence and carries
    ``conclusiveness: conclusive``.

    REDCap Consortium community observations are a separate evidence stream -
    see :func:`load_redcap_forum_observations`.

    Returns a dict with keys: campaign, indicators
    """
    data = _load_yaml("infinitered_campaign.yaml")
    logger.debug(
        "Loaded INFINITERED campaign (GTIG): %d indicators",
        len(data.get("indicators", [])),
    )
    return data


def load_redcap_forum_observations() -> dict[str, Any]:
    """Load REDCap Community Forum / Vanderbilt advisory observations from YAML.

    REDCap-specific persistence and webroot-hygiene patterns reported by the
    Consortium community. Severities match the original records; they carry
    ``conclusiveness: suspicious`` because they are strong leads rather than
    family attribution - only GTIG-published evidence is counted as a
    conclusive compromise indicator.

    Returns a dict with keys: campaign, indicators
    """
    data = _load_yaml("redcap_forum_observations.yaml")
    logger.debug(
        "Loaded REDCap forum observations: %d indicators",
        len(data.get("indicators", [])),
    )
    return data
