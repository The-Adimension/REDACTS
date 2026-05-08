"""Loader for the regex security rules consumed by
:class:`static.analyze.scanner.SecurityScanner`.

Rules live in ``threat_base/data/yaml/security_rules.yaml`` and are
compiled at import time. Schema per entry:

    * ``id``             - unique rule identifier (SEC001-SEC099)
    * ``severity``       - CRITICAL / HIGH / MEDIUM / LOW / INFO
    * ``category``       - injection, rce, xss, credentials, etc.
    * ``pattern``        - compiled :class:`re.Pattern`
    * ``message``        - human-readable description
    * ``cwe``            - CWE identifier from the MITRE CWE list
      (https://cwe.mitre.org/), optional
    * ``recommendation`` - remediation guidance, optional

Rule provenance is documented in the YAML header. Categories track
the OWASP Top-10 2021 buckets where the mapping is unambiguous.

Known limit: regex rules cannot express scope or data flow. Anything
that needs taint goes into the Semgrep ruleset instead. To add a
detection here, edit the YAML and refresh the checksum manifest at
``threat_base/data/checksums.json``; no code change is required.
"""

from __future__ import annotations

from typing import Any

from threat_base.data_loader import load_security_rules as _load_rules


def _adapt_rules() -> list[dict[str, object]]:
    """Load YAML rules and remap ``compiled_pattern`` -> ``pattern``."""
    adapted: list[dict[str, object]] = []
    for r in _load_rules():
        entry: dict[str, Any] = {
            "id": r["id"],
            "severity": r["severity"],
            "category": r["category"],
            "pattern": r["compiled_pattern"],
            "message": r["message"],
        }
        if "cwe" in r:
            entry["cwe"] = r["cwe"]
        if "recommendation" in r:
            entry["recommendation"] = r["recommendation"]
        adapted.append(entry)
    return adapted


SECURITY_RULES: list[dict[str, object]] = _adapt_rules()
