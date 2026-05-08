"""
REDACTS MITRE ATT&CK + CVSS Mapping - Standards-compliant classification.

Maps REDACTS rules (SEC*, WEB*, IOC-*) to:
    - MITRE ATT&CK techniques (T-codes)
    - CVSS 3.1 base score vectors
    - CWE identifiers (canonical, verified)

These mappings ensure every finding exported via SARIF/STIX carries
proper standards-compliant classification, enabling cross-tool
correlation and threat intelligence sharing.

Data is loaded from ``knowledge/data/yaml/mitre_mapping.yaml``.

Sources:
    - MITRE ATT&CK v14+ (https://attack.mitre.org)
    - CWE v4.13+ (https://cwe.mitre.org)
    - CVSS v3.1 (https://www.first.org/cvss/v3.1/specification-document)
"""

from __future__ import annotations

from static.core.findings import CvssVector
from .data_loader import load_mitre_mapping

# --- Load all mappings from externalized YAML ------

_data = load_mitre_mapping()

# rule_id -> (technique_id, technique_name)
MITRE_ATTACK_MAP: dict[str, tuple[str, str]] = {
    k: tuple(v) for k, v in _data["mitre_attack_map"].items()
}


def get_mitre_attack(rule_id: str) -> tuple[str, str]:
    """Look up ATT&CK technique for a rule ID.

    Falls back to prefix matching for IoC IDs (e.g., "IOC-FP-001" -> "IOC-FP").
    """
    if rule_id in MITRE_ATTACK_MAP:
        return MITRE_ATTACK_MAP[rule_id]
    # Try prefix match for IoC and Semgrep rules
    for prefix_len in (6, 5, 4, 3):
        prefix = rule_id[:prefix_len]
        if prefix in MITRE_ATTACK_MAP:
            return MITRE_ATTACK_MAP[prefix]
    # Try category-based match for semgrep
    if ":" in rule_id:
        parts = rule_id.split(":")
        for part in parts:
            for key, val in MITRE_ATTACK_MAP.items():
                if part in key:
                    return val
    return ("", "")


# rule_id -> CvssVector
CVSS_MAP: dict[str, CvssVector] = {
    k: CvssVector(
        vector_string=v["vector_string"],
        base_score=v["base_score"],
    )
    for k, v in _data["cvss_map"].items()
}


# rule_id -> "CWE-XXX"
CWE_MAP: dict[str, str] = _data["cwe_map"]


# tactic_label -> [technique_ids]
ATTACK_TACTICS: dict[str, list[str]] = _data["attack_tactics"]
