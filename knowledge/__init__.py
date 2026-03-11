"""
REDACTS Knowledge Base — IoC Database & Attack Vector Definitions.

Structured knowledge about REDCap-specific threats, filesystem artifacts,
and compromise indicators. This is NOT a scanner — it's a knowledge base
that the investigation module queries during Tier 2 analysis.

Components:
    - ioc_database.py: IoC definitions, known-good structures, anomaly rules
    - attack_vectors.py: 30+ attack vector definitions with detection strategies
"""

from .ioc_database import (
    IoC,
    IoCDatabase,
    REDCAP_KNOWN_GOOD_STRUCTURE,
    HOOK_FUNCTION_NAMES,
)
from .attack_vectors import AttackVector, AttackVectorDatabase
from .cwe_database import CweDatabase, CweEntry, CWE_ATTRIBUTION
from .mitre_mapping import MITRE_ATTACK_MAP, CVSS_MAP, CWE_MAP
from .sensitive_data import (
    SensitiveDataFinding,
    SensitiveDataReport,
    SensitiveDataScanner,
)
