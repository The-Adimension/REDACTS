"""
REDACTS Knowledge Base - domain model + enrichment engine.

This unified package contains:

**Domain model** (BLOCK-tier - always loaded):
    - ioc_database.py: IoC definitions, known-good structures, anomaly rules
    - attack_vectors.py: 30+ attack vector definitions with detection strategies
    - cwe_database.py: CWE entry model and scoring
    - mitre_mapping.py: ATT&CK / CVSS / CWE mappings
    - sensitive_data.py: PHI / PII / credential scanners

**Enrichment engine** (WARN-tier - lazy-loaded, scan proceeds without):
    - data_loader.py: YAML data loading with SHA-256 integrity
    - prefetch.py: First-run data acquisition and offline cache
    - updater.py: CLI for updating knowledge data files
    - attack_knowledge.py: ATT&CK Enterprise STIX 2.1 data (downloaded)
    - nvd/: NVD 2.0 API client (optional, needs API key)
"""

from .attack_vectors import AttackVectorDatabase
from .ioc_database import IoCDatabase, HOOK_FUNCTION_NAMES
from .sensitive_data import SensitiveDataScanner

__all__ = [
    "AttackVectorDatabase",
    "IoCDatabase",
    "HOOK_FUNCTION_NAMES",
    "SensitiveDataScanner",
]
