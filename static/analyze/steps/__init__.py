"""Investigation pipeline steps.

One module per ``InvestigationStep``. Execution order:

1. :class:`IocScanStep`          --- filesystem IoC detection
2. :class:`ConfigIntegrityStep`  --- critical file validation
3. :class:`SecurityScanStep`     --- rule-based security scan
4. :class:`SensitiveDataStep`    --- PHI / PII / credential detection
5. :class:`ExternalToolsStep`    --- YARA, PHP lint, Lizard, etc.
6. :class:`AttackVectorStep`     --- cross-reference attack vector DB
7. :class:`CweEnrichmentStep`    --- CWE name + recommendation backfill
8. :class:`RiskCalculationStep`  --- overall risk level derivation

Maintainer note: the public API exposed at this package root
(``from static.analyze.steps import IocScanStep, ...``) is what the
orchestrator imports.  Adding a new step means adding it here *and*
wiring it in :mod:`static.analyze.investigator`.
"""

from __future__ import annotations

from .attack_vector import AttackVectorStep
from .config_integrity import ConfigIntegrityStep
from .cwe_enrichment import CweEnrichmentStep
from .external_tools import ExternalToolsStep
from .ioc_scan import IocScanStep
from .risk_calculation import RiskCalculationStep
from .security_scan import SecurityScanStep
from .sensitive_data import SensitiveDataStep

__all__ = [
    "AttackVectorStep",
    "ConfigIntegrityStep",
    "CweEnrichmentStep",
    "ExternalToolsStep",
    "IocScanStep",
    "RiskCalculationStep",
    "SecurityScanStep",
    "SensitiveDataStep",
]
