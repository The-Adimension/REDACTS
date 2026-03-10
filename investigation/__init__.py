"""
REDACTS Investigation Module (Tier 2) — Analysis & Enrichment.

Components:
    - investigator.py: Tier 2 orchestrator (IoC, config, security, sensitive data)
    - step_protocol.py: InvestigationStep protocol + shared context + utilities
    - steps/: Concrete step implementations (IoC, config, security, …)
    - external_tools.py: YARA adapter + runner
    - semgrep_adapter.py: Semgrep AST-based scanning
    - trivy_adapter.py: Trivy vulnerability/secret scanning
"""

__all__ = [
    "Investigator",
    "InvestigationReport",
    "InvestigationFinding",
    "InvestigationStep",
    "InvestigationContext",
    "StepResult",
    "ExternalToolRunner",
    "SemgrepAdapter",
    "TrivyAdapter",
]

from .external_tools import ExternalToolRunner
from .investigator import InvestigationFinding, InvestigationReport, Investigator
from .semgrep_adapter import SemgrepAdapter
from .step_protocol import InvestigationContext, InvestigationStep, StepResult
from .trivy_adapter import TrivyAdapter
