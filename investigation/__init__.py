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

from .investigator import Investigator, InvestigationReport, InvestigationFinding
from .step_protocol import InvestigationStep, InvestigationContext, StepResult
from .external_tools import ExternalToolRunner, ExternalToolsReport
from .semgrep_adapter import SemgrepAdapter
from .trivy_adapter import TrivyAdapter
