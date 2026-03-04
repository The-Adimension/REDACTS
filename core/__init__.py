"""
REDACTS core package.

Config dataclasses live in :mod:`core.config`; logging bootstrap lives
in :mod:`core.logging_setup`.  This module re-exports both so that
``from core import REDACTSConfig, setup_logging`` continues to work.
"""

from .config import (  # noqa: F401 — backward-compat re-exports
    AnalysisConfig,
    ComparisonConfig,
    DastConfig,
    EvidenceConfig,
    ForensicReportConfig,
    InvestigationConfig,
    REDACTSConfig,
    RepomixConfig,
    ReportConfig,
    SandboxConfig,
)
from .logging_setup import setup_logging  # noqa: F401

__all__ = [
    "AnalysisConfig",
    "ComparisonConfig",
    "DastConfig",
    "EvidenceConfig",
    "ForensicReportConfig",
    "InvestigationConfig",
    "REDACTSConfig",
    "RepomixConfig",
    "ReportConfig",
    "SandboxConfig",
    "setup_logging",
]
