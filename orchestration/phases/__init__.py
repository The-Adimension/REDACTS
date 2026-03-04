"""
Orchestration phase implementations.

Each module in this sub-package contains one concrete
:class:`~orchestration.phase_protocol.ScanPhase` implementation
extracted from the former monolithic ``ToolOrchestrator`` class.
"""

from .discover_phase import DiscoverPhase
from .magika_phase import MagikaPhase
from .semgrep_phase import SemgrepPhase
from .trivy_phase import TrivyPhase
from .yara_phase import YaraPhase
from .legacy_scanner_phase import LegacyScannerPhase
from .tree_sitter_phase import TreeSitterPhase
from .correlate_phase import CorrelatePhase
from .dast_phase import DastPhase

__all__ = [
    "DiscoverPhase",
    "MagikaPhase",
    "SemgrepPhase",
    "TrivyPhase",
    "YaraPhase",
    "LegacyScannerPhase",
    "TreeSitterPhase",
    "CorrelatePhase",
    "DastPhase",
]
