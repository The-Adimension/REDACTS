"""Scanner pipeline phases.

One module per ``ScanPhase``. Execution order owned by
:mod:`static.scanners.orchestrator`:

1. :class:`DiscoverPhase`      --- probe tool availability
2. :class:`MagikaPhase`        --- type every file (routing intelligence)
3. :class:`SemgrepPhase`       --- AST-based PHP security analysis
4. :class:`TrivyPhase`         --- dependency CVE + secret scanning
5. :class:`YaraPhase`          --- webshell / backdoor detection
6. :class:`RegexScannerPhase` --- regex-based supplementary hints
7. :class:`TreeSitterPhase`    --- structural enrichment
8. :class:`CorrelatePhase`     --- cross-tool corroboration
9. :class:`DastPhase`          --- dynamic validation via Playwright
"""

from __future__ import annotations

from .correlate_phase import CorrelatePhase
from .dast_phase import DastPhase
from .discover_phase import DiscoverPhase
from .regex_scanner_phase import RegexScannerPhase
from .magika_phase import MagikaPhase
from .semgrep_phase import SemgrepPhase
from .tree_sitter_phase import TreeSitterPhase
from .trivy_phase import TrivyPhase
from .yara_phase import YaraPhase

__all__ = [
    "CorrelatePhase",
    "DastPhase",
    "DiscoverPhase",
    "RegexScannerPhase",
    "MagikaPhase",
    "SemgrepPhase",
    "TreeSitterPhase",
    "TrivyPhase",
    "YaraPhase",
]
