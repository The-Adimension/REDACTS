"""REDACTS CLI - non-interactive workflow components.

Every value the scan needs is sourced from the active
``FrozenCaseContract`` installed by ``main.py``. The CLI is
non-interactive: the contract is mandatory, and there is no
fallback path that prompts for paths or auto-detects case files.
"""

from ._console import create_console, cli_print
from .banner import step_banner
from .preflight import step_preflight
from .workflow import step_run_scan

__all__ = [
    "create_console",
    "cli_print",
    "step_banner",
    "step_preflight",
    "step_run_scan",
]
