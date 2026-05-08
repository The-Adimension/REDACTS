"""
REDACTS core package.

Config dataclasses live in :mod:`core.config`; logging bootstrap lives
in :mod:`core.logging`.  This module re-exports ``REDACTSConfig`` and
``setup_logging`` so that ``from core import REDACTSConfig`` works.
"""

from .config import REDACTSConfig  # noqa: F401
from .logging import setup_logging  # noqa: F401

__all__ = ["REDACTSConfig", "setup_logging"]
