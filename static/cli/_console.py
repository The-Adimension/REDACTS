"""Console output helpers - Rich-aware ``print`` wrapper.

This module exposes the banner and status print paths used by the
non-interactive CLI. It deliberately exposes no prompt helpers -
every value flows through the ``FrozenCaseContract``.
"""

from __future__ import annotations


try:
    from rich.console import Console

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def create_console() -> "Console" | None:
    """Return a Rich Console if available, else ``None``."""
    return Console() if RICH_AVAILABLE else None


def cli_print(console: "Console" | None, msg: str, style: str = "") -> None:
    """Print *msg* via Rich or fall back to plain ``print``."""
    if console and RICH_AVAILABLE:
        console.print(msg, style=style)
    else:
        print(msg)
