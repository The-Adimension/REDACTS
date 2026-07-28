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
    """Print *msg* via Rich or fall back to plain ``print``.

    ``markup=False`` is deliberate: styling flows through the ``style``
    argument, and *msg* is literal diagnostic text. With Rich markup enabled,
    a message that mentions a lowercase ``[section]`` - e.g. ``[security]`` or
    ``[static]`` from ``case.toml`` - is parsed as a style tag and silently
    dropped from the output.
    """
    if console and RICH_AVAILABLE:
        console.print(msg, style=style, markup=False)
    else:
        print(msg)
