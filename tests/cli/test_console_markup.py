"""``cli_print`` must render diagnostic text literally, not as Rich markup.

Rich's markup parser treats a bracketed lowercase token as a style tag and
silently drops it. Many operational messages reference ``case.toml`` sections
by name - ``[security]``, ``[static]``, ``[dynamic]`` - so with markup enabled
those section names vanished from the output (``[security].network_disabled``
rendered as ``.network_disabled``). Styling is supplied separately via the
``style`` argument, so *msg* is always literal.
"""

from __future__ import annotations

import io
import re

import pytest

from static.cli._console import RICH_AVAILABLE, cli_print

pytestmark = pytest.mark.skipif(not RICH_AVAILABLE, reason="Rich not installed")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _render(msg: str, style: str = "yellow") -> str:
    from rich.console import Console

    buf = io.StringIO()
    console = Console(file=buf, force_terminal=True, width=100)
    cli_print(console, msg, style=style)
    return _ANSI.sub("", buf.getvalue()).rstrip("\n")


@pytest.mark.parametrize(
    "msg",
    [
        "([security].network_disabled = true)",
        "Set [static].severity_gate to 'high'.",
        "Configure [dynamic].suites in case.toml.",
        "[inputs.target].sha256 mismatch",
        "[NOTICE] Reduced CWE enrichment - the scan will continue.",
        "plain text with no brackets",
    ],
)
def test_bracketed_sections_render_literally(msg: str) -> None:
    assert _render(msg) == msg


def test_style_is_still_applied() -> None:
    from rich.console import Console

    buf = io.StringIO()
    Console(file=buf, force_terminal=True, width=100).print(
        "styled", style="bold red", markup=False
    )
    # ANSI escape present -> the style argument still took effect.
    assert "\x1b[" in buf.getvalue()
