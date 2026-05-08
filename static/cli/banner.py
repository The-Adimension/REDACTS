"""
CLI banner display - version, branding, and disclaimer.
"""

from __future__ import annotations


from ._console import RICH_AVAILABLE, cli_print

try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    Console = Panel = None  # type: ignore[assignment]

from ..core.constants import VERSION


def step_banner(console: "Console" | None) -> None:
    """Display application banner and mandatory disclaimer."""
    banner = f"""\
++
|                         REDACTS v{VERSION}                      |
|          REDCap Arbitrary Code Threat Scan                    |
|                                                               |
|   Automated forensic analysis for REDCap deployments          |
|   Semgrep * Trivy * tree-sitter * Magika * YARA * DAST       |
++"""
    if console and RICH_AVAILABLE:
        console.print(Panel(banner, style="bold blue"))
    else:
        print(banner)

    disclaimer = (
        "!  DISCLAIMER: REDACTS is a forensic analysis AID. It does not replace\n"
        "   thorough manual review by qualified security professionals. Results\n"
        "   are not guaranteed to be complete or definitive. Use as an auxiliary\n"
        "   tool within your incident response workflow, not as a sole determination.\n"
        "   \u00a9 2024\u20132026 The Adimension / Shehab Anwer \u2014 atrium@theadimension.com"
    )
    if console and RICH_AVAILABLE:
        console.print(Panel(disclaimer, style="bold yellow", title="Disclaimer"))
    else:
        print(disclaimer)
    cli_print(console, "")
