"""Guided Error Recovery module for REDACTS CLI (R7).

Formats exceptions, missing dependencies, contract errors, and runtime failures into
structured, actionable error recovery blocks containing explicit [WHAT WENT WRONG]
and [HOW TO FIX IT] diagnostics with concrete remediation commands.
"""

from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from rich.console import Console

from ._console import RICH_AVAILABLE


class ErrorRecoveryBlock:
    """Structured representation of a guided error recovery block."""

    def __init__(
        self,
        title: str,
        what_went_wrong: str,
        how_to_fix: list[str],
        recommended_command: str,
        exit_code: int = 1,
    ) -> None:
        self.title = title
        self.what_went_wrong = what_went_wrong
        self.how_to_fix = how_to_fix
        self.recommended_command = recommended_command
        self.exit_code = exit_code

    def render_plain(self) -> str:
        """Render plain text recovery block for stderr."""
        fix_steps = "\n".join(
            f"    {i + 1}. {step}" for i, step in enumerate(self.how_to_fix)
        )
        return (
            f"\n"
            f"{'=' * 78}\n"
            f"  GUIDED ERROR RECOVERY: {self.title.upper()}\n"
            f"{'=' * 78}\n"
            f"  [WHAT WENT WRONG]:\n"
            f"    {self.what_went_wrong}\n\n"
            f"  [HOW TO FIX IT]:\n"
            f"{fix_steps}\n\n"
            f"  [RECOMMENDED COMMAND]:\n"
            f"    $ {self.recommended_command}\n"
            f"{'=' * 78}\n"
        )

    def display(self, console: Optional["Console"] = None) -> None:
        """Display the recovery block to Rich console or stderr."""
        if console and RICH_AVAILABLE:
            from rich.panel import Panel

            body = (
                f"[bold red][WHAT WENT WRONG]:[/bold red]\n"
                f"  {self.what_went_wrong}\n\n"
                f"[bold yellow][HOW TO FIX IT]:[/bold yellow]\n"
                + "\n".join(
                    f"  [cyan]{i + 1}.[/cyan] {step}"
                    for i, step in enumerate(self.how_to_fix)
                )
                + f"\n\n[bold green][RECOMMENDED COMMAND]:[/bold green]\n"
                f"  [bold white]$ {self.recommended_command}[/bold white]"
            )
            console.print(
                Panel(
                    body,
                    title=f"[bold red]GUIDED ERROR RECOVERY: {self.title}[/bold red]",
                    border_style="red",
                )
            )
        else:
            sys.stderr.write(self.render_plain())
            sys.stderr.flush()


def _has_word(text: str, word: str) -> bool:
    """Substring match constrained to word boundaries.

    Plain ``in`` checks caused real misclassification here: ``"gate" in text``
    matches *aggregate*, *propagate*, *investigate* and *mitigate*, so ordinary
    scanner errors were reported as a severity-gate trip (and had their exit
    code rewritten to 2). Likewise bare ``"threat"`` matches almost every
    message in a codebase with a ``threat_base`` package.
    """
    return re.search(rf"\b{re.escape(word)}\b", text) is not None


# Phrases that indicate something is absent, as opposed to merely mentioned.
# ``"semgrep"`` appearing in a message does not mean semgrep is missing.
_MISSING_SIGNALS: tuple[str, ...] = (
    "not found",
    "not installed",
    "not available",
    "no such file",
    "cannot find",
    "could not find",
    "is missing",
    "missing",
    "unavailable",
    "not recognized",
    "winerror 2",
)

# Tool name -> (title suffix, description, fix steps, recommended command).
_TOOL_REMEDIES: tuple[tuple[str, str, str, list[str], str], ...] = (
    (
        "semgrep",
        "Semgrep",
        "Semgrep SAST code scanner is missing or not available on PATH.",
        [
            "Install Semgrep via pip: pip install semgrep",
            "See SETUP.md for step-by-step instructions to install required dependencies.",
        ],
        "pip install semgrep",
    ),
    (
        "trivy",
        "Trivy",
        "Trivy vulnerability scanner is missing or not available on PATH.",
        [
            "Install Trivy via winget: winget install AquaSecurity.Trivy",
            "See SETUP.md for step-by-step instructions to install required dependencies.",
        ],
        "winget install AquaSecurity.Trivy",
    ),
    (
        "yara",
        "YARA",
        "YARA signature scanner is missing or not available on PATH.",
        [
            "Install YARA via winget: winget install YARA.YARA (or brew install yara)",
            "See SETUP.md for step-by-step instructions to install required dependencies.",
        ],
        "winget install YARA.YARA",
    ),
    (
        "repomix",
        "Repomix",
        "Repomix codebase packager is missing or not available on PATH.",
        [
            "Install Repomix globally via npm: npm install -g repomix",
            "Or install Node.js from https://nodejs.org or winget install OpenJS.NodeJS",
        ],
        "npm install -g repomix",
    ),
)


def _from_exit_code(code: int) -> ErrorRecoveryBlock:
    """Map a process exit code to a recovery block.

    Exit codes are never run through the text matcher - ``str(2)`` has no
    diagnostic content, and matching it as text is how a bare ``1`` used to be
    reported as a generic "Runtime Error".
    """
    if code == 2:
        return ErrorRecoveryBlock(
            title="Severity Gate Threshold Triggered",
            what_went_wrong=(
                "Scan findings met or exceeded the configured severity gate threshold."
            ),
            how_to_fix=[
                "Review generated forensic report findings in the output directory.",
                "Adjust severity gate threshold via CLI: python main.py scan --severity-gate critical",
                "Or modify 'severity_gate' under [static] in case.toml.",
            ],
            recommended_command="python main.py scan --severity-gate critical",
            exit_code=2,
        )
    return ErrorRecoveryBlock(
        title="Scan Failed",
        what_went_wrong=f"REDACTS exited with status {code}.",
        how_to_fix=[
            "Review the diagnostic output above for the underlying failure.",
            "Run preflight verification to check tool availability: python main.py preflight",
            "Review diagnostic output logs in the output directory.",
        ],
        recommended_command="python main.py preflight",
        exit_code=code,
    )


def format_error_recovery(error: Union[Exception, str, int]) -> ErrorRecoveryBlock:
    """Map any exception, error string, or exit code to a structured ErrorRecoveryBlock.

    Classification is type-first and phrase-second. Loose substring tests are
    avoided deliberately - see :func:`_has_word`.
    """
    try:
        from static.core.contract import CaseConfigError
    except ImportError:
        CaseConfigError = None

    # Exit codes carry no text to classify; handle them separately.
    if isinstance(error, int) and not isinstance(error, bool):
        return _from_exit_code(error)

    err_str = str(error)
    err_lower = err_str.lower()
    exc_name = type(error).__name__ if isinstance(error, Exception) else ""
    missing = any(signal in err_lower for signal in _MISSING_SIGNALS)

    # 1a. Lockfile drift is a CaseConfigError, but "run init" is actively bad
    #     advice for it - init overwrites the very case.toml under dispute.
    #     The seal exists to be investigated, not regenerated.
    if "lockfile-drift" in err_lower:
        return ErrorRecoveryBlock(
            title="Contract Seal Mismatch",
            what_went_wrong=(
                f"The sealed contract no longer matches the configuration for this "
                f"run, so strict reproducibility cannot be guaranteed: {error}"
            ),
            how_to_fix=[
                "Diff case.toml against the sealed values in case.toml.lock and revert "
                "the unintended change.",
                "If a CLI flag (--target/--reference/--severity-gate/--timeout) caused "
                "this, drop the flag: a sealed case runs only as sealed.",
                "To start a genuinely new scan, delete case.toml.lock and the run "
                "directory, then re-run.",
            ],
            recommended_command="python main.py scan",
            exit_code=2,
        )

    # 1b. Configuration / Contract Errors (e.g. missing case.toml or invalid schema)
    if (CaseConfigError and isinstance(error, CaseConfigError)) or "case.toml" in err_lower:
        return ErrorRecoveryBlock(
            title="Configuration Contract Error",
            what_went_wrong=f"case.toml configuration file is missing, invalid, or lockfile mismatched: {error}",
            how_to_fix=[
                "Run 'python main.py init' to interactively generate a valid case.toml configuration file.",
                "Inspect 'case.toml' for syntax or schema errors against case.example.toml.",
                "Ensure no forbidden environment variables (e.g. REDACTS_*) or .env files exist in the workspace.",
            ],
            recommended_command="python main.py init",
            exit_code=2,
        )

    # 2. Refused subprocess invocation (Windows shim injection guard).
    if exc_name == "UnsafeCommandError":
        return ErrorRecoveryBlock(
            title="Unsafe Command Refused",
            what_went_wrong=(
                f"REDACTS refused to launch a scanner because the invocation "
                f"could not be made safely: {error}"
            ),
            how_to_fix=[
                "Install the tool as a native executable rather than a .cmd/.bat shim.",
                "Move the target or reference to a path without shell metacharacters "
                "(& | < > ^ ( ) \" % !).",
                "See SETUP.md for step-by-step instructions to install required dependencies.",
            ],
            recommended_command="python main.py preflight",
            exit_code=1,
        )

    # 3. Specific Missing Tool / Dependency Failures. A tool name alone is not
    #    enough - the message must also indicate absence, otherwise any error
    #    that merely mentions a scanner is reported as that scanner missing.
    if missing or isinstance(error, FileNotFoundError):
        for tool, label, description, fixes, command in _TOOL_REMEDIES:
            if _has_word(err_lower, tool):
                return ErrorRecoveryBlock(
                    title=f"Missing Dependency: {label}",
                    what_went_wrong=description,
                    how_to_fix=list(fixes),
                    recommended_command=command,
                    exit_code=1,
                )

    if missing and (
        "threat database" in err_lower
        or "cwe database" in err_lower
        or _has_word(err_lower, "cwe")
    ):
        return ErrorRecoveryBlock(
            title="Missing Threat Database",
            what_went_wrong="CWE threat database or threat rules are missing or uninitialized.",
            how_to_fix=[
                "Update the CWE threat database: python main.py update cwe",
                "Or run full threat update: python main.py update",
            ],
            recommended_command="python main.py update cwe",
            exit_code=1,
        )

    if _has_word(err_lower, "preflight"):
        return ErrorRecoveryBlock(
            title="Preflight Dependency Failure",
            what_went_wrong=f"Scan preflight checks were blocked due to missing critical dependencies: {error}",
            how_to_fix=[
                "See SETUP.md for step-by-step instructions to install required dependencies.",
                "Verify required system packages (Semgrep, Trivy, YARA, Repomix).",
            ],
            recommended_command="python main.py preflight",
            exit_code=1,
        )

    # 4. Network Disabled Error. Matched on the exception type or an explicit
    #    phrase - a bare "network" substring claimed network_disabled = true
    #    for any message that happened to mention networking.
    if exc_name == "NetworkDisabledError" or any(
        phrase in err_lower
        for phrase in ("network_disabled", "network is disabled", "network access is disabled")
    ):
        return ErrorRecoveryBlock(
            title="Network Access Disabled",
            what_went_wrong="Network access was attempted but network is disabled by security policy ([security].network_disabled = true).",
            how_to_fix=[
                "Fetch required threat database offline using 'python main.py update cwe' on an internet-connected system.",
                "Copy downloaded CWE data into 'threat_base/data/'.",
                "Or set [security].network_disabled = false in case.toml.",
            ],
            recommended_command="python main.py update cwe",
            exit_code=1,
        )

    # 5. Timeout Error
    if (
        isinstance(error, TimeoutError)
        or exc_name == "TimeoutExpired"
        or _has_word(err_lower, "timeout")
        or "timed out" in err_lower
    ):
        return ErrorRecoveryBlock(
            title="Scan Timeout Exceeded",
            what_went_wrong=f"Scan execution exceeded configured global timeout: {error}",
            how_to_fix=[
                "Increase timeout using CLI option: python main.py scan --timeout 1200",
                "Or adjust 'global_timeout_seconds' in case.toml under [static].",
                "Scope scan target to static-only mode: python main.py scan --mode static",
            ],
            recommended_command="python main.py scan --timeout 1200",
            exit_code=1,
        )

    # 6. Input File / Path Not Found Error
    if isinstance(error, FileNotFoundError) or "no such file" in err_lower:
        return ErrorRecoveryBlock(
            title="File / Path Not Found",
            what_went_wrong=f"Required target archive, reference directory, or input file does not exist: {error}",
            how_to_fix=[
                "Verify target and reference paths: python main.py scan --target <TARGET_PATH> --reference <REF_PATH>",
                "Re-run interactive wizard to update configuration: python main.py init",
            ],
            recommended_command="python main.py init",
            exit_code=1,
        )

    # 7. Severity Gate Triggered. Requires the full phrase: bare "gate" also
    #    matches aggregate/propagate/investigate/mitigate, which silently
    #    rewrote unrelated failures to exit code 2.
    if any(
        phrase in err_lower
        for phrase in ("severity gate", "severity_gate", "severity-gate")
    ):
        return _from_exit_code(2)

    # 8. Generic Fallback Error Recovery Block
    return ErrorRecoveryBlock(
        title="Runtime Error",
        what_went_wrong=f"{type(error).__name__ if isinstance(error, Exception) else 'Error'}: {error}",
        how_to_fix=[
            "Run preflight verification to check tool availability: python main.py preflight",
            "Generate fresh configuration: python main.py init",
            "Review diagnostic output logs in the output directory.",
        ],
        recommended_command="python main.py preflight",
        # Integers are handled by _from_exit_code above, so the only remaining
        # source of a non-default code is an exception carrying one.
        exit_code=getattr(error, "exit_code", 1) if isinstance(error, Exception) else 1,
    )


def format_exception_recovery(exc: Exception) -> ErrorRecoveryBlock:
    """Alias for format_error_recovery for exception instances."""
    return format_error_recovery(exc)


def handle_error(
    error: Union[Exception, str, int],
    console: Optional["Console"] = None,
) -> int:
    """Format and display a guided error recovery block, returning the exit code."""
    block = format_error_recovery(error)
    block.display(console=console)
    return block.exit_code
