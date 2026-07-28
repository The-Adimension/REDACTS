"""``format_error_recovery`` must not misclassify ordinary failures.

The classifier originally used plain substring tests, which matched far more
than intended:

* ``"gate" in msg`` matches *aggregate*, *propagate*, *investigate*,
  *mitigate* - so a routine scanner error was reported as a severity-gate trip
  **and had its exit code rewritten to 2**, which a CI gate would read as
  "findings exceeded threshold" rather than "the scan broke".
* ``"threat" in msg`` matches almost anything in a codebase with a
  ``threat_base`` package.
* ``"network" in msg`` claimed ``network_disabled = true`` for any message that
  mentioned networking.
* ``"not found" in msg`` turned a missing Python module into "check your
  target and reference paths".

Classification is now type-first, then word-boundary and phrase matches.
"""

from __future__ import annotations

import pytest

from static.cli.error_recovery import format_error_recovery


# --- words that must no longer trigger the severity gate --


@pytest.mark.parametrize(
    "message",
    [
        "Failed to aggregate scanner results",
        "SSRF allowlist check propagated failure",
        "Could not investigate delta file",
        "Attempting to mitigate risk in delegated handler",
        "Segment delegated to subordinate navigator",
    ],
)
def test_words_containing_gate_do_not_trip_severity_gate(message: str) -> None:
    block = format_error_recovery(RuntimeError(message))

    assert block.title != "Severity Gate Threshold Triggered"
    assert block.exit_code != 2, "an unrelated failure must not become exit 2"


@pytest.mark.parametrize(
    "message",
    [
        "severity gate threshold exceeded",
        "severity_gate reached",
        "--severity-gate triggered",
    ],
)
def test_explicit_severity_gate_phrases_still_match(message: str) -> None:
    block = format_error_recovery(RuntimeError(message))

    assert block.title == "Severity Gate Threshold Triggered"
    assert block.exit_code == 2


# --- a tool mentioned is not a tool missing --


@pytest.mark.parametrize(
    "message",
    [
        "semgrep returned malformed SARIF on line 4",
        "trivy exited with a JSON parse error",
        "yara rule compilation produced 3 warnings",
        "repomix wrote 0 bytes to the output file",
    ],
)
def test_tool_mentioned_without_absence_is_not_a_missing_dependency(message: str) -> None:
    block = format_error_recovery(RuntimeError(message))

    assert not block.title.startswith("Missing Dependency")


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("semgrep scanner not found on PATH", "Missing Dependency: Semgrep"),
        ("trivy vulnerability scanner not found", "Missing Dependency: Trivy"),
        ("yara is not installed", "Missing Dependency: YARA"),
        ("repomix is missing", "Missing Dependency: Repomix"),
    ],
)
def test_genuinely_missing_tools_still_classify(message: str, expected: str) -> None:
    assert format_error_recovery(message).title == expected


# --- network --


def test_bare_network_mention_is_not_reported_as_disabled() -> None:
    """Claiming network_disabled = true when it is not set misleads the operator."""
    block = format_error_recovery(RuntimeError("network socket read returned EOF"))

    assert block.title != "Network Access Disabled"


def test_network_disabled_error_type_still_classifies() -> None:
    from static.core.network import NetworkDisabledError

    block = format_error_recovery(NetworkDisabledError("blocked by policy"))

    assert block.title == "Network Access Disabled"


# --- not found --


def test_missing_python_module_is_not_reported_as_missing_input_path() -> None:
    block = format_error_recovery(ImportError("module 'lxml' not found"))

    assert block.title != "File / Path Not Found"


def test_file_not_found_error_type_still_classifies() -> None:
    block = format_error_recovery(FileNotFoundError("target.zip"))

    assert block.title == "File / Path Not Found"


# --- exit codes are not text --


@pytest.mark.parametrize("code", [1, 3, 70, 130])
def test_non_gate_exit_codes_preserve_their_value(code: int) -> None:
    block = format_error_recovery(code)

    assert block.exit_code == code
    assert block.title != "Severity Gate Threshold Triggered"


def test_exit_code_two_is_the_severity_gate() -> None:
    block = format_error_recovery(2)

    assert block.title == "Severity Gate Threshold Triggered"
    assert block.exit_code == 2


# --- refused subprocess invocations get their own guidance --


def test_unsafe_command_error_is_classified() -> None:
    from static.core.subprocess_env import UnsafeCommandError

    block = format_error_recovery(
        UnsafeCommandError("refusing to run Windows script shim 'x.bat'")
    )

    assert block.title == "Unsafe Command Refused"
    assert any("native executable" in step for step in block.how_to_fix)
