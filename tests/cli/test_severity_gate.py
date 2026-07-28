"""The exit-code severity gate must span every analysis layer.

Regression for a real false-negative: the gate originally evaluated only the
tool-scan layer (``orchestrator.findings``). A scan could therefore report
risk=CRITICAL with a HIGH forensic finding and still exit 0 - so a CI pipeline
gating on the exit code would pass a compromised deployment. The gate now also
considers the deep investigation findings, baseline structural changes, and the
holistic overall-risk verdict.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from static.cli.workflow import evaluate_severity_gate
from static.core.findings import SeverityLevel


def _tool(sev: str) -> SimpleNamespace:
    """A tool-scan finding: object carrying a SeverityLevel."""
    return SimpleNamespace(severity=SeverityLevel.from_string(sev))


def _rec(sev: str) -> dict:
    """An investigation/baseline finding: dict with a severity string."""
    return {"severity": sev}


# --- the regression: non-tool layers now trip the gate --


def test_investigation_high_trips_gate_when_tool_scan_empty() -> None:
    """The exact case that used to exit 0: HIGH forensic finding, no tool findings."""
    triggered, breakdown = evaluate_severity_gate(
        "high",
        orchestrator_findings=[],
        investigation_findings=[_rec("HIGH")] + [_rec("INFO")] * 4,
        baseline_findings=[_rec("MEDIUM"), _rec("MEDIUM")],
        overall_risk="CRITICAL",
    )
    assert triggered is True
    assert breakdown.get("investigation") == 1
    assert breakdown.get("overall-risk") == 1
    assert "tool-scan" not in breakdown


def test_overall_risk_alone_trips_gate() -> None:
    """A holistic CRITICAL verdict must fail even if every finding is INFO."""
    triggered, breakdown = evaluate_severity_gate(
        "high",
        investigation_findings=[_rec("INFO")],
        overall_risk="CRITICAL",
    )
    assert triggered is True
    assert breakdown == {"overall-risk": 1}


def test_baseline_added_file_can_trip_gate_at_its_level() -> None:
    triggered, breakdown = evaluate_severity_gate(
        "medium", baseline_findings=[_rec("MEDIUM")], overall_risk="MEDIUM"
    )
    assert triggered is True
    assert breakdown.get("baseline") == 1


# --- tool-scan behavior preserved --


def test_tool_scan_finding_still_trips_gate() -> None:
    triggered, breakdown = evaluate_severity_gate(
        "high", orchestrator_findings=[_tool("HIGH"), _tool("LOW")]
    )
    assert triggered is True
    assert breakdown == {"tool-scan": 1}


# --- clean scans must NOT trip --


def test_clean_scan_does_not_trip() -> None:
    triggered, breakdown = evaluate_severity_gate(
        "high",
        orchestrator_findings=[],
        investigation_findings=[],
        baseline_findings=[],
        overall_risk="CLEAN",
    )
    assert triggered is False
    assert breakdown == {}


def test_findings_below_gate_do_not_trip() -> None:
    triggered, breakdown = evaluate_severity_gate(
        "high",
        orchestrator_findings=[_tool("MEDIUM")],
        investigation_findings=[_rec("LOW")],
        baseline_findings=[_rec("MEDIUM")],
        overall_risk="MEDIUM",
    )
    assert triggered is False
    assert breakdown == {}


def test_clean_risk_string_never_trips_even_at_info_gate() -> None:
    """'CLEAN' is not a real severity - it must not map to INFO and trip info gate."""
    triggered, _ = evaluate_severity_gate("info", overall_risk="CLEAN")
    assert triggered is False


# --- robustness --


def test_unknown_finding_severity_is_ignored_not_crashing() -> None:
    triggered, breakdown = evaluate_severity_gate(
        "high",
        investigation_findings=[{"severity": "banana"}, {"nope": 1}, {"severity": "CRITICAL"}],
    )
    assert triggered is True
    assert breakdown.get("investigation") == 1  # only the CRITICAL counts


def test_invalid_gate_raises_valueerror() -> None:
    with pytest.raises(ValueError):
        evaluate_severity_gate("banana", orchestrator_findings=[_tool("HIGH")])


def test_all_none_sources_do_not_trip() -> None:
    triggered, breakdown = evaluate_severity_gate("high")
    assert triggered is False
    assert breakdown == {}


@pytest.mark.parametrize("gate", ["info", "low", "medium", "high", "critical"])
def test_gate_level_controls_sensitivity(gate: str) -> None:
    """A single HIGH finding trips iff the gate is at or below HIGH."""
    triggered, _ = evaluate_severity_gate(
        gate, orchestrator_findings=[_tool("HIGH")]
    )
    expected = SeverityLevel.from_string(gate).numeric_rank <= SeverityLevel.HIGH.numeric_rank
    assert triggered is expected
