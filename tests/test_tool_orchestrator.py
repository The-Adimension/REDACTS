"""Tests for the REDACTS ToolOrchestrator."""

from __future__ import annotations

import time
from pathlib import Path

from REDACTS.core.models import (
    Confidence,
    FindingCollection,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)
from REDACTS.orchestration.phase_protocol import (
    OrchestratorContext,
    PhaseResult,
)
from REDACTS.orchestration.tool_orchestrator import (
    OrchestratorConfig,
    ToolOrchestrator,
)


class MockPhase:
    """A simple mock phase for testing orchestration."""

    def __init__(self, name: str, sleep_time: float = 0.0) -> None:
        self.name = name
        self.sleep_time = sleep_time
        self.executed = False

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        self.executed = True
        if self.sleep_time > 0:
            time.sleep(self.sleep_time)
        return PhaseResult(skipped=False)


class ErrorPhase:
    """A mock phase that raises an exception."""

    name = "error_phase"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        raise ValueError("Simulated phase failure")


class MockMagikaResult:
    def __init__(self, match: bool, label: str):
        self.content_type_match = match
        self.label = label


def test_orchestrator_initialization(tmp_path: Path) -> None:
    """Test that the orchestrator initializes correctly with defaults."""
    target = tmp_path / "target"
    target.mkdir()

    orchestrator = ToolOrchestrator(target_path=target, phases=[])

    assert orchestrator.target_path == target
    assert orchestrator.baseline_path is None
    assert isinstance(orchestrator.config, OrchestratorConfig)
    assert orchestrator.only_files is None
    assert orchestrator.output_dir == target.parent / "_orchestrator"
    assert orchestrator.phases == []


def test_orchestrator_initialization_with_args(tmp_path: Path) -> None:
    """Test that the orchestrator respects custom initialization arguments."""
    target = tmp_path / "target"
    baseline = tmp_path / "baseline"
    output_dir = tmp_path / "custom_output"
    only_files = {"foo.php"}
    config = OrchestratorConfig(enable_semgrep=False)

    orchestrator = ToolOrchestrator(
        target_path=target,
        baseline_path=baseline,
        config=config,
        only_files=only_files,
        output_dir=output_dir,
        phases=[MockPhase("test")],
    )

    assert orchestrator.baseline_path == baseline
    assert orchestrator.config.enable_semgrep is False
    assert orchestrator.only_files == only_files
    assert orchestrator.output_dir == output_dir
    assert len(orchestrator.phases) == 1
    assert orchestrator.phases[0].name == "test"


def test_register_phase(tmp_path: Path) -> None:
    """Test that custom phases can be registered and ordered."""
    orchestrator = ToolOrchestrator(target_path=tmp_path, phases=[MockPhase("first")])

    orchestrator.register_phase(MockPhase("third"))
    orchestrator.register_phase(MockPhase("second"), index=1)
    orchestrator.register_phase(MockPhase("zeroth"), index=0)

    names = [p.name for p in orchestrator.phases]
    assert names == ["zeroth", "first", "second", "third"]


def test_run_all_execution(tmp_path: Path) -> None:
    """Test that run_all executes phases in order and records timings."""
    p1 = MockPhase("p1", sleep_time=0.01)
    p2 = MockPhase("p2", sleep_time=0.01)

    orchestrator = ToolOrchestrator(target_path=tmp_path, phases=[p1, p2])

    collection = orchestrator.run_all()

    assert isinstance(collection, FindingCollection)
    assert p1.executed is True
    assert p2.executed is True

    # Check timings were recorded
    assert "p1" in orchestrator.phase_timings
    assert "p2" in orchestrator.phase_timings
    assert "total" in orchestrator.phase_timings
    assert orchestrator.phase_timings["p1"] > 0
    assert orchestrator.phase_timings["total"] >= (
        orchestrator.phase_timings["p1"] + orchestrator.phase_timings["p2"]
    )


def test_run_all_phase_error(tmp_path: Path) -> None:
    """Test that a failing phase does not halt the entire pipeline."""
    p1 = MockPhase("p1")
    p2 = MockPhase("p3")

    orchestrator = ToolOrchestrator(target_path=tmp_path, phases=[p1, ErrorPhase(), p2])

    # Should not raise
    orchestrator.run_all()

    assert p1.executed is True
    assert p2.executed is True
    assert "error_phase" in orchestrator.phase_timings


def test_public_query_api(tmp_path: Path) -> None:
    """Test the read-only properties of the orchestrator."""
    orchestrator = ToolOrchestrator(target_path=tmp_path, phases=[])

    # They should be empty initially
    assert isinstance(orchestrator.findings, FindingCollection)
    assert len(orchestrator.findings.findings) == 0

    assert orchestrator.magika_results == {}
    assert orchestrator.tool_availability == {}
    assert orchestrator.phase_timings == {}

    # Manually populate context to verify properties return internal state
    orchestrator._context.magika_results["foo.txt"] = "text/plain"
    orchestrator._context.tool_availability["semgrep"] = True
    orchestrator._context.phase_timings["p1"] = 1.0

    assert orchestrator.magika_results == {"foo.txt": "text/plain"}
    assert orchestrator.tool_availability == {"semgrep": True}
    assert orchestrator.phase_timings == {"p1": 1.0}


def test_get_suspicious_files(tmp_path: Path) -> None:
    """Test the cross-tool suspicious file correlation logic."""
    orchestrator = ToolOrchestrator(target_path=tmp_path, phases=[])
    context = orchestrator._context

    # File 1: Only one low severity finding
    f1 = UnifiedFinding(
        rule_id="test1",
        title="Test 1",
        description="Low severity issue",
        severity=SeverityLevel.LOW,
        source=FindingSource.SEMGREP,
        id="1",
        confidence=Confidence.HIGH,
        category="test",
        file_path="normal.php",
    )
    context.collection.add(f1)

    # File 2: Multiple tools flagged it (Semgrep + Yara)
    f2 = UnifiedFinding(
        rule_id="test2",
        title="Test 2",
        description="Medium issue",
        severity=SeverityLevel.MEDIUM,
        source=FindingSource.SEMGREP,
        id="1",
        confidence=Confidence.HIGH,
        category="test",
        file_path="multi.php",
    )
    f3 = UnifiedFinding(
        rule_id="test3",
        title="Test 3",
        description="Yara hit",
        severity=SeverityLevel.HIGH,
        source=FindingSource.YARA,
        id="3",
        confidence=Confidence.HIGH,
        category="test",
        file_path="multi.php",
    )
    context.collection.add(f2)
    context.collection.add(f3)

    # File 3: Critical severity finding (only one source)
    f4 = UnifiedFinding(
        rule_id="test4",
        title="Test 4",
        description="Critical hit",
        severity=SeverityLevel.CRITICAL,
        source=FindingSource.SECURITY_SCANNER,
        id="4",
        confidence=Confidence.HIGH,
        category="test",
        file_path="critical.php",
    )
    context.collection.add(f4)

    # File 4: Magika content-type mismatch
    context.magika_results["mismatch.txt"] = MockMagikaResult(match=False, label="php")

    # File 5: Magika match (should not be flagged)
    context.magika_results["match.txt"] = MockMagikaResult(match=True, label="txt")

    suspicious = orchestrator.get_suspicious_files()

    # normal.php (1 signal, low severity) should NOT be in the list
    # match.txt (Magika match) should NOT be in the list
    assert len(suspicious) == 3

    paths = [s["path"] for s in suspicious]
    assert "multi.php" in paths
    assert "critical.php" in paths
    assert "mismatch.txt" in paths

    # Check sorting: CRITICAL should be first
    assert suspicious[0]["path"] == "critical.php"
    assert suspicious[0]["max_severity"] == "critical"

    # Next should be multi.php (High severity, 2 signals)
    assert suspicious[1]["path"] == "multi.php"
    assert suspicious[1]["max_severity"] == "high"
    assert suspicious[1]["source_count"] == 2

    # Last is mismatch.txt (info severity by default, but has mismatch)
    assert suspicious[2]["path"] == "mismatch.txt"
    assert suspicious[2]["magika_mismatch"] is True
