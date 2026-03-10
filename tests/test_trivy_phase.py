"""Tests for the TrivyPhase orchestrator component."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest
from REDACTS.core.models import (
    Confidence,
    CvssVector,
    FindingCollection,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)
from REDACTS.investigation.external_tools import ExternalToolResult
from REDACTS.orchestration.phase_protocol import OrchestratorContext
from REDACTS.orchestration.phases.trivy_phase import TrivyPhase


@pytest.fixture
def mock_config() -> Any:
    class MockConfig:
        enable_trivy = True
        tool_timeout = 300
        trivy_scanners = ["vuln", "secret"]
        trivy_severity = ""
        generate_sbom = False
        sbom_output_path = ""

    return MockConfig()


@pytest.fixture
def orchestrator_context(tmp_path: Path, mock_config: Any) -> OrchestratorContext:
    collection = FindingCollection()
    target_path = tmp_path / "target"
    target_path.mkdir()

    return OrchestratorContext(
        target_path=target_path,
        baseline_path=None,
        config=mock_config,
        only_files=None,
        output_dir=tmp_path / "output",
        collection=collection,
        tool_availability={"trivy": True},
    )


class MockTrivyAdapter:
    def __init__(
        self, result: ExternalToolResult, sbom_result: ExternalToolResult | None = None
    ):
        self._result = result
        self._sbom_result = sbom_result
        self.run_called_with: tuple[Path, dict[str, Any]] | None = None
        self.run_sbom_called_with: tuple[Path, Path] | None = None

    def run(self, target_path: Path, config: dict[str, Any]) -> ExternalToolResult:
        self.run_called_with = (target_path, config)
        return self._result

    def run_sbom(self, target_path: Path, output_path: Path) -> ExternalToolResult:
        self.run_sbom_called_with = (target_path, output_path)
        if self._sbom_result:
            return self._sbom_result
        return ExternalToolResult(tool_name="trivy", success=False)


def create_finding(
    file_path: str = "test.txt", cve_id: str = "CVE-2023-1234"
) -> UnifiedFinding:
    return UnifiedFinding(
        id="",
        rule_id=cve_id,
        title="Test Vuln",
        description="A test vulnerability",
        severity=SeverityLevel.HIGH,
        confidence=Confidence.CONFIRMED,
        source=FindingSource.TRIVY,
        category="dependency_vulnerability",
        file_path=file_path,
        tool_name="trivy",
        cve_id=cve_id,
        cvss=CvssVector(base_score=7.5),
    )


def test_trivy_phase_skipped_when_disabled(
    orchestrator_context: OrchestratorContext,
) -> None:
    orchestrator_context.config.enable_trivy = False
    phase = TrivyPhase()
    result = phase.execute(orchestrator_context)
    assert result.skipped is True
    assert len(orchestrator_context.collection.findings) == 0


def test_trivy_phase_skipped_when_tool_unavailable(
    orchestrator_context: OrchestratorContext,
) -> None:
    orchestrator_context.tool_availability["trivy"] = False
    phase = TrivyPhase()
    result = phase.execute(orchestrator_context)
    assert result.skipped is True
    assert len(orchestrator_context.collection.findings) == 0


def test_trivy_phase_success(
    orchestrator_context: OrchestratorContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    phase = TrivyPhase()

    findings = [
        create_finding("composer.lock"),
        create_finding("package.json", "CVE-2023-5678"),
    ]
    result_data = ExternalToolResult(
        tool_name="trivy",
        success=True,
        execution_time_seconds=1.5,
        parsed_data={
            "unified_findings": findings,
            "cve_findings_count": 2,
            "secret_findings_count": 0,
        },
    )

    adapter = MockTrivyAdapter(result_data)
    monkeypatch.setattr(
        "REDACTS.investigation.trivy_adapter.TrivyAdapter", lambda: adapter
    )

    result = phase.execute(orchestrator_context)

    assert result.skipped is False
    assert adapter.run_called_with is not None
    assert adapter.run_called_with[0] == orchestrator_context.target_path

    # Verify findings were added
    assert len(orchestrator_context.collection.findings) == 2


def test_trivy_phase_with_delta_filter(
    orchestrator_context: OrchestratorContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    phase = TrivyPhase()
    orchestrator_context.only_files = {"package.json"}

    findings = [
        create_finding("composer.lock"),
        create_finding("package.json", "CVE-2023-5678"),
    ]
    result_data = ExternalToolResult(
        tool_name="trivy",
        success=True,
        execution_time_seconds=1.5,
        parsed_data={
            "unified_findings": findings,
            "cve_findings_count": 2,
            "secret_findings_count": 0,
        },
    )

    adapter = MockTrivyAdapter(result_data)
    monkeypatch.setattr(
        "REDACTS.investigation.trivy_adapter.TrivyAdapter", lambda: adapter
    )

    result = phase.execute(orchestrator_context)

    assert result.skipped is False
    # Only the finding in package.json should remain
    assert len(orchestrator_context.collection.findings) == 1
    assert orchestrator_context.collection.findings[0].file_path == "package.json"


def test_trivy_phase_failure(
    orchestrator_context: OrchestratorContext,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    phase = TrivyPhase()

    result_data = ExternalToolResult(
        tool_name="trivy", success=False, errors=["scan error"]
    )

    adapter = MockTrivyAdapter(result_data)
    monkeypatch.setattr(
        "REDACTS.investigation.trivy_adapter.TrivyAdapter", lambda: adapter
    )

    with caplog.at_level(logging.WARNING):
        result = phase.execute(orchestrator_context)

    assert result.skipped is False
    assert len(orchestrator_context.collection.findings) == 0
    assert "Trivy: scan failed" in caplog.text


def test_trivy_phase_generate_sbom(
    orchestrator_context: OrchestratorContext,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    phase = TrivyPhase()
    orchestrator_context.config.generate_sbom = True

    result_data = ExternalToolResult(
        tool_name="trivy", success=True, parsed_data={"unified_findings": []}
    )
    sbom_result_data = ExternalToolResult(tool_name="trivy", success=True)

    adapter = MockTrivyAdapter(result_data, sbom_result_data)
    monkeypatch.setattr(
        "REDACTS.investigation.trivy_adapter.TrivyAdapter", lambda: adapter
    )

    with caplog.at_level(logging.INFO):
        result = phase.execute(orchestrator_context)

    assert result.skipped is False
    assert adapter.run_sbom_called_with is not None
    assert "Trivy: SBOM generated at" in caplog.text


def test_trivy_phase_exception(
    orchestrator_context: OrchestratorContext,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    phase = TrivyPhase()

    class RaisingAdapter:
        def run(self, *args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("unexpected error")

    monkeypatch.setattr(
        "REDACTS.investigation.trivy_adapter.TrivyAdapter", RaisingAdapter
    )

    with caplog.at_level(logging.ERROR):
        result = phase.execute(orchestrator_context)

    assert result.skipped is False
    assert "Trivy phase failed: unexpected error" in caplog.text
