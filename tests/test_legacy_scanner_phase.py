"""Tests for orchestration.phases.legacy_scanner_phase.

Covers skipping when disabled, full directory scans, delta-aware scans,
finding normalization, and exception safety.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from REDACTS.core.models import (
    Confidence,
    FindingCollection,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)
from REDACTS.forensics.security_scanner import SecurityFinding, SecurityReport
from REDACTS.orchestration.phase_protocol import OrchestratorContext
from REDACTS.orchestration.phases.legacy_scanner_phase import LegacyScannerPhase

# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_config():
    """Mock orchestrator config."""
    config = MagicMock()
    config.enable_legacy_scanner = True
    return config


@pytest.fixture
def mock_context(mock_config, tmp_path):
    """Mock shared context for the phase."""
    return OrchestratorContext(
        target_path=tmp_path / "target",
        baseline_path=None,
        config=mock_config,
        only_files=None,
        output_dir=tmp_path / "out",
        collection=FindingCollection(),
    )


@pytest.fixture
def phase():
    """The phase under test."""
    return LegacyScannerPhase()


# ═══════════════════════════════════════════════════════════════════════════
# Tests
# ═══════════════════════════════════════════════════════════════════════════

def test_name(phase):
    """The phase identifies itself correctly."""
    assert phase.name == "legacy_scanner"


def test_execute_skipped_when_disabled(phase, mock_context):
    """Phase skips itself if config disables legacy scanner."""
    mock_context.config.enable_legacy_scanner = False
    result = phase.execute(mock_context)

    assert result.skipped is True
    assert len(mock_context.collection.findings) == 0


@patch("REDACTS.orchestration.phases.legacy_scanner_phase.SecurityScanner")
@patch("REDACTS.orchestration.phases.legacy_scanner_phase.normalize_security_finding")
def test_execute_scan_directory(
    mock_normalize, mock_scanner_class, phase, mock_context
):
    """Phase scans full directory when only_files is None."""
    # Setup mock scanner and report
    mock_scanner = MagicMock()
    mock_scanner_class.return_value = mock_scanner

    mock_finding = SecurityFinding(
        severity="HIGH",
        category="injection",
        rule="SEC001",
        file="vuln.php",
        line=10,
        message="SQLi",
    )
    mock_report = SecurityReport(findings=[mock_finding])
    mock_scanner.scan_directory.return_value = mock_report

    # Setup mock normalization
    unified = UnifiedFinding(
        id="mock-id",
        rule_id="SEC001",
        title="SQLi",
        description="SQLi found",
        severity=SeverityLevel.HIGH,
        confidence=Confidence.LOW,
        source=FindingSource.SECURITY_SCANNER,
        category="injection",
    )
    mock_normalize.return_value = unified

    # Execute
    result = phase.execute(mock_context)

    # Verify
    assert result.skipped is False
    mock_scanner.scan_directory.assert_called_once_with(mock_context.target_path)
    mock_scanner.scan_files.assert_not_called()
    mock_normalize.assert_called_once()

    # Finding should be added to collection
    assert len(mock_context.collection.findings) == 1
    assert mock_context.collection.findings[0] == unified


@patch("REDACTS.orchestration.phases.legacy_scanner_phase.SecurityScanner")
def test_execute_scan_files_delta(mock_scanner_class, phase, mock_context):
    """Phase uses scan_files when only_files is provided (audit mode)."""
    # Setup mock scanner
    mock_scanner = MagicMock()
    mock_scanner_class.return_value = mock_scanner
    mock_scanner.scan_files.return_value = SecurityReport(findings=[])

    # Set delta
    mock_context.only_files = {"changed.php", "new.php"}

    # Execute
    result = phase.execute(mock_context)

    # Verify
    assert result.skipped is False
    mock_scanner.scan_files.assert_called_once_with(
        mock_context.target_path, mock_context.only_files
    )
    mock_scanner.scan_directory.assert_not_called()


@patch("REDACTS.orchestration.phases.legacy_scanner_phase.SecurityScanner")
def test_execute_exception_handling(mock_scanner_class, phase, mock_context, caplog):
    """Phase catches exceptions and returns safely."""
    # Scanner instantiation crashes
    mock_scanner_class.side_effect = RuntimeError("Scanner exploded")

    with caplog.at_level(logging.ERROR):
        result = phase.execute(mock_context)

    assert result.skipped is False
    assert len(mock_context.collection.findings) == 0
    assert "Legacy scanner phase failed" in caplog.text
    assert "Scanner exploded" in caplog.text
