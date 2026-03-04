"""Tests for investigation.sarif_utils — shared SARIF parsing utilities.

Covers every public function, the Strategy pattern (location extraction),
the Plugin registry (post-parse processors), configuration-driven caps,
and parity with the original adapter implementations.
"""

from __future__ import annotations

import importlib
import json
import types
from pathlib import Path
from typing import Any

import pytest

from REDACTS.investigation import sarif_utils


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════

def _make_sarif(
    *,
    num_results: int = 3,
    num_runs: int = 1,
    include_rules: bool = False,
    include_artifacts: bool = False,
    include_invocations: bool = False,
    include_taxa: bool = False,
    cwe_id: str = "89",
) -> dict[str, Any]:
    """Build a minimal but valid SARIF 2.1.0 structure."""
    runs: list[dict[str, Any]] = []
    for run_idx in range(num_runs):
        results = []
        for i in range(num_results):
            result: dict[str, Any] = {
                "ruleId": f"rule-{run_idx}-{i}",
                "level": ["error", "warning", "note"][i % 3],
                "message": {"text": f"Finding {run_idx}-{i}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/file{i}.php"},
                            "region": {
                                "startLine": 10 + i,
                                "endLine": 12 + i,
                                "startColumn": 5,
                                "endColumn": 20,
                                "snippet": {"text": f"$code_{i}();"},
                            },
                        }
                    }
                ],
            }
            if include_taxa:
                result["taxa"] = [
                    {
                        "id": cwe_id,
                        "toolComponent": {"name": "CWE"},
                    }
                ]
            results.append(result)

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": "test-tool",
                    "version": "1.0.0",
                    "rules": [],
                }
            },
            "results": results,
        }

        if include_rules:
            run["tool"]["driver"]["rules"] = [
                {
                    "id": f"rule-{run_idx}-{i}",
                    "name": f"TestRule{i}",
                    "shortDescription": {"text": f"Description for rule {i}"},
                }
                for i in range(num_results)
            ]

        if include_artifacts:
            run["artifacts"] = [
                {"location": {"uri": f"src/file{i}.php"}}
                for i in range(num_results)
            ]

        if include_invocations:
            run["invocations"] = [
                {
                    "executionSuccessful": False,
                    "toolExecutionNotifications": [
                        {"message": {"text": f"Error in run {run_idx}"}},
                        {"message": {"text": ""}},  # empty — should be skipped
                    ],
                }
            ]

        runs.append(run)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def _reload() -> types.ModuleType:
    """Reload sarif_utils to reset registry."""
    return importlib.reload(sarif_utils)


# ═══════════════════════════════════════════════════════════════════════════
# 1. LocationStrategy protocol & built-in strategies
# ═══════════════════════════════════════════════════════════════════════════


class TestLocationStrategy:
    """Strategy pattern for location extraction."""

    def test_full_location_protocol(self) -> None:
        assert isinstance(sarif_utils.full_location, sarif_utils.LocationStrategy)

    def test_minimal_location_protocol(self) -> None:
        assert isinstance(sarif_utils.minimal_location, sarif_utils.LocationStrategy)

    def test_full_location_all_fields(self) -> None:
        phys = {
            "artifactLocation": {"uri": "src/main.php"},
            "region": {
                "startLine": 10,
                "endLine": 15,
                "startColumn": 3,
                "endColumn": 30,
                "snippet": {"text": "echo $x;"},
            },
        }
        loc = sarif_utils.full_location(phys)
        assert loc == {
            "file_path": "src/main.php",
            "line_start": 10,
            "line_end": 15,
            "column_start": 3,
            "column_end": 30,
            "snippet": "echo $x;",
        }

    def test_minimal_location_only_file_and_line(self) -> None:
        phys = {
            "artifactLocation": {"uri": "src/main.php"},
            "region": {
                "startLine": 42,
                "endLine": 50,
                "startColumn": 1,
                "endColumn": 99,
                "snippet": {"text": "ignored by minimal"},
            },
        }
        loc = sarif_utils.minimal_location(phys)
        assert loc == {"file_path": "src/main.php", "line_start": 42}

    def test_full_location_empty_input(self) -> None:
        loc = sarif_utils.full_location({})
        assert loc["file_path"] == ""
        assert loc["line_start"] == 0

    def test_minimal_location_empty_input(self) -> None:
        loc = sarif_utils.minimal_location({})
        assert loc == {"file_path": "", "line_start": 0}

    def test_custom_strategy(self) -> None:
        """A user-defined lambda satisfies LocationStrategy."""
        custom = lambda phys: {"uri": phys.get("artifactLocation", {}).get("uri", "")}
        assert isinstance(custom, sarif_utils.LocationStrategy)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Plugin registry — SARIF processors
# ═══════════════════════════════════════════════════════════════════════════


class TestProcessorRegistry:
    """Plugin registry for post-parse processors."""

    def test_register_and_retrieve(self) -> None:
        mod = _reload()
        mod.register_sarif_processor("test_noop", lambda results: results)
        assert "test_noop" in mod.get_registered_processors()
        _reload()

    def test_register_duplicate_raises(self) -> None:
        mod = _reload()
        mod.register_sarif_processor("dup", lambda r: r)
        with pytest.raises(ValueError, match="already registered"):
            mod.register_sarif_processor("dup", lambda r: r)
        _reload()

    def test_replace_processor(self) -> None:
        mod = _reload()
        mod.register_sarif_processor("rep", lambda r: r)
        mod.replace_sarif_processor("rep", lambda r: [])
        assert mod.get_registered_processors()["rep"]([1, 2]) == []
        _reload()

    def test_get_returns_copy(self) -> None:
        mod = _reload()
        procs = mod.get_registered_processors()
        procs["injected"] = lambda r: r
        assert "injected" not in mod.get_registered_processors()
        _reload()


# ═══════════════════════════════════════════════════════════════════════════
# 3. extract_sarif_results (DUP-007)
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractSarifResults:
    """DUP-007: Canonical SARIF result extraction."""

    def test_basic_extraction(self) -> None:
        sarif = _make_sarif(num_results=5)
        results = sarif_utils.extract_sarif_results(sarif)
        assert len(results) == 5

    def test_multi_run(self) -> None:
        sarif = _make_sarif(num_results=2, num_runs=3)
        results = sarif_utils.extract_sarif_results(sarif)
        assert len(results) == 6

    def test_empty_sarif(self) -> None:
        assert sarif_utils.extract_sarif_results({}) == []

    def test_empty_runs(self) -> None:
        assert sarif_utils.extract_sarif_results({"runs": []}) == []

    def test_runs_without_results(self) -> None:
        sarif = {"runs": [{"tool": {}}]}
        assert sarif_utils.extract_sarif_results(sarif) == []

    def test_max_results_cap(self) -> None:
        sarif = _make_sarif(num_results=10)
        results = sarif_utils.extract_sarif_results(sarif, max_results=3)
        assert len(results) == 3

    def test_max_results_zero_is_unlimited(self) -> None:
        sarif = _make_sarif(num_results=10)
        results = sarif_utils.extract_sarif_results(sarif, max_results=0)
        assert len(results) == 10

    def test_processors_applied(self) -> None:
        mod = _reload()
        mod.register_sarif_processor(
            "filter_errors",
            lambda results: [r for r in results if r.get("level") == "error"],
        )
        sarif = _make_sarif(num_results=6)
        results = mod.extract_sarif_results(sarif, processors=("filter_errors",))
        assert all(r["level"] == "error" for r in results)
        _reload()

    def test_unknown_processor_skipped(self) -> None:
        sarif = _make_sarif(num_results=3)
        # Should not raise, just warn
        results = sarif_utils.extract_sarif_results(
            sarif, processors=("nonexistent_proc",)
        )
        assert len(results) == 3

    def test_result_structure_preserved(self) -> None:
        sarif = _make_sarif(num_results=1)
        results = sarif_utils.extract_sarif_results(sarif)
        r = results[0]
        assert "ruleId" in r
        assert "level" in r
        assert "message" in r
        assert "locations" in r


# ═══════════════════════════════════════════════════════════════════════════
# 4. count_by_severity (DUP-008)
# ═══════════════════════════════════════════════════════════════════════════


class _FakeSeverity:
    """Mimics SeverityLevel enum .value attribute."""
    def __init__(self, value: str) -> None:
        self.value = value


class _FakeFinding:
    """Mimics UnifiedFinding with .severity."""
    def __init__(self, severity_value: str) -> None:
        self.severity = _FakeSeverity(severity_value)


class TestCountBySeverity:
    """DUP-008: Canonical severity counting."""

    def test_basic_counting(self) -> None:
        findings = [
            _FakeFinding("HIGH"),
            _FakeFinding("HIGH"),
            _FakeFinding("LOW"),
        ]
        counts = sarif_utils.count_by_severity(findings)
        assert counts == {"HIGH": 2, "LOW": 1}

    def test_empty_findings(self) -> None:
        assert sarif_utils.count_by_severity([]) == {}

    def test_single_finding(self) -> None:
        counts = sarif_utils.count_by_severity([_FakeFinding("CRITICAL")])
        assert counts == {"CRITICAL": 1}

    def test_all_levels(self) -> None:
        findings = [_FakeFinding(s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        counts = sarif_utils.count_by_severity(findings)
        assert len(counts) == 5
        assert all(c == 1 for c in counts.values())

    def test_invalid_finding_uses_fallback(self) -> None:
        """Object without .severity.value falls back to UNKNOWN."""

        class NoSeverity:
            pass

        counts = sarif_utils.count_by_severity([NoSeverity()])
        assert counts == {"UNKNOWN": 1}

    def test_custom_default_severity(self) -> None:
        class NoSeverity:
            pass

        counts = sarif_utils.count_by_severity(
            [NoSeverity()], default_severity_value="UNCLASSIFIED"
        )
        assert counts == {"UNCLASSIFIED": 1}


# ═══════════════════════════════════════════════════════════════════════════
# 5. extract_location — Strategy-based
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractLocation:
    """Strategy-based location extraction."""

    def test_full_strategy_default(self) -> None:
        sarif = _make_sarif(num_results=1)
        result = sarif_utils.extract_sarif_results(sarif)[0]
        loc = sarif_utils.extract_location(result)
        assert loc["file_path"] == "src/file0.php"
        assert loc["line_start"] == 10
        assert loc["line_end"] == 12
        assert loc["column_start"] == 5
        assert loc["snippet"] == "$code_0();"

    def test_minimal_strategy(self) -> None:
        sarif = _make_sarif(num_results=1)
        result = sarif_utils.extract_sarif_results(sarif)[0]
        loc = sarif_utils.extract_location(result, strategy=sarif_utils.minimal_location)
        assert set(loc.keys()) == {"file_path", "line_start"}
        assert loc["file_path"] == "src/file0.php"
        assert loc["line_start"] == 10

    def test_no_locations(self) -> None:
        result = {"ruleId": "test", "level": "error", "message": {"text": "msg"}}
        loc = sarif_utils.extract_location(result)
        assert loc == {}

    def test_custom_strategy_callable(self) -> None:
        def uri_only(phys: dict[str, Any]) -> dict[str, Any]:
            return {"uri": phys.get("artifactLocation", {}).get("uri", "")}

        sarif = _make_sarif(num_results=1)
        result = sarif_utils.extract_sarif_results(sarif)[0]
        loc = sarif_utils.extract_location(result, strategy=uri_only)
        assert loc == {"uri": "src/file0.php"}


# ═══════════════════════════════════════════════════════════════════════════
# 6. extract_cwe
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractCwe:
    """CWE extraction from SARIF taxa + properties fallback."""

    def test_cwe_from_taxa(self) -> None:
        sarif = _make_sarif(num_results=1, include_taxa=True, cwe_id="89")
        result = sarif_utils.extract_sarif_results(sarif)[0]
        assert sarif_utils.extract_cwe(result) == "CWE-89"

    def test_cwe_from_properties_fallback(self) -> None:
        result = {
            "ruleId": "test",
            "properties": {"cwe": "CWE-79"},
        }
        assert sarif_utils.extract_cwe(result) == "CWE-79"

    def test_no_cwe(self) -> None:
        result = {"ruleId": "test"}
        assert sarif_utils.extract_cwe(result) == ""

    def test_taxa_preferred_over_properties(self) -> None:
        result = {
            "taxa": [{"id": "89", "toolComponent": {"name": "CWE"}}],
            "properties": {"cwe": "CWE-79"},
        }
        assert sarif_utils.extract_cwe(result) == "CWE-89"

    def test_non_cwe_taxa_skipped(self) -> None:
        result = {
            "taxa": [{"id": "T1059", "toolComponent": {"name": "MITRE"}}],
            "properties": {"cwe": "CWE-502"},
        }
        assert sarif_utils.extract_cwe(result) == "CWE-502"


# ═══════════════════════════════════════════════════════════════════════════
# 7. extract_rules
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractRules:
    """Rule extraction from SARIF tool.driver.rules."""

    def test_basic_extraction(self) -> None:
        sarif = _make_sarif(num_results=3, include_rules=True)
        rules = sarif_utils.extract_rules(sarif)
        assert len(rules) == 3
        assert rules[0]["id"] == "rule-0-0"
        assert rules[0]["name"] == "TestRule0"
        assert "Description" in rules[0]["shortDescription"]

    def test_no_rules(self) -> None:
        sarif = _make_sarif(num_results=1)
        assert sarif_utils.extract_rules(sarif) == []

    def test_empty_sarif(self) -> None:
        assert sarif_utils.extract_rules({}) == []


# ═══════════════════════════════════════════════════════════════════════════
# 8. count_files_scanned
# ═══════════════════════════════════════════════════════════════════════════


class TestCountFilesScanned:
    """File-count from SARIF artifacts + result locations."""

    def test_from_artifacts(self) -> None:
        sarif = _make_sarif(num_results=3, include_artifacts=True)
        count = sarif_utils.count_files_scanned(sarif)
        assert count == 3  # file0, file1, file2

    def test_from_result_locations(self) -> None:
        sarif = _make_sarif(num_results=3)
        count = sarif_utils.count_files_scanned(sarif)
        assert count == 3

    def test_deduplication(self) -> None:
        sarif = _make_sarif(num_results=3, include_artifacts=True)
        # artifacts + result locations point to same files
        count = sarif_utils.count_files_scanned(sarif)
        assert count == 3  # deduplicated

    def test_empty_sarif(self) -> None:
        assert sarif_utils.count_files_scanned({}) == 0


# ═══════════════════════════════════════════════════════════════════════════
# 9. extract_execution_errors
# ═══════════════════════════════════════════════════════════════════════════


class TestExtractExecutionErrors:
    """Error extraction from SARIF invocations."""

    def test_extracts_errors(self) -> None:
        sarif = _make_sarif(num_results=1, include_invocations=True)
        errors = sarif_utils.extract_execution_errors(sarif)
        assert len(errors) == 1  # empty-message entry is skipped
        assert "Error in run 0" in errors[0]

    def test_no_invocations(self) -> None:
        sarif = _make_sarif(num_results=1)
        assert sarif_utils.extract_execution_errors(sarif) == []

    def test_empty_sarif(self) -> None:
        assert sarif_utils.extract_execution_errors({}) == []


# ═══════════════════════════════════════════════════════════════════════════
# 10. load_sarif_file
# ═══════════════════════════════════════════════════════════════════════════


class TestLoadSarifFile:
    """Convenience function: load + extract."""

    def test_load_valid_file(self, tmp_path: Path) -> None:
        sarif_data = _make_sarif(num_results=4)
        sarif_file = tmp_path / "results.sarif"
        sarif_file.write_text(json.dumps(sarif_data), encoding="utf-8")

        root, results = sarif_utils.load_sarif_file(sarif_file)
        assert root["version"] == "2.1.0"
        assert len(results) == 4

    def test_load_with_max_results(self, tmp_path: Path) -> None:
        sarif_data = _make_sarif(num_results=10)
        sarif_file = tmp_path / "big.sarif"
        sarif_file.write_text(json.dumps(sarif_data), encoding="utf-8")

        _, results = sarif_utils.load_sarif_file(sarif_file, max_results=2)
        assert len(results) == 2

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            sarif_utils.load_sarif_file(tmp_path / "missing.sarif")

    def test_load_invalid_json_raises(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.sarif"
        bad_file.write_text("not json", encoding="utf-8")
        with pytest.raises(json.JSONDecodeError):
            sarif_utils.load_sarif_file(bad_file)


# ═══════════════════════════════════════════════════════════════════════════
# 11. Legacy parity
# ═══════════════════════════════════════════════════════════════════════════


class TestLegacyParity:
    """Ensure canonical functions produce identical results to originals."""

    def test_extract_parity_with_semgrep(self) -> None:
        """Output matches SemgrepAdapter._extract_sarif_results."""
        sarif = _make_sarif(num_results=5, num_runs=2)

        # Legacy implementation (inline copy from semgrep_adapter.py L231)
        legacy_results: list[dict[str, Any]] = []
        for run in sarif.get("runs", []):
            legacy_results.extend(run.get("results", []))

        canonical = sarif_utils.extract_sarif_results(sarif)
        assert canonical == legacy_results

    def test_extract_parity_with_trivy(self) -> None:
        """Output matches TrivyAdapter._extract_sarif_results."""
        sarif = _make_sarif(num_results=3, num_runs=1)

        legacy_results: list[dict[str, Any]] = []
        for run in sarif.get("runs", []):
            legacy_results.extend(run.get("results", []))

        canonical = sarif_utils.extract_sarif_results(sarif)
        assert canonical == legacy_results

    def test_count_severity_parity(self) -> None:
        """Output matches SemgrepAdapter._count_by_severity."""
        findings = [
            _FakeFinding("HIGH"),
            _FakeFinding("HIGH"),
            _FakeFinding("MEDIUM"),
            _FakeFinding("LOW"),
            _FakeFinding("CRITICAL"),
        ]

        # Legacy (inline copy from semgrep_adapter.py L418)
        legacy_counts: dict[str, int] = {}
        for f in findings:
            key = f.severity.value
            legacy_counts[key] = legacy_counts.get(key, 0) + 1

        canonical = sarif_utils.count_by_severity(findings)
        assert canonical == legacy_counts

    def test_extract_rules_parity(self) -> None:
        """Output matches SemgrepAdapter._extract_rules."""
        sarif = _make_sarif(num_results=3, include_rules=True)

        # Legacy (inline copy from semgrep_adapter.py L241)
        legacy_rules: list[dict[str, str]] = []
        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            for rule in driver.get("rules", []):
                legacy_rules.append({
                    "id": rule.get("id", ""),
                    "name": rule.get("name", ""),
                    "shortDescription": (
                        rule.get("shortDescription", {}).get("text", "")
                    ),
                })

        canonical = sarif_utils.extract_rules(sarif)
        assert canonical == legacy_rules

    def test_count_files_parity(self) -> None:
        """Output matches SemgrepAdapter._count_files_scanned."""
        sarif = _make_sarif(num_results=5, include_artifacts=True)

        # Legacy (inline copy from semgrep_adapter.py L257)
        files: set[str] = set()
        for run in sarif.get("runs", []):
            for artifact in run.get("artifacts", []):
                uri = artifact.get("location", {}).get("uri", "")
                if uri:
                    files.add(uri)
            for result in run.get("results", []):
                for loc in result.get("locations", []):
                    uri = (
                        loc.get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri", "")
                    )
                    if uri:
                        files.add(uri)
        legacy_count = len(files)

        canonical = sarif_utils.count_files_scanned(sarif)
        assert canonical == legacy_count

    def test_cwe_extraction_parity_semgrep(self) -> None:
        """Matches CWE extraction logic from semgrep_adapter.py L312-319."""
        result_taxa = {
            "taxa": [{"id": "89", "toolComponent": {"name": "CWE"}}],
            "properties": {"cwe": "CWE-79"},
        }
        # Legacy: taxa wins
        cwe_id = ""
        for taxa in result_taxa.get("taxa", []):
            component = taxa.get("toolComponent", {}).get("name", "")
            if component.upper() == "CWE":
                cwe_id = f"CWE-{taxa.get('id', '')}"
                break
        if not cwe_id:
            props = result_taxa.get("properties", {})
            cwe_id = props.get("cwe", "")

        assert sarif_utils.extract_cwe(result_taxa) == cwe_id

    def test_execution_errors_parity(self) -> None:
        """Matches SARIF error extraction from semgrep_adapter.py L170-178."""
        sarif = _make_sarif(num_results=1, include_invocations=True)

        # Legacy
        legacy_errors: list[str] = []
        for run in sarif.get("runs", []):
            for inv in run.get("invocations", []):
                for note in inv.get("toolExecutionNotifications", []):
                    msg = note.get("message", {}).get("text", "")
                    if msg:
                        legacy_errors.append(msg)

        assert sarif_utils.extract_execution_errors(sarif) == legacy_errors
