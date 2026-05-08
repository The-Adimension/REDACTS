"""Tests for SARIF exporter - CI/CD compliance and OASIS schema validation.

Covers:
    1. SARIF v2.1.0 schema validation against the canonical OASIS spec
    2. ``%SRCROOT%`` uriBaseId presence
    3. MITRE ATT&CK tags in rule properties
    4. CWE + ATT&CK dual taxonomy
    5. Provenance property bag with ATT&CK disclaimer
    6. Rule hydration (YAML-enriched descriptions)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from static.core.findings import (
    Confidence,
    FindingCollection,
    FindingSource,
    SeverityLevel,
    UnifiedFinding,
)
from static.collect.provenance import ProvenanceData
from static.report.sarif_exporter import SarifExporter


# --- Fixtures ---


def _make_finding(**overrides: Any) -> UnifiedFinding:
    """Create a realistic finding with sane defaults."""
    defaults = dict(
        id="TEST-001",
        rule_id="SEC001",
        title="SQL Injection via unsanitized input",
        description="Direct user input concatenated into SQL query string.",
        severity=SeverityLevel.CRITICAL,
        confidence=Confidence.HIGH,
        source=FindingSource.SECURITY_SCANNER,
        category="injection",
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command",
        mitre_attack_id="T1190",
        mitre_attack_name="Exploit Public-Facing Application",
        file_path="Classes/Database.php",
        line_start=42,
        line_end=42,
        snippet="$sql = \"SELECT * FROM users WHERE id=\" . $_GET['id'];",
        recommendation="Use parameterized queries.",
    )
    defaults.update(overrides)
    return UnifiedFinding(**defaults)


def _make_collection(
    *, n_findings: int = 3, include_cwe: bool = True, include_attack: bool = True
) -> FindingCollection:
    """Build a FindingCollection with N diverse findings."""
    rules = [
        ("SEC001", "injection", "CWE-89", "T1190", "Exploit Public-Facing Application"),
        ("SEC027", "webshell", "CWE-94", "T1505.003", "Web Shell"),
        ("SEC042", "credentials", "CWE-798", "T1552.001", "Credentials In Files"),
    ]

    collection = FindingCollection(
        target_path="/evidence/redcap_15.7.4",
        baseline_path="/reference/redcap_15.7.4.zip",
    )
    collection.scan_started = datetime.now(timezone.utc).isoformat()
    collection.scan_completed = datetime.now(timezone.utc).isoformat()
    collection.tool_versions = {"semgrep": "1.67.0", "trivy": "0.52.0"}

    for i in range(min(n_findings, len(rules))):
        rule_id, cat, cwe, attack_id, attack_name = rules[i]
        collection.findings.append(
            _make_finding(
                id=f"TEST-{i + 1:03d}",
                rule_id=rule_id,
                category=cat,
                cwe_id=cwe if include_cwe else "",
                cwe_name="" if not include_cwe else f"CWE Name for {cwe}",
                mitre_attack_id=attack_id if include_attack else "",
                mitre_attack_name=attack_name if include_attack else "",
                file_path=f"Classes/Module{i}.php",
                line_start=10 * (i + 1),
            )
        )
    return collection


def _make_provenance() -> ProvenanceData:
    """Build a realistic ProvenanceData."""
    return ProvenanceData(
        input_hashes={
            "target": "abc123" * 10 + "ab",
            "reference": "def456" * 10 + "de",
        },
        tool_versions={"semgrep": "1.67.0", "trivy": "0.52.0"},
        knowledge_data_hashes={
            "security_rules.yaml": "aaa111" * 10 + "aa",
            "ioc_indicators.yaml": "bbb222" * 10 + "bb",
        },
        scan_started=datetime.now(timezone.utc).isoformat(),
        scan_completed=datetime.now(timezone.utc).isoformat(),
    )


# --- Test: OASIS schema validation


_SARIF_SCHEMA_PATH = (
    Path(__file__).parent.parent / "data" / "sarif-schema-2.1.0.json"
)


def _load_schema() -> dict[str, Any]:
    """Load the SARIF schema, fetching from GitHub SchemaStore if missing."""
    if _SARIF_SCHEMA_PATH.exists():
        return json.loads(_SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))

    # Fetch canonical schema and cache locally for offline use
    import urllib.request

    url = (
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
        "main/sarif-2.1/schema/sarif-schema-2.1.0.json"
    )
    _SARIF_SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.urlopen(url, timeout=30)  # noqa: S310
    data = req.read().decode("utf-8")
    _SARIF_SCHEMA_PATH.write_text(data, encoding="utf-8")
    return json.loads(data)


@pytest.fixture(scope="module")
def sarif_schema() -> dict[str, Any]:
    """SARIF v2.1.0 OASIS JSON schema (cached on first access)."""
    return _load_schema()


class TestSarifSchemaValidation:
    """Validate SARIF output against the canonical OASIS spec."""

    def test_minimal_sarif_validates(self, sarif_schema: dict) -> None:
        """An empty collection produces valid SARIF."""
        import jsonschema

        exporter = SarifExporter()
        collection = FindingCollection(target_path="/tmp/test")
        collection.scan_started = datetime.now(timezone.utc).isoformat()
        sarif = exporter.export(collection)

        jsonschema.validate(instance=sarif, schema=sarif_schema)

    def test_full_sarif_validates(self, sarif_schema: dict) -> None:
        """A collection with findings, provenance, and taxonomies validates."""
        import jsonschema

        exporter = SarifExporter()
        collection = _make_collection(n_findings=3)
        provenance = _make_provenance()
        sarif = exporter.export(collection, provenance=provenance, source_root="/evidence/redcap")

        jsonschema.validate(instance=sarif, schema=sarif_schema)

    def test_version_and_schema(self, sarif_schema: dict) -> None:
        """SARIF log has correct version and $schema."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection())

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif


# --- Test: %SRCROOT% uriBaseId ----


class TestSrcRootUriBaseId:
    """Verify %SRCROOT% is properly defined and used."""

    def test_original_uri_base_ids_present(self) -> None:
        """run.originalUriBaseIds must define %SRCROOT%."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(), source_root="/evidence/scan")
        run = sarif["runs"][0]

        assert "%SRCROOT%" in run["originalUriBaseIds"]

    def test_srcroot_uri_from_source_root(self) -> None:
        """When source_root is provided, %SRCROOT% uri reflects it."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(), source_root="/evidence/scan")
        base = sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]

        assert base["uri"].endswith("/")
        assert "evidence/scan" in base["uri"]

    def test_srcroot_empty_without_source_root(self) -> None:
        """Without source_root, %SRCROOT% uri is empty string."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection())
        base = sarif["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]

        assert base["uri"] == ""

    def test_results_use_srcroot(self) -> None:
        """Individual results reference %SRCROOT% via uriBaseId."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(n_findings=1))
        results = sarif["runs"][0]["results"]

        assert len(results) >= 1
        loc = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc["uriBaseId"] == "%SRCROOT%"


# --- Test: MITRE ATT&CK tags in rule properties ----


class TestMitreAttackTags:
    """Verify ATT&CK technique IDs appear as tags for GitHub badges."""

    def test_rules_have_attack_tags(self) -> None:
        """Rules with ATT&CK findings have TXXXX in properties.tags."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(include_attack=True))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        tagged_rules = [r for r in rules if "tags" in r.get("properties", {})]
        assert len(tagged_rules) > 0

        for rule in tagged_rules:
            tags = rule["properties"]["tags"]
            attack_tags = [t for t in tags if t.startswith("T")]
            assert len(attack_tags) > 0, f"Rule {rule['id']} missing ATT&CK tag"

    def test_rules_have_cwe_tags(self) -> None:
        """Rules with CWE findings have CWE-XXX in properties.tags."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(include_cwe=True))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        for rule in rules:
            tags = rule.get("properties", {}).get("tags", [])
            cwe_tags = [t for t in tags if t.startswith("CWE-")]
            if rule["properties"].get("cwe"):
                assert len(cwe_tags) > 0


# --- Test: Dual taxonomy (CWE + ATT&CK) ------------


class TestDualTaxonomy:
    """Verify both CWE and ATT&CK taxonomies are emitted."""

    def test_cwe_taxonomy_present(self) -> None:
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(include_cwe=True))
        taxonomies = sarif["runs"][0].get("taxonomies", [])
        cwe_tax = [t for t in taxonomies if t["name"] == "CWE"]
        assert len(cwe_tax) == 1
        assert len(cwe_tax[0]["taxa"]) > 0

    def test_attack_taxonomy_present(self) -> None:
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(include_attack=True))
        taxonomies = sarif["runs"][0].get("taxonomies", [])
        attack_tax = [t for t in taxonomies if t["name"] == "MITRE ATT&CK"]
        assert len(attack_tax) == 1
        assert len(attack_tax[0]["taxa"]) > 0

    def test_no_cwe_taxonomy_without_cwe(self) -> None:
        """CWE taxonomy is absent when no findings have CWE IDs."""
        exporter = SarifExporter()
        sarif = exporter.export(
            _make_collection(include_cwe=False, include_attack=False)
        )
        taxonomies = sarif["runs"][0].get("taxonomies", [])
        cwe_tax = [t for t in taxonomies if t["name"] == "CWE"]
        assert len(cwe_tax) == 0


# --- Test: Provenance property bag


class TestProvenancePropertyBag:
    """Verify full ProvenanceData is serialized into runs[0].properties."""

    def test_provenance_key_present(self) -> None:
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(), provenance=_make_provenance())
        props = sarif["runs"][0]["properties"]
        assert "redacts:provenance" in props

    def test_provenance_has_input_hashes(self) -> None:
        exporter = SarifExporter()
        prov = _make_provenance()
        sarif = exporter.export(_make_collection(), provenance=prov)
        prov_data = sarif["runs"][0]["properties"]["redacts:provenance"]

        assert "input_hashes" in prov_data
        assert prov_data["input_hashes"]["target"] == prov.input_hashes["target"]

    def test_provenance_has_knowledge_hashes(self) -> None:
        exporter = SarifExporter()
        prov = _make_provenance()
        sarif = exporter.export(_make_collection(), provenance=prov)
        prov_data = sarif["runs"][0]["properties"]["redacts:provenance"]

        assert "knowledge_data_hashes" in prov_data
        assert "security_rules.yaml" in prov_data["knowledge_data_hashes"]

    def test_provenance_has_attack_disclaimer(self) -> None:
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection(), provenance=_make_provenance())
        prov_data = sarif["runs"][0]["properties"]["redacts:provenance"]

        assert "attack_coverage_disclaimer" in prov_data
        assert "ATT&CK" in prov_data["attack_coverage_disclaimer"]

    def test_provenance_has_tool_versions(self) -> None:
        exporter = SarifExporter()
        prov = _make_provenance()
        sarif = exporter.export(_make_collection(), provenance=prov)
        prov_data = sarif["runs"][0]["properties"]["redacts:provenance"]

        assert prov_data["tool_versions"]["semgrep"] == "1.67.0"

    def test_provenance_without_provenance_obj(self) -> None:
        """Without provenance, basic scan metadata is still recorded."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection())
        prov_data = sarif["runs"][0]["properties"]["redacts:provenance"]

        assert "scan_started" in prov_data
        assert "total_findings" in prov_data


# --- Test: Rule structure ---------


class TestRuleHydration:
    """Verify rules have CI/CD-required fields."""

    def test_rules_have_required_fields(self) -> None:
        """Every rule must have shortDescription, fullDescription, level."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        for rule in rules:
            assert "id" in rule
            assert "shortDescription" in rule
            assert "text" in rule["shortDescription"]
            assert "fullDescription" in rule
            assert "text" in rule["fullDescription"]
            assert "defaultConfiguration" in rule
            assert "level" in rule["defaultConfiguration"]

    def test_rule_level_values(self) -> None:
        """SARIF levels must be error, warning, or note."""
        exporter = SarifExporter()
        sarif = exporter.export(_make_collection())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        valid_levels = {"error", "warning", "note", "none"}
        for rule in rules:
            assert rule["defaultConfiguration"]["level"] in valid_levels
