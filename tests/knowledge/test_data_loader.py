"""
Tests for REDACTS Knowledge Data Loader - knowledge/data_loader.py

Coverage:
    - All 7 YAML loaders (real shipped files)
    - Integrity verification (checksum match / mismatch / missing)
    - Checksum regeneration
    - Regex compilation in loaded data
    - Schema shape assertions for every dataset
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from threat_base.data_loader import (
    IntegrityError,
    _verify_file,
    load_attack_vectors,
    load_infinitered_campaign,
    load_ioc_indicators,
    load_mitre_mapping,
    load_redcap_baseline,
    load_security_rules,
    load_sensitive_data_patterns,
    regenerate_checksums,
)


# --- Real shipped YAML - smoke tests ---------------


class TestLoadSecurityRules:
    """Verify security_rules.yaml loads and compiles."""

    def test_returns_list(self) -> None:
        rules = load_security_rules()
        assert isinstance(rules, list)
        assert len(rules) >= 50  # currently 57

    def test_rule_has_required_keys(self) -> None:
        rules = load_security_rules()
        required = {"id", "severity", "category", "pattern", "message"}
        for rule in rules:
            assert required <= set(rule.keys()), f"Rule {rule.get('id')} missing keys"

    def test_patterns_compiled(self) -> None:
        rules = load_security_rules()
        compiled_count = sum(1 for r in rules if r.get("compiled_pattern") is not None)
        assert compiled_count == len(rules)  # every rule should have a pattern

    def test_compiled_pattern_is_regex(self) -> None:
        rules = load_security_rules()
        for rule in rules:
            cp = rule.get("compiled_pattern")
            if cp is not None:
                assert isinstance(cp, re.Pattern), f"Rule {rule['id']} pattern not compiled"


class TestLoadIocIndicators:
    """Verify ioc_indicators.yaml loads and compiles."""

    def test_returns_dict(self) -> None:
        data = load_ioc_indicators()
        assert isinstance(data, dict)

    def test_has_required_sections(self) -> None:
        data = load_ioc_indicators()
        for key in ("iocs", "webshell_signatures", "htaccess_dangerous_directives"):
            assert key in data, f"Missing section: {key}"

    def test_ioc_count(self) -> None:
        data = load_ioc_indicators()
        # Loader returns key "indicators" mapped from "iocs" or directly
        iocs = data.get("iocs") or data.get("indicators", [])
        assert len(iocs) >= 15  # currently 17

    def test_webshell_signatures_compiled(self) -> None:
        data = load_ioc_indicators()
        for sig in data.get("webshell_signatures", []):
            if sig.get("pattern"):
                assert "compiled_pattern" in sig


class TestLoadSensitiveDataPatterns:
    """Verify sensitive_data_patterns.yaml loads and compiles."""

    def test_returns_dict(self) -> None:
        data = load_sensitive_data_patterns()
        assert isinstance(data, dict)

    def test_pattern_count(self) -> None:
        data = load_sensitive_data_patterns()
        assert len(data.get("patterns", [])) >= 20  # currently 25

    def test_quick_gate_compiled(self) -> None:
        data = load_sensitive_data_patterns()
        assert isinstance(data.get("compiled_quick_gate"), re.Pattern)

    def test_individual_patterns_compiled(self) -> None:
        data = load_sensitive_data_patterns()
        for pat in data.get("patterns", []):
            assert isinstance(pat.get("compiled_regex"), re.Pattern), (
                f"Pattern {pat.get('id', '?')} not compiled"
            )


class TestLoadMitreMapping:
    """Verify mitre_mapping.yaml loads."""

    def test_returns_dict(self) -> None:
        data = load_mitre_mapping()
        assert isinstance(data, dict)

    def test_has_required_maps(self) -> None:
        data = load_mitre_mapping()
        assert len(data.get("mitre_attack_map", {})) >= 40  # currently 52
        assert len(data.get("cvss_map", {})) >= 20  # currently 27

    def test_attack_map_values_are_pairs(self) -> None:
        data = load_mitre_mapping()
        for key, entry in data["mitre_attack_map"].items():
            assert isinstance(entry, list) and len(entry) == 2, (
                f"Entry {key} should be [technique_id, name] pair"
            )


class TestLoadRedcapBaseline:
    """Verify redcap_baseline.yaml loads."""

    def test_returns_dict(self) -> None:
        data = load_redcap_baseline()
        assert isinstance(data, dict)

    def test_known_directories_populated(self) -> None:
        data = load_redcap_baseline()
        assert len(data.get("known_directories", [])) >= 30  # currently 40

    def test_hook_function_names_populated(self) -> None:
        data = load_redcap_baseline()
        assert len(data.get("hook_function_names", [])) >= 15  # currently 20

    def test_database_php_patterns_compiled(self) -> None:
        data = load_redcap_baseline()
        db_val = data.get("database_php_validation", {})
        for fp in db_val.get("forbidden_patterns", []):
            if fp.get("pattern"):
                assert isinstance(fp.get("compiled_pattern"), re.Pattern)


class TestLoadAttackVectors:
    """Verify attack_vectors.yaml loads."""

    def test_returns_list(self) -> None:
        vectors = load_attack_vectors()
        assert isinstance(vectors, list)
        assert len(vectors) >= 30  # currently 34

    def test_vector_has_required_keys(self) -> None:
        vectors = load_attack_vectors()
        required = {"id", "name", "description", "category", "severity", "conclusiveness"}
        for v in vectors:
            assert required <= set(v.keys()), f"Vector {v.get('id')} missing keys"

    def test_severity_values_valid(self) -> None:
        valid = {"critical", "high", "medium", "low", "informational"}
        for v in load_attack_vectors():
            assert v["severity"].lower() in valid, (
                f"Vector {v['id']} has invalid severity: {v['severity']}"
            )


class TestLoadInfiniteredCampaign:
    """Verify infinitered_campaign.yaml loads."""

    def test_returns_dict(self) -> None:
        data = load_infinitered_campaign()
        assert isinstance(data, dict)

    def test_has_campaign_metadata(self) -> None:
        data = load_infinitered_campaign()
        campaign = data.get("campaign", {})
        assert "name" in campaign
        assert "description" in campaign

    def test_indicators_populated(self) -> None:
        data = load_infinitered_campaign()
        assert len(data.get("indicators", [])) >= 15  # currently 17


# --- Integrity verification -------


class TestIntegrity:
    """Tests for _verify_file and checksums.json."""

    def test_shipped_yaml_files_pass_integrity(self) -> None:
        """Every shipped YAML file must match checksums.json."""
        data_dir = Path(__file__).resolve().parent.parent.parent / "threat_base" / "data"
        checksums_path = data_dir / "checksums.json"
        assert checksums_path.is_file(), "checksums.json missing"

        manifest = json.loads(checksums_path.read_text(encoding="utf-8"))
        files = manifest.get("files", {})
        assert len(files) >= 7, f"Expected 7+ entries, got {len(files)}"

        for rel_path, expected in files.items():
            abs_path = data_dir / rel_path
            assert abs_path.is_file(), f"Manifest references missing file: {rel_path}"
            assert expected.startswith("sha256:")
            actual = hashlib.sha256(abs_path.read_bytes()).hexdigest()
            assert actual == expected[7:], (
                f"Integrity mismatch for {rel_path}: "
                f"expected {expected[7:][:16]}..., got {actual[:16]}..."
            )

    def test_regenerate_checksums_round_trips(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """regenerate_checksums() should produce consistent output."""
        import threat_base.data_loader as dl

        # Save originals
        original_checksums_path = dl._CHECKSUMS_PATH
        original_yaml_dir = dl._YAML_DIR
        original_data_dir = dl._DATA_DIR

        # Create a temp layout
        yaml_dir = tmp_path / "yaml"
        yaml_dir.mkdir()
        (yaml_dir / "test.yaml").write_text("key: value\n", encoding="utf-8")

        monkeypatch.setattr(dl, "_DATA_DIR", tmp_path)
        monkeypatch.setattr(dl, "_YAML_DIR", yaml_dir)
        monkeypatch.setattr(dl, "_CHECKSUMS_PATH", tmp_path / "checksums.json")

        result_path = regenerate_checksums()
        assert result_path.is_file()

        manifest = json.loads(result_path.read_text(encoding="utf-8"))
        assert "yaml/test.yaml" in manifest["files"]
        # Verify the checksum matches the actual file on disk
        actual_hash = hashlib.sha256((yaml_dir / "test.yaml").read_bytes()).hexdigest()
        assert manifest["files"]["yaml/test.yaml"] == f"sha256:{actual_hash}"

    def test_verify_file_detects_tampering(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_verify_file should raise IntegrityError on hash mismatch."""
        import threat_base.data_loader as dl

        data_dir = tmp_path / "data"
        yaml_dir = data_dir / "yaml"
        yaml_dir.mkdir(parents=True)

        test_file = yaml_dir / "tampered.yaml"
        test_file.write_text("original content\n", encoding="utf-8")

        # Build checksum from the actual file bytes on disk
        original_hash = hashlib.sha256(test_file.read_bytes()).hexdigest()

        monkeypatch.setattr(dl, "_DATA_DIR", data_dir)
        monkeypatch.setattr(dl, "_CHECKSUMS", {"yaml/tampered.yaml": f"sha256:{original_hash}"})

        # Should pass with original content
        _verify_file(test_file)  # no error

        # Tamper with the file
        test_file.write_text("TAMPERED content\n", encoding="utf-8")

        with pytest.raises(IntegrityError, match="INTEGRITY FAILURE"):
            _verify_file(test_file)


# --- Sources manifest -------------


class TestSourcesManifest:
    """Verify sources.json is complete and well-formed."""

    @pytest.fixture
    def sources(self) -> dict:
        path = Path(__file__).resolve().parent.parent.parent / "threat_base" / "data" / "sources.json"
        assert path.is_file(), "sources.json missing"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_has_all_sources(self, sources: dict) -> None:
        expected = {
            "cwe_database", "attack_enterprise",
            "yara_php_malware_finder", "yara_signature_base_webshells",
            "yara_signature_base_php_webshells", "nvd_api",
            "redacts_attack_vectors", "redacts_ioc_database",
            "redacts_infinitered_campaign", "redacts_sensitive_data_patterns",
            "redacts_mitre_mapping",
        }
        assert expected == set(sources["sources"].keys())

    def test_every_source_has_required_fields(self, sources: dict) -> None:
        required = {"name", "provider", "license", "format"}
        for key, entry in sources["sources"].items():
            assert required <= set(entry.keys()), f"Source {key} missing fields"

    def test_external_sources_have_url(self, sources: dict) -> None:
        external = {
            "cwe_database", "attack_enterprise",
            "yara_php_malware_finder", "yara_signature_base_webshells",
            "yara_signature_base_php_webshells", "nvd_api",
        }
        for key in external:
            entry = sources["sources"][key]
            assert entry.get("url"), f"External source {key} missing URL"

    def test_signature_base_uses_drl(self, sources: dict) -> None:
        for key in ("yara_signature_base_webshells", "yara_signature_base_php_webshells"):
            assert sources["sources"][key]["license"] == "DRL-1.1"
