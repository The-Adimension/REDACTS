"""Tests for ``threat_base.sources``.

Verifies that all knowledge-source URLs and the NVD API key are routed
through the active :class:`FrozenCaseContract` when one is installed,
and fall back to the documented baseline values otherwise. No
environment variables are read.
"""

from __future__ import annotations

import pytest

from static.core import runtime_context
from static.core.contract import load_and_freeze
from threat_base import sources


@pytest.fixture(autouse=True)
def _reset_context():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


# --- defaults (no contract) -------


class TestDefaults:
    def test_cwe_url_default(self):
        assert sources.cwe_url() == "https://cwe.mitre.org/data/csv/1000.csv.zip"

    def test_nvd_base_url_default(self):
        assert (
            sources.nvd_base_url()
            == "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )

    def test_nvd_api_key_empty_without_contract(self):
        assert sources.nvd_api_key() == ""

    def test_nvd_api_key_ignores_environment(self, monkeypatch):
        monkeypatch.setenv("REDACTS_NVD_API_KEY", "should-not-be-read")
        # Env var must not be consulted.
        assert sources.nvd_api_key() == ""

    def test_attack_stix_url_default(self):
        assert sources.attack_stix_url().startswith(
            "https://github.com/mitre-attack/attack-stix-data/"
        )

    def test_yara_sources_default_count_and_shape(self):
        specs = sources.yara_community_sources()
        assert len(specs) == 3
        names = {s["name"] for s in specs}
        assert names == {
            "php-malware-finder",
            "signature-base-webshells",
            "signature-base-php-webshells",
        }
        for spec in specs:
            assert set(spec.keys()) == {"name", "url", "license"}
            assert spec["url"].startswith("https://")


# --- contract-driven ---------------


class TestContractDriven:
    def test_cwe_url_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        assert sources.cwe_url() == contract.threat_base.sources.cwe.url

    def test_nvd_base_url_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        assert (
            sources.nvd_base_url()
            == contract.threat_base.sources.nvd.base_url
        )

    def test_nvd_api_key_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        assert (
            sources.nvd_api_key()
            == contract.threat_base.sources.nvd.api_key
        )

    def test_attack_stix_url_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        assert (
            sources.attack_stix_url()
            == contract.threat_base.sources.attack_stix.url
        )

    def test_yara_sources_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        runtime_context.set_contract(contract)
        specs = sources.yara_community_sources()
        contract_urls = [s.url for s in contract.threat_base.sources.yara_rules]
        assert [s["url"] for s in specs] == contract_urls
        for spec in specs:
            assert spec["license"] == "contract"
            assert spec["name"]  # non-empty derived basename

    def test_name_derivation(self):
        assert (
            sources._name_from_url(
                "https://example.invalid/dir/expl_php.yar"
            )
            == "expl_php"
        )
        assert (
            sources._name_from_url("https://example.invalid/x.yara")
            == "x"
        )
