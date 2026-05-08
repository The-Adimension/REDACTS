"""Contract-driven resolution of external knowledge-source URLs.

When a :class:`~static.core.contract.FrozenCaseContract` is installed via
:mod:`static.core.runtime_context`, the URLs and the NVD API key are
sourced from ``contract.threat_base.sources``. When no contract is
installed (ad-hoc CLI invocations or unit tests), the documented
baseline values below are used so the codebase remains operable.

No environment variables are read here; that is by design.
"""

from __future__ import annotations

from typing import TypedDict
from urllib.parse import urlparse

from static.core import runtime_context

__all__ = [
    "YaraSourceSpec",
    "cwe_url",
    "nvd_base_url",
    "nvd_api_key",
    "attack_stix_url",
    "yara_community_sources",
]


# --- Baseline (no-contract) defaults ----------------
# Documented sources of truth for each knowledge feed. Used as
# fallbacks when no contract is loaded.

_DEFAULT_CWE_URL: str = "https://cwe.mitre.org/data/csv/1000.csv.zip"
_DEFAULT_NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_ATTACK_STIX_URL: str = (
    "https://github.com/mitre-attack/attack-stix-data/"
    "releases/download/v18.1/enterprise-attack.json"
)


class YaraSourceSpec(TypedDict):
    """Shape of a single YARA community-rule download spec."""

    name: str
    url: str
    license: str


# Names + licenses are intentionally kept here (not in the contract)
# because they describe the rule file rather than configure it. Only
# the *URL* is contract-overridable.
_DEFAULT_YARA_SOURCES: tuple[YaraSourceSpec, ...] = (
    {
        "name": "php-malware-finder",
        "url": (
            "https://raw.githubusercontent.com/"
            "jvoisin/php-malware-finder/master/data/php.yar"
        ),
        "license": "LGPL-3.0",
    },
    {
        "name": "signature-base-webshells",
        "url": (
            "https://raw.githubusercontent.com/"
            "Neo23x0/signature-base/master/yara/gen_webshells.yar"
        ),
        "license": "DRL-1.1",
    },
    {
        "name": "signature-base-php-webshells",
        "url": (
            "https://raw.githubusercontent.com/"
            "Neo23x0/signature-base/master/yara/thor-webshells.yar"
        ),
        "license": "DRL-1.1",
    },
)


# --- Resolvers ---


def cwe_url() -> str:
    """Return the CWE CSV ZIP URL - contract value when available."""
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return _DEFAULT_CWE_URL
    return contract.threat_base.sources.cwe.url


def nvd_base_url() -> str:
    """Return the NVD REST base URL - contract value when available."""
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return _DEFAULT_NVD_BASE_URL
    return contract.threat_base.sources.nvd.base_url


def nvd_api_key() -> str:
    """Return the NVD API key.

    The API key comes exclusively from
    ``contract.threat_base.sources.nvd.api_key``. There is no
    environment-variable fallback. When no contract is installed, an
    empty string is returned (NVD enrichment is then disabled).
    """
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return ""
    return contract.threat_base.sources.nvd.api_key


def attack_stix_url() -> str:
    """Return the ATT&CK Enterprise STIX bundle URL."""
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return _DEFAULT_ATTACK_STIX_URL
    return contract.threat_base.sources.attack_stix.url


def yara_community_sources() -> tuple[YaraSourceSpec, ...]:
    """Return the YARA community rule download specs.

    When a contract is installed, the URL list is taken from
    ``contract.threat_base.sources.yara_rules``; the rule-file names are
    derived from the URL basename (``.../foo.yar`` -> ``foo``) so the
    on-disk filenames remain ``<name>.yar`` as before. License is
    reported as ``"contract"`` (the contract pins the URL/digest; the
    legal terms live with the upstream project).

    Without a contract, the documented baseline list is returned.
    """
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return _DEFAULT_YARA_SOURCES

    specs: list[YaraSourceSpec] = []
    for src in contract.threat_base.sources.yara_rules:
        name = _name_from_url(src.url)
        specs.append({"name": name, "url": src.url, "license": "contract"})
    return tuple(specs)


def _name_from_url(url: str) -> str:
    """Derive a stable rule-file basename from a YARA URL."""
    path = urlparse(url).path
    leaf = path.rsplit("/", 1)[-1] or "rules.yar"
    for ext in (".yar", ".yara"):
        if leaf.endswith(ext):
            return leaf[: -len(ext)]
    return leaf
