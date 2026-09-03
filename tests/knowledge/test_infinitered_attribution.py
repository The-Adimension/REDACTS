"""The attribution boundary: GTIG evidence vs REDCap Consortium observations.

REDACTS carries two evidence streams. Only the first is family attribution:

* **GTIG-published INFINITERED / UNC6508 markers** - the seven SHA-256 digests,
  the ``G_Backdoor_INFINITERED_1`` YARA rule, and the literal implant strings.
  A hit here is confirmation.
* **REDCap Community Forum / Vanderbilt observations** - REDCap-specific
  persistence and hygiene patterns (SQLite ``redcap.db``, ``eval(gzinflate(...))``,
  ``.user.ini auto_prepend_file``). Actionable and unchanged in severity, but a
  lead rather than proof.

These tests pin that boundary. Previously every one of the second group was
labelled ``conclusiveness: conclusive`` under ``campaign: INFINITERED``, so a
stock tree containing a ``.git`` directory could be reported as a conclusive
INFINITERED compromise.
"""

from __future__ import annotations

import hashlib
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import pytest

from threat_base.data_loader import load_security_rules
from threat_base.ioc_database import (
    Conclusiveness,
    IoC,
    IoCCategory,
    IoCDatabase,
)

GTIG_HOST = "cloud.google.com"


def _cites_gtig(text: str) -> bool:
    """True if *text* carries a URL whose host is exactly the GTIG blog host.

    Matched on the parsed hostname, not with ``in``: a substring test would
    also accept ``https://evil.example/cloud.google.com`` (CodeQL
    py/incomplete-url-substring-sanitization).
    """
    return any(
        urlparse(token).hostname == GTIG_HOST
        for token in re.findall(r"https?://\S+", text)
    )


# Literals copied verbatim from GTIG YARA rule G_Backdoor_INFINITERED_1.
GTIG_LITERALS = {
    "SEC100": "$magic_flag = 'ej671a16i7fd8202nu6ltfg5p6x7u';",
    "SEC101": "ZWo2NzFhMTZpN2ZkODIwMm51Nmx0Zmc1cDZ4N3U=",
    "SEC102": "b49e334d-9c01-463e-9bc5-00a6920fb66e",
    "SEC103": "YjQ5ZTMzNGQtOWMwMS00NjNlLTliYzUtMDBhNjkyMGZiNjZl",
    "SEC104": "$req_data = substr($cookieValue, strlen($magic_flag));",
    "SEC105": (
        "INSERT INTO redcap_sessions (session_id, session_data, "
        "session_expiration) VALUES ('$session_id', '$str', "
        "FROM_UNIXTIME($expiration_timestamp))"
    ),
    "SEC106": "encrypt($currentUTC . '[::]' . $_POST['username'] . '[::]' . $_POST['password']);",
    "SEC107": "$session_id = 'xc32038474a'.substr(bin2hex($currentUTC), -20);",
    "SEC108": "$file_content_upgrade = $zip->getFromName($file_upgrade);",
    "SEC109": "str_replace($search_content, $hooks_decode, $file_content_hooks);",
    "SEC110": "getcwd(), php_uname(), phpversion(), $_SERVER['SERVER_SOFTWARE']",
}


def _ioc(ioc_id: str) -> IoC:
    """Look up an IoC by id via the public ``all_iocs`` surface."""
    return next(i for i in IoCDatabase().all_iocs if i.id == ioc_id)


@pytest.fixture(scope="module")
def rules_by_id() -> dict:
    return {r["id"]: r for r in load_security_rules()}


def _search(rule: dict, text: str):
    flags = re.IGNORECASE if (rule.get("pattern_flags") or "") == "IGNORECASE" else 0
    return re.search(rule["pattern"], text, flags)


# --- GTIG literals must match, exactly --


@pytest.mark.parametrize("rule_id,literal", sorted(GTIG_LITERALS.items()))
def test_gtig_rule_matches_published_literal(rule_id, literal, rules_by_id) -> None:
    assert _search(rules_by_id[rule_id], literal), (
        f"{rule_id} no longer matches its GTIG-published literal"
    )


@pytest.mark.parametrize("rule_id", sorted(GTIG_LITERALS))
def test_gtig_rule_is_attributed_and_cited(rule_id, rules_by_id) -> None:
    rule = rules_by_id[rule_id]
    assert rule["category"] == "infinitered"
    assert rule["severity"] == "CRITICAL"
    assert _cites_gtig(" ".join(rule.get("references", []) + [rule.get("recommendation", "")]))


def test_gtig_rules_do_not_fire_on_benign_redcap_code(rules_by_id) -> None:
    """Legitimate REDCap code must never be attributed to the family."""
    benign = (
        "<?php\n"
        "$token = $_GET['api_token'];   // REDCAP_TOKEN api usage\n"
        "$cwd = getcwd();\n"
        "$rows = $conn->query('SELECT * FROM redcap_sessions');\n"
    )
    for rule_id in GTIG_LITERALS:
        assert not _search(rules_by_id[rule_id], benign), (
            f"{rule_id} false-positived on benign REDCap code"
        )


# --- the SEC060 correction --


def test_sec060_no_longer_claims_infinitered(rules_by_id) -> None:
    """A bare REDCAP-TOKEN string is not family evidence.

    GTIG's YARA pairs the cookie with the magic flag ($s1); the cookie name
    alone collides with legitimate REDCap API-token language.
    """
    rule = rules_by_id["SEC060"]
    assert rule["category"] == "redcap_forum"
    assert "INFINITERED" not in rule["message"]
    assert _search(rule, "$c = $_COOKIE['REDCAP-TOKEN'];"), "pattern was gutted"


def test_paired_cookie_form_is_still_conclusive(rules_by_id) -> None:
    assert rules_by_id["SEC104"]["category"] == "infinitered"


@pytest.mark.parametrize("rule_id", ["SEC061", "SEC062", "SEC066"])
def test_forum_rules_keep_pattern_but_drop_attribution(rule_id, rules_by_id) -> None:
    """Consortium detections are retained - only the family claim is removed."""
    rule = rules_by_id[rule_id]
    assert rule["category"] == "redcap_forum"
    assert "INFINITERED" not in rule["message"]
    assert "INFINITERED" not in rule.get("recommendation", "")
    assert rule["pattern"], "pattern must be kept"


def test_forum_rule_severities_unchanged(rules_by_id) -> None:
    """Relabelling must not silently downgrade Consortium severities."""
    assert rules_by_id["SEC061"]["severity"] == "CRITICAL"
    assert rules_by_id["SEC062"]["severity"] == "HIGH"
    assert rules_by_id["SEC066"]["severity"] == "HIGH"


# --- published hashes --


def test_gtig_hash_ioc_is_conclusive_and_cited() -> None:
    ioc = _ioc("IOC-INF-005")
    assert ioc.category is IoCCategory.INFINITERED
    assert ioc.conclusiveness is Conclusiveness.CONCLUSIVE
    assert len(ioc.known_bad_sha256) == 7
    assert all(len(h) == 64 for h in ioc.known_bad_sha256)
    assert any(_cites_gtig(r) for r in ioc.references)


def test_hash_match_flags_only_exact_digests() -> None:
    """Exact-digest matching, proven without a live sample."""
    from static.analyze.steps.ioc_scan import IocScanStep

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "help.php"
        target.write_bytes(b"<?php // stand-in for a known-bad implant\n")
        (root / "index.php").write_bytes(b"<?php echo 1;\n")

        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        ioc = IoC(
            id="IOC-TEST",
            name="test",
            description="d",
            category=IoCCategory.INFINITERED,
            conclusiveness=Conclusiveness.CONCLUSIVE,
            severity="CRITICAL",
            detection_method="hash_match",
            known_bad_sha256=[digest],
        )
        hits = IocScanStep(IoCDatabase())._ioc_hash_match(ioc, root)

    assert [h.file_path for h in hits] == ["help.php"]
    assert hits[0].conclusiveness == "conclusive"
    assert hits[0].evidence["sha256"] == digest


# --- forum IoCs must not be counted as compromise proof --


@pytest.mark.parametrize(
    "ioc_id", ["IOC-INF-001", "IOC-INF-002", "IOC-INF-003", "IOC-INF-004", "IOC-CT-002"]
)
def test_forum_iocs_are_not_conclusive(ioc_id) -> None:
    """Regression: these fed the 'Conclusive Compromise Indicators' count."""
    ioc = _ioc(ioc_id)
    assert ioc.category is IoCCategory.REDCAP_FORUM
    assert ioc.conclusiveness is not Conclusiveness.CONCLUSIVE
    assert ioc.references, f"{ioc_id} must carry its Consortium citation"


def test_only_gtig_iocs_claim_the_family() -> None:
    for ioc in IoCDatabase().all_iocs:
        if ioc.category is IoCCategory.INFINITERED:
            assert ioc.known_bad_sha256, (
                f"{ioc.id} claims INFINITERED without a published digest"
            )


# --- the pinned YARA rule --


def test_inert_fixture_trips_the_gtig_rules() -> None:
    """The inert fixture must be detected by the GTIG string rules.

    ``tests/data/php/infinitered/gtig_markers.php`` holds only published string
    literals - no working handler, no key, no payload. It lives outside the
    tree-sitter positive corpus because it contains no AST-detectable construct;
    it exists to prove the regex layer still matches real published markers.
    """
    fixture = (
        Path(__file__).resolve().parents[1]
        / "data" / "php" / "infinitered" / "gtig_markers.php"
    )
    assert fixture.is_file(), "inert GTIG fixture is missing"
    content = fixture.read_text(encoding="utf-8")

    by_id = {r["id"]: r for r in load_security_rules()}
    fired = {rid for rid in GTIG_LITERALS if _search(by_id[rid], content)}
    # Every marker family should be represented: flag, GUID, cookie gate,
    # harvester SQL, encryption, session prefix, zip-inject, beacon.
    assert {"SEC100", "SEC102", "SEC104", "SEC105", "SEC106",
            "SEC107", "SEC108", "SEC109", "SEC110"} <= fired, sorted(fired)


def test_gtig_yara_rule_is_pinned_on_disk() -> None:
    """Vendor rule ships with REDACTS - never fetched at scan time."""
    import threat_base

    rule = (
        Path(threat_base.__file__).resolve().parent
        / "data" / "yara" / "G_Backdoor_INFINITERED_1.yar"
    )
    assert rule.is_file()
    body = rule.read_text(encoding="utf-8")
    assert "rule G_Backdoor_INFINITERED_1" in body
    assert _cites_gtig(body)
    assert "$magic_flag" in body and "$marker" in body
