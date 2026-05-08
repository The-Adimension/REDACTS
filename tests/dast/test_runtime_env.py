"""Unit tests for the in-container runtime-env boundary."""
from __future__ import annotations

import pytest

from dynamic.helpers import _runtime_env as _re


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "REDCAP_VERSION",
        "REDCAP_ADMIN_USER",
        "REDCAP_ADMIN_PASS",
        "REDCAP_BASE_URL",
        "REDACTS_DAST_INTERNAL_HOSTS",
    ):
        monkeypatch.delenv(var, raising=False)


def test_snapshot_reads_each_documented_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REDCAP_VERSION", "16.1.2")
    monkeypatch.setenv("REDCAP_ADMIN_USER", "casey")
    monkeypatch.setenv("REDCAP_ADMIN_PASS", "s3cret!")
    monkeypatch.setenv("REDCAP_BASE_URL", "http://localhost:8585/")
    monkeypatch.setenv("REDACTS_DAST_INTERNAL_HOSTS", "localhost,redcap")

    snap = _re.snapshot()

    assert snap.redcap_version == "16.1.2"
    assert snap.admin_user == "casey"
    assert snap.admin_password == "s3cret!"
    assert snap.base_url == "http://localhost:8585/"
    assert snap.internal_hosts == ("localhost", "redcap")


def test_internal_hosts_strips_whitespace_and_drops_empties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REDACTS_DAST_INTERNAL_HOSTS", " a , ,b , , c ")
    assert _re.snapshot().internal_hosts == ("a", "b", "c")


def test_defaults_when_unset() -> None:
    snap = _re.snapshot()
    assert snap.redcap_version == ""
    assert snap.admin_user == "admin"
    assert snap.admin_password == ""
    assert snap.base_url == ""
    assert snap.internal_hosts == ()


def test_runtime_env_is_frozen_dataclass() -> None:
    snap = _re.snapshot()
    with pytest.raises((AttributeError, TypeError)):
        snap.redcap_version = "tampered"  # type: ignore[misc]
