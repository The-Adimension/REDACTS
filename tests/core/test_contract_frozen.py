"""``FrozenCaseContract`` is genuinely immutable."""

from __future__ import annotations

import dataclasses

import pytest

from static.core.contract import load_and_freeze


def test_top_level_is_frozen(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    with pytest.raises(dataclasses.FrozenInstanceError):
        contract.schema_version = 99  # type: ignore[misc]


def test_nested_dataclasses_are_frozen(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    with pytest.raises(dataclasses.FrozenInstanceError):
        contract.dynamic.credentials.admin_password = "leaked"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        contract.dynamic.images.mariadb.digest = "sha256:" + ("0" * 64)  # type: ignore[misc]


def test_collections_are_tuples(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    assert isinstance(contract.static.scanners, tuple)
    assert isinstance(contract.dynamic.network.internal_hosts, tuple)
    assert isinstance(contract.security.ssrf_allowlist, tuple)
