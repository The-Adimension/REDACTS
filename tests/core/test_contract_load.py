"""``load_and_freeze`` happy-path and structural assertions."""

from __future__ import annotations

from pathlib import Path

import pytest

from static.core.contract import (
    CaseConfigError,
    FrozenCaseContract,
    SCHEMA_VERSION,
    load_and_freeze,
)


def test_load_valid_case_returns_frozen_contract(valid_case_factory, isolated_search_paths):
    case_path: Path = valid_case_factory()
    contract = load_and_freeze(
        case_path,
        env={},
        dotenv_search_paths=isolated_search_paths,
    )
    assert isinstance(contract, FrozenCaseContract)
    assert contract.schema_version == SCHEMA_VERSION
    assert contract.case.id == "REDACTS-TEST-FIXTURE"
    assert contract.dynamic.runtime == "docker"
    assert contract.dynamic.images.mariadb.full_ref.startswith("docker.io/library/mariadb@sha256:")
    assert contract.threat_base.offline_mode is True  # forensic-strict default


def test_unknown_top_level_key_refused(tmp_path, valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    case_path.write_text(case_path.read_text(encoding="utf-8") + '\nbogus = "x"\n', encoding="utf-8")
    with pytest.raises(CaseConfigError, match="unknown keys"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_missing_required_section_refused(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = text.replace("[threat_base]", "[__missing__]")
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_wrong_schema_version_refused(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8").replace("schema_version = 2", "schema_version = 1")
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError, match="schema_version"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_input_sha_mismatch_refused(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    # Mutate the input file *after* case.toml was rendered with the original hash.
    target = case_path.parent / "inputs" / "target.bin"
    target.write_bytes(b"tampered\n")
    with pytest.raises(CaseConfigError, match="sha256 mismatch"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_path_to_directory_resolves_to_case_toml(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(
        case_path.parent,  # pass the directory
        env={},
        dotenv_search_paths=isolated_search_paths,
    )
    assert contract.source_path == case_path.resolve()


def test_source_sha256_is_recorded(valid_case_factory, isolated_search_paths):
    import hashlib
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    expected = hashlib.sha256(case_path.read_bytes()).hexdigest()
    assert contract.source_sha256 == expected
