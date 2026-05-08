"""Refusal when ``.env`` / ``.env.config`` is present."""

from __future__ import annotations

import pytest

from static.core.contract import CaseConfigError, load_and_freeze


def test_dotenv_in_search_path_refused(valid_case_factory, tmp_path):
    case_path = valid_case_factory()
    poison_dir = tmp_path / "poison"
    poison_dir.mkdir()
    (poison_dir / ".env").write_text("REDACTS_OUTPUT_DIR=/tmp\n", encoding="utf-8")
    with pytest.raises(CaseConfigError, match="dotenv-refusal"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=[poison_dir])


def test_dotenv_config_in_search_path_refused(valid_case_factory, tmp_path):
    case_path = valid_case_factory()
    poison_dir = tmp_path / "poison"
    poison_dir.mkdir()
    (poison_dir / ".env.config").write_text("REDACTS_MODE=static\n", encoding="utf-8")
    with pytest.raises(CaseConfigError, match="dotenv-refusal"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=[poison_dir])


def test_dotenv_absent_passes(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    contract = load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
    assert contract is not None
