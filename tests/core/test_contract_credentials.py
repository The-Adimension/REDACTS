"""Credential strength + refusal of empties."""

from __future__ import annotations

import pytest

from static.core.contract import CaseConfigError, load_and_freeze


def _replace(text: str, old: str, new: str) -> str:
    assert old in text, f"fixture template lost the line: {old!r}"
    return text.replace(old, new, 1)


def test_blank_admin_password_refused(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = _replace(
        text,
        'admin_password = "REDACTS-Strong!Pass-2026-x"',
        'admin_password = ""',
    )
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError, match="admin_password"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_weak_password_warns_by_default(valid_case_factory, isolated_search_paths, caplog):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = _replace(
        text,
        'admin_password = "REDACTS-Strong!Pass-2026-x"',
        'admin_password = "weakpass"',  # length < 16, only one class
    )
    case_path.write_text(text, encoding="utf-8")
    import logging
    with caplog.at_level(logging.WARNING):
        contract = load_and_freeze(
            case_path, env={}, dotenv_search_paths=isolated_search_paths
        )
    assert contract.dynamic.credentials.admin_password == "weakpass"
    assert any("weak-credentials" in rec.message for rec in caplog.records)


def test_weak_password_fails_under_strict_policy(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = _replace(
        text,
        'admin_password = "REDACTS-Strong!Pass-2026-x"',
        'admin_password = "weakpass"',
    )
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError, match="weak-credentials"):
        load_and_freeze(
            case_path, env={}, dotenv_search_paths=isolated_search_paths,
            weak_credentials_policy="fail",
        )


def test_insecure_credentials_flag_downgrades_strict_policy(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = _replace(
        text,
        'admin_password = "REDACTS-Strong!Pass-2026-x"',
        'admin_password = "weakpass"',
    )
    case_path.write_text(text, encoding="utf-8")
    contract = load_and_freeze(
        case_path,
        env={},
        dotenv_search_paths=isolated_search_paths,
        weak_credentials_policy="fail",
        allow_insecure_credentials=True,
    )
    assert contract.dynamic.credentials.admin_password == "weakpass"
