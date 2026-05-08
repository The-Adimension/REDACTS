"""Environment-pollution refusal."""

from __future__ import annotations

import pytest

from static.core.contract import (
    CaseConfigError,
    FORBIDDEN_ENV_PREFIXES,
    FORBIDDEN_ENV_EXACT,
    load_and_freeze,
)


@pytest.mark.parametrize("offending", [
    "REDACTS_OUTPUT_DIR",
    "REDCAP_VERSION",
    "DAST_ADMIN_PASS",
    "PLAYWRIGHT_CHROMIUM_EXECUTABLE",
    "XDEBUG_MODE",
    "MYSQL_ROOT_PASSWORD",
    "MARIADB_DATABASE",
])
def test_each_forbidden_name_refused(valid_case_factory, isolated_search_paths, offending):
    case_path = valid_case_factory()
    poisoned = {offending: "x"}
    with pytest.raises(CaseConfigError, match="environment-pollution"):
        load_and_freeze(case_path, env=poisoned, dotenv_search_paths=isolated_search_paths)


def test_clean_env_passes(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    # No forbidden names -> loader proceeds.
    contract = load_and_freeze(
        case_path, env={"PATH": "/usr/bin"}, dotenv_search_paths=isolated_search_paths
    )
    assert contract is not None


def test_forbidden_set_is_documented():
    # Smoke: prefixes & exact set are non-empty and well-typed.
    assert "REDACTS_" in FORBIDDEN_ENV_PREFIXES
    assert "DAST_" in FORBIDDEN_ENV_PREFIXES
    assert "MYSQL_ROOT_PASSWORD" in FORBIDDEN_ENV_EXACT
