"""Resolver for DAST credentials sourced from the contract.

The active :class:`FrozenCaseContract` is the only authority for DAST
credentials. Environment variables are NOT read for any of these
secrets. When no contract is installed, each resolver returns a
clearly-marked placeholder and emits a warning so the orchestrator
fails fast in production paths but can still execute non-secret code
paths during tests.
"""

from __future__ import annotations

import logging
from typing import NamedTuple

from static.core import runtime_context

logger = logging.getLogger(__name__)


class _Creds(NamedTuple):
    admin_user: str
    admin_password: str
    admin_email: str
    db_user: str
    db_password: str
    db_root_password: str
    salt: str


# Sentinel placeholder used only when no contract is installed.
# Strong enough to fail loudly in any tool that validates input, but
# never used as an actual secret in production paths.
_PLACEHOLDER = "REDACTS-NO-CONTRACT"


def _from_contract() -> _Creds | None:
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return None
    c = contract.dynamic.credentials
    return _Creds(
        admin_user=c.admin_user,
        admin_password=c.admin_password,
        admin_email=c.admin_email,
        db_user=c.db_user,
        db_password=c.db_password,
        db_root_password=c.db_root_password,
        salt=c.salt,
    )


def _no_contract_warning(field: str) -> None:
    logger.warning(
        "DAST credential %r requested but no FrozenCaseContract is "
        "installed; using no-contract placeholder. Configure "
        "[dynamic.credentials] in case.toml (schema_version = 2).",
        field,
    )


def admin_user() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.admin_user
    _no_contract_warning("admin_user")
    return "admin"


def admin_password() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.admin_password
    _no_contract_warning("admin_password")
    return _PLACEHOLDER


def admin_email() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.admin_email
    _no_contract_warning("admin_email")
    return "admin@example.invalid"


def db_user() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.db_user
    _no_contract_warning("db_user")
    return "redcap"


def db_password() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.db_password
    _no_contract_warning("db_password")
    return _PLACEHOLDER


def db_root_password() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.db_root_password
    _no_contract_warning("db_root_password")
    return _PLACEHOLDER


def salt() -> str:
    creds = _from_contract()
    if creds is not None:
        return creds.salt
    _no_contract_warning("salt")
    return _PLACEHOLDER


def compose_env() -> dict[str, str]:
    """Return the ``${VAR}`` injections required by the static compose files.

    The static compose YAML now treats every credential as a *required*
    variable (``${X:?error}``). This helper builds the matching env
    dictionary from the contract so the orchestrator can hand it to
    ``subprocess.run(..., env=...)`` without leaking secrets via the
    parent environment.
    """
    creds = _from_contract()
    if creds is None:
        # No-contract fallback: orchestrator will still work if the user
        # has set the variables externally; we deliberately do not
        # supply weak defaults here.
        return {}
    return {
        "DAST_ADMIN_USER": creds.admin_user,
        "DAST_ADMIN_PASS": creds.admin_password,
        "DAST_ADMIN_EMAIL": creds.admin_email,
        "DAST_DB_USER": creds.db_user,
        "DAST_DB_PASS": creds.db_password,
        "DAST_DB_ROOT_PASS": creds.db_root_password,
        "DAST_SALT": creds.salt,
        "DOCKER_DB_USER": creds.db_user,
        "DOCKER_DB_PASS": creds.db_password,
        "DOCKER_DB_ROOT_PASS": creds.db_root_password,
        "DOCKER_SALT": creds.salt,
    }
