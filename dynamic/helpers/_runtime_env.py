"""Single env-read boundary for Playwright in-container helpers.

The Playwright runner ships in a separate Docker container that does
**not** have access to the REDACTS ``FrozenCaseContract``. Instead, the
orchestrator injects the test-runtime configuration via a small set of
environment variables when it spawns the container (or when it shells
out to the host's ``npx playwright`` runner). Every read of those
variables is funnelled through this single, allow-listed boundary
module so the rest of ``dynamic/helpers/`` is environment-pure and the
AST linter remains green.

Variables consumed:

================  =========================================================
Variable          Purpose
----------------  ----
REDCAP_VERSION    Major.minor version of REDCap under test (URL routing).
REDCAP_ADMIN_USER Admin username for browser login.
REDCAP_ADMIN_PASS Admin password for browser login.
REDCAP_BASE_URL   Public base URL the harness is hitting.
REDACTS_DAST_INTERNAL_HOSTS  Comma-separated allow-list of internal hosts.
================  =========================================================

All accessors return strings (possibly empty). They never raise on
unset; the helpers themselves decide whether absence is fatal at the
call site.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimeEnv:
    """Snapshot of the in-container test runtime configuration."""

    redcap_version: str
    admin_user: str
    admin_password: str
    base_url: str
    internal_hosts: tuple[str, ...]


def _split_hosts(raw: str) -> tuple[str, ...]:
    return tuple(host.strip() for host in raw.split(",") if host.strip())


def snapshot() -> RuntimeEnv:
    """Read every supported variable in one pass.

    The returned :class:`RuntimeEnv` is immutable; callers should
    capture it once and pass it around instead of re-reading.
    """
    return RuntimeEnv(
        redcap_version=os.environ.get("REDCAP_VERSION", ""),
        admin_user=os.environ.get("REDCAP_ADMIN_USER", "admin"),
        admin_password=os.environ.get("REDCAP_ADMIN_PASS", ""),
        base_url=os.environ.get("REDCAP_BASE_URL", ""),
        internal_hosts=_split_hosts(
            os.environ.get("REDACTS_DAST_INTERNAL_HOSTS", "")
        ),
    )


__all__ = ["RuntimeEnv", "snapshot"]
