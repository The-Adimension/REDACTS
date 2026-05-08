"""
REDACTS DAST - Shared Helpers
Utility functions shared by the DAST orchestrator and Nix runtime:
  - derive_redcap_version(): detect version from package contents
  - build_install_payload(): POST payload for REDCap install.php
"""

from __future__ import annotations

import logging
import re
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)
_INTERNAL_VERSION_RE = re.compile(
    r"redcap_v(?P<version>\d+(?:\.\d+)+)", re.IGNORECASE
)


def _detect_version_from_zip(zip_path: Path) -> str | None:
    """Open a ZIP and find the ``redcap_v<VERSION>`` directory entry."""
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.namelist():
            m = _INTERNAL_VERSION_RE.search(entry)
            if m:
                return m.group("version")
    return None


def _detect_version_from_directory(dir_path: Path) -> str | None:
    """Walk up to two levels looking for a ``redcap_v<VERSION>`` directory."""
    for child in dir_path.iterdir():
        m = _INTERNAL_VERSION_RE.match(child.name)
        if m:
            return m.group("version")
        if child.is_dir():
            for grandchild in child.iterdir():
                m = _INTERNAL_VERSION_RE.match(grandchild.name)
                if m:
                    return m.group("version")
    return None


def derive_redcap_version(source_path: str | Path, explicit_version: str = "") -> str:
    """Resolve a REDCap version by inspecting the package contents.

    Priority:
        1. *explicit_version* when supplied (trusted as-is).
        2. Internal ``redcap_v<VERSION>`` directory inside the ZIP or source
           directory - the canonical version embedded in every REDCap package.

    The filename of the package is deliberately ignored because users may
    rename the archive to anything they like.
    """
    if explicit_version:
        cleaned = explicit_version.strip()
        m = _INTERNAL_VERSION_RE.search(cleaned)
        if m:
            return m.group("version")
        return cleaned

    source = Path(source_path)

    if source.is_file() and source.suffix.lower() == ".zip":
        version = _detect_version_from_zip(source)
    elif source.is_dir():
        version = _detect_version_from_directory(source)
    else:
        version = None

    if version:
        return version

    raise ValueError(
        "Could not detect REDCap version from package contents. "
        "Ensure the package contains a redcap_v<VERSION> directory, "
        "or pass --redcap-version explicitly."
    )


def build_install_payload(
    *,
    base_url: str,
    admin_user: str,
    admin_password: str,
    admin_email: str,
) -> dict[str, str]:
    """Build the POST payload for REDCap's install.php auto-install path."""
    return {
        "system_offline": "0",
        "auth_meth_global": "none",
        "homepage_contact": "REDACTS Administrator",
        "homepage_contact_email": admin_email,
        "project_contact_name": "REDACTS Administrator",
        "project_contact_email": admin_email,
        "institution": "REDACTS",
        "site_org_type": "REDACTS DAST Sandbox",
        "project_language": "English",
        "language_global": "English",
        "api_enabled": "1",
        "default_datetime_format": "M/D/Y_12",
        "default_number_format_decimal": ".",
        "default_number_format_thousands_sep": ",",
        "redcap_base_url": base_url.rstrip("/") + "/",
        "first_username": admin_user,
        "first_password": admin_password,
        "first_email": admin_email,
    }
