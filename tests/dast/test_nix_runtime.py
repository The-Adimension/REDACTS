from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dynamic.docker_runtime import build_install_payload, derive_redcap_version


def test_derive_redcap_version_from_zip_contents(tmp_path: Path) -> None:
    """Version is detected from the redcap_v<VER> directory inside the ZIP."""
    pkg = tmp_path / "my-custom-package.zip"
    with zipfile.ZipFile(pkg, "w") as zf:
        zf.writestr("redcap/redcap_v15.7.4/Config/init_functions.php", "<?php")
        zf.writestr("redcap/redcap_connect.php", "<?php")
    assert derive_redcap_version(pkg) == "15.7.4"


def test_derive_redcap_version_from_directory_contents(tmp_path: Path) -> None:
    """Version is detected from a redcap_v<VER> subdirectory on disk."""
    nested = tmp_path / "redcap" / "redcap_v16.1.2" / "Config"
    nested.mkdir(parents=True)
    (nested / "init_functions.php").write_text("<?php")
    assert derive_redcap_version(tmp_path) == "16.1.2"


def test_derive_redcap_version_prefers_explicit_value(tmp_path: Path) -> None:
    version = derive_redcap_version(tmp_path, explicit_version="16.1.0")
    assert version == "16.1.0"


def test_derive_redcap_version_raises_without_version_content(tmp_path: Path) -> None:
    """No redcap_v directory inside -> error."""
    (tmp_path / "some-file.txt").write_text("dummy")
    with pytest.raises(ValueError, match="Could not detect REDCap version"):
        derive_redcap_version(tmp_path)


def test_derive_redcap_version_filename_does_not_matter(tmp_path: Path) -> None:
    """The ZIP filename is irrelevant; only internal content matters."""
    pkg = tmp_path / "totally-random-name.zip"
    with zipfile.ZipFile(pkg, "w") as zf:
        zf.writestr("redcap/redcap_v14.0.0/index.php", "<?php")
    assert derive_redcap_version(pkg) == "14.0.0"
    payload = build_install_payload(
        base_url="http://127.0.0.1:8585/redcap",
        admin_user="admin",
        admin_password="password123",
        admin_email="admin@example.invalid",
    )
    assert payload["redcap_base_url"] == "http://127.0.0.1:8585/redcap/"
    assert payload["first_username"] == "admin"
    assert payload["first_password"] == "password123"
    assert payload["site_org_type"] == "REDACTS DAST Sandbox"
