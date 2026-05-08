"""Tests for the contract-driven renderers and credential resolver."""

from __future__ import annotations

import yaml
import pytest

from static.core import runtime_context
from static.core.contract import load_and_freeze
from dynamic import compose_render, dockerfile_render, nix_render
from dynamic import credentials as creds


@pytest.fixture(autouse=True)
def _reset_context():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


@pytest.fixture
def contract(valid_case_factory):
    return load_and_freeze(valid_case_factory())


# compose_render


class TestComposeRender:
    def test_dast_compose_is_valid_yaml(self, contract):
        text = compose_render.render_dast_compose(contract)
        doc = yaml.safe_load(text)
        assert "services" in doc
        for svc in ("redcap-dast-db", "redcap-dast-app", "playwright"):
            assert svc in doc["services"]

    def test_dast_compose_pins_images_by_digest(self, contract):
        doc = yaml.safe_load(compose_render.render_dast_compose(contract))
        db_image = doc["services"]["redcap-dast-db"]["image"]
        pw_image = doc["services"]["playwright"]["image"]
        assert "@sha256:" in db_image
        assert "@sha256:" in pw_image
        # Floating tag must NOT appear as the image reference.
        assert ":10.11" not in db_image.split("@")[0]

    def test_dast_compose_credentials_match_contract(self, contract):
        doc = yaml.safe_load(compose_render.render_dast_compose(contract))
        env_db = doc["services"]["redcap-dast-db"]["environment"]
        c = contract.dynamic.credentials
        assert env_db["MARIADB_ROOT_PASSWORD"] == c.db_root_password
        assert env_db["MARIADB_USER"] == c.db_user
        assert env_db["MARIADB_PASSWORD"] == c.db_password
        env_pw = doc["services"]["playwright"]["environment"]
        assert env_pw["REDCAP_ADMIN_USER"] == c.admin_user
        assert env_pw["REDCAP_ADMIN_PASS"] == c.admin_password

    def test_no_default_secrets_in_output(self, contract):
        text = compose_render.render_dast_compose(contract)
        for default_secret in ("D4st_s3cur3", "D4stR00t!2026", "Password123", "dastSalt2026xQz"):
            assert default_secret not in text, f"default secret {default_secret!r} leaked into compose"

    def test_docker_runtime_compose(self, contract):
        text = compose_render.render_docker_runtime_compose(contract)
        doc = yaml.safe_load(text)
        assert "@sha256:" in doc["services"]["db"]["image"]
        assert (
            doc["services"]["db"]["environment"]["MARIADB_PASSWORD"]
            == contract.dynamic.credentials.db_password
        )

    def test_render_all_writes_files(self, contract, tmp_path):
        out = compose_render.render_all(contract, tmp_path / "gen")
        assert "dast" in out and out["dast"].exists()
        assert "docker" in out and out["docker"].exists()


# dockerfile_render


class TestDockerfileRender:
    def test_dast_dockerfile_pins_php(self, contract):
        text = dockerfile_render.render_dast_dockerfile(contract)
        php = contract.dynamic.images.php
        assert f"FROM {php.full_ref}" in text
        # Floating tag must not appear without digest.
        assert "FROM php:8.3-apache\n" not in text

    def test_playwright_dockerfile_pins_image(self, contract):
        text = dockerfile_render.render_playwright_dockerfile(contract)
        pw = contract.dynamic.images.playwright
        assert f"FROM {pw.full_ref}" in text
        assert "FROM mcr.microsoft.com/playwright:v1.51.0-noble\n" not in text

    def test_render_all_writes_files(self, contract, tmp_path):
        out = dockerfile_render.render_all(contract, tmp_path / "gen")
        assert out["dast"].exists()
        assert out["playwright"].exists()


# nix_render


class TestNixRender:
    def test_flake_pins_nixpkgs(self, contract):
        text = nix_render.render_flake(contract)
        rev = contract.nix.nixpkgs_rev
        assert f"github:NixOS/nixpkgs/{rev}" in text
        assert "nixos-unstable" not in text

    def test_flake_uses_contract_attrs(self, contract):
        text = nix_render.render_flake(contract)
        assert f"pkgs.{contract.nix.php_attr}.buildEnv" in text
        assert f"pkgs.{contract.nix.mariadb_attr}" in text
        assert f"pkgs.{contract.nix.chromium_attr}" in text

    def test_flake_rejects_short_rev(self, contract, valid_case_factory, monkeypatch):
        # Mutate via a freshly-loaded contract with a short rev: simulate
        # by patching the dataclass field directly (frozen, so use object.__setattr__).
        bad_rev = "abc1234"
        # build a fake nix block with a bad rev
        from dataclasses import replace
        bad_contract = replace(contract, nix=replace(contract.nix, nixpkgs_rev=bad_rev))
        with pytest.raises(ValueError, match="40-hex commit SHA"):
            nix_render.render_flake(bad_contract)


# credentials resolver


class TestCredentialsResolver:
    def test_no_contract_returns_placeholders(self):
        runtime_context.reset_contract()
        assert creds.admin_user() == "admin"
        assert creds.admin_password() == creds._PLACEHOLDER
        assert creds.db_password() == creds._PLACEHOLDER
        assert creds.compose_env() == {}

    def test_contract_drives_all_credentials(self, contract):
        runtime_context.set_contract(contract)
        c = contract.dynamic.credentials
        assert creds.admin_user() == c.admin_user
        assert creds.admin_password() == c.admin_password
        assert creds.admin_email() == c.admin_email
        assert creds.db_user() == c.db_user
        assert creds.db_password() == c.db_password
        assert creds.db_root_password() == c.db_root_password
        assert creds.salt() == c.salt

    def test_compose_env_payload(self, contract):
        runtime_context.set_contract(contract)
        env = creds.compose_env()
        c = contract.dynamic.credentials
        assert env["DAST_ADMIN_USER"] == c.admin_user
        assert env["DAST_ADMIN_PASS"] == c.admin_password
        assert env["DAST_DB_PASS"] == c.db_password
        assert env["DAST_DB_ROOT_PASS"] == c.db_root_password
        assert env["DAST_SALT"] == c.salt
        assert env["DOCKER_DB_PASS"] == c.db_password

    def test_credentials_ignore_environment(self, contract, monkeypatch):
        runtime_context.set_contract(contract)
        monkeypatch.setenv("DAST_ADMIN_PASS", "should-be-ignored")
        monkeypatch.setenv("DAST_DB_PASS", "should-be-ignored")
        assert creds.admin_password() == contract.dynamic.credentials.admin_password
        assert creds.db_password() == contract.dynamic.credentials.db_password
