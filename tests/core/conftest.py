"""Fixtures for ``tests/core`` - ``FrozenCaseContract`` tests.

The factory builds a complete, valid case directory in a tmp path with:

* dummy target/reference input files,
* a ``case.toml`` rendered with their actual SHA-256 hashes,
* an isolated workspace so dotenv search paths cannot escape the tmp dir.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

import pytest

# Pinned reference digests (64-hex). Real digests where we have them; zeroed
# placeholders (still 64-hex) for images we do not exercise in this fixture.
_VALID_DIGEST_PHP_83 = "sha256:6c8fd4ecc59d5950798f064d19a2e9eb0077fcd39a40819e5daeba9f06661122"
_VALID_DIGEST_PHP_82 = "sha256:188c05cf6090add7910f33fcc7d47259ce442c698cfe9ae2818918ee6e0f8e99"
_VALID_DIGEST_MARIADB_1011 = "sha256:4d54b976cde4c382d92278ef7998a4ddb1393846e97fb4d8efc5c21fe6cb8bb9"
_VALID_DIGEST_PLACEHOLDER = "sha256:" + ("0" * 64)
_VALID_NIXPKGS_REV = "0123456789abcdef0123456789abcdef01234567"

_STRONG_PASSWORD = "REDACTS-Strong!Pass-2026-x"
_STRONG_SALT = "Sa1t-Mix#A1B2C3D4E5F6"


def _render(case_dir: Path, target_sha: str, ref_sha: str) -> str:
    return f"""\
schema_version = 2

[case]
id = "REDACTS-TEST-FIXTURE"
analyst = "Test Analyst"
organization = "REDACTS Test Suite"
date = "2026-05-03"
description = "Contract validation fixture"

[paths]
workspace_root = "{case_dir.as_posix()}"

[inputs.target]
path = "inputs/target.bin"
sha256 = "{target_sha}"
[inputs.reference]
path = "inputs/reference.bin"
sha256 = "{ref_sha}"

[static]
enabled = true
scanners = ["regex", "yara", "trivy"]
formats = ["json", "sarif"]
severity_gate = "high"
max_total_files = 50000
parallel_workers = 4
global_timeout_seconds = 3600

[dynamic]
enabled = true
runtime = "docker"
suites = ["export", "admin", "upgrade"]
port = 8585
suite_timeout = 600
keep_stack = false
stack_only = false

[dynamic.images.mariadb]
registry = "docker.io"
repo = "library/mariadb"
tag = "10.11"
digest = "{_VALID_DIGEST_MARIADB_1011}"

[dynamic.images.php]
registry = "docker.io"
repo = "library/php"
tag = "8.3-apache"
digest = "{_VALID_DIGEST_PHP_83}"

[dynamic.images.playwright]
registry = "mcr.microsoft.com"
repo = "playwright"
tag = "v1.51.0-noble"
digest = "{_VALID_DIGEST_PLACEHOLDER}"

[dynamic.images.sandbox]
registry = "docker.io"
repo = "library/php"
tag = "8.2-cli-alpine"
digest = "{_VALID_DIGEST_PHP_82}"

[dynamic.credentials]
admin_user = "admin"
admin_password = "{_STRONG_PASSWORD}"
admin_email = "admin@example.invalid"
db_root_password = "{_STRONG_PASSWORD}-root"
db_user = "redcap"
db_password = "{_STRONG_PASSWORD}-db"
salt = "{_STRONG_SALT}"

[dynamic.network]
base_url = "http://localhost:8585"
internal_hosts = ["localhost", "127.0.0.1", "::1"]
xdebug_mode = "trace"

[dynamic.playwright]
chromium_executable = ""
chromium_args = []
node_version = "20"

[threat_base]
offline_mode = true
allow_stale = true
ttl_hours = 168

[threat_base.sources.cwe]
url = "https://cwe.mitre.org/data/csv/1000.csv.zip"
sha256 = ""

[threat_base.sources.nvd]
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
api_key = ""

[threat_base.sources.attack_stix]
url = "https://github.com/mitre-attack/attack-stix-data/raw/master/enterprise-attack/enterprise-attack.json"
sha256 = ""

[[threat_base.sources.yara_rules]]
url = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/expl_php.yar"
sha256 = ""

[tools.trivy]
version = "0.58.2"
url_template = "https://github.com/aquasecurity/trivy/releases/download/v{{version}}/trivy_{{version}}_{{os}}-{{arch}}.zip"
sha256_table = {{ "windows-64bit" = "deadbeef", "linux-64bit" = "deadbeef", "darwin-64bit" = "deadbeef" }}

[tools.yara]
version = "4.5.2"
url_template = "https://github.com/VirusTotal/yara/releases/download/v{{version}}/yara-v{{version}}-2326-{{os}}.zip"
sha256_table = {{ "win64" = "deadbeef" }}

[tools.semgrep]
version = "1.85.0"
[tools.repomix]
version = "0.2.31"
[tools.magika]
version = "0.5.1"

[runtime.nix]
flake_ref = "github:NixOS/nixpkgs/nixos-unstable"
nixpkgs_rev = "{_VALID_NIXPKGS_REV}"
php_attr = "php83"
mariadb_attr = "mariadb_1011"
chromium_attr = "chromium"
playwright_browsers = "playwright-driver.browsers"

[security]
network_disabled = true
ssrf_allowlist = [
    "cwe.mitre.org",
    "services.nvd.nist.gov",
    "github.com",
    "raw.githubusercontent.com",
]
sandbox_drop_caps = ["ALL"]
sandbox_no_new_priv = true
sandbox_read_only = true

[logging]
level = "INFO"
format = "json"
retention_days = 30
to_file = true
to_stderr = true
"""


@pytest.fixture
def valid_case_factory(tmp_path: Path) -> Callable[..., Path]:
    """Return a factory that materializes a valid case directory.

    Returns a callable ``make(target=b"...", reference=b"...") -> case_path``
    where ``case_path`` is the absolute path of the rendered ``case.toml``.
    """

    def _make(
        *,
        target_bytes: bytes = b"REDACTS-target-fixture\n",
        reference_bytes: bytes = b"REDACTS-reference-fixture\n",
        case_subdir: str = "case",
    ) -> Path:
        case_dir = tmp_path / case_subdir
        (case_dir / "inputs").mkdir(parents=True, exist_ok=True)

        target_path = case_dir / "inputs" / "target.bin"
        reference_path = case_dir / "inputs" / "reference.bin"
        target_path.write_bytes(target_bytes)
        reference_path.write_bytes(reference_bytes)

        target_sha = hashlib.sha256(target_bytes).hexdigest()
        reference_sha = hashlib.sha256(reference_bytes).hexdigest()

        case_toml = case_dir / "case.toml"
        case_toml.write_text(_render(case_dir, target_sha, reference_sha), encoding="utf-8")
        return case_toml

    return _make


@pytest.fixture
def isolated_search_paths(tmp_path: Path):
    """Return a list of dotenv search paths confined to the tmp dir.

    Tests pass this as ``dotenv_search_paths`` so a developer's
    ``~/.redacts/.env`` (if any) does not poison the run.
    """
    return [tmp_path / "_no_dotenv_here"]
