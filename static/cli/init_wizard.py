"""
REDACTS Interactive Contract Builder (case.toml generation).

Provides interactive and non-interactive wizard functionality to build a valid
``case.toml`` contract matching ``schema_version = 2``.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rich.console import Console


class MissingInputError(Exception):
    """A target or reference path the operator named does not exist on disk."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"input path does not exist: {path}")
        self.path = path


def detect_scanners() -> list[str]:
    """Auto-detect available scanners (regex, yara, trivy, semgrep).

    ``regex`` is always available. The tool-backed scanners are resolved with
    the **same** canonical resolver the scan and preflight use
    (:func:`static.scanners.external._resolve_venv_tool`), so ``init`` never
    writes a scanner into ``case.toml`` that the scan then cannot run - and
    never omits one it could. Definition of "available" is therefore identical
    across ``init``, ``preflight`` and the scan.
    """
    from static.scanners.external import _resolve_venv_tool

    detected = ["regex"]
    # Canonical display order.
    for name in ("yara", "trivy", "semgrep"):
        if _resolve_venv_tool(name) is not None:
            detected.append(name)
    return detected


_TOML_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


def toml_escape(value: object) -> str:
    """Escape *value* for embedding inside a TOML basic (double-quoted) string.

    Every field below is interpolated into a hand-written template, so an
    unescaped ``"`` or ``\\`` produces a file that either fails to parse or
    parses into something other than what the operator typed - an analyst name
    like ``O'Brien "Bob"`` or a Windows path is enough to do it.
    """
    text = str(value)
    out = []
    for ch in text:
        if ch in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[ch])
        elif ch < "\x20" or ch == "\x7f":
            # TOML requires control characters to be \u-escaped.
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    return "".join(out)


def generate_case_toml(
    *,
    case_id: str,
    analyst: str,
    organization: str,
    target_path: str,
    target_sha256: str,
    reference_path: str,
    reference_sha256: str,
    scanners: list[str],
    date: str | None = None,
    description: str | None = None,
) -> str:
    """Generate a ready-to-run case.toml configuration matching schema_version = 2."""
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if description is None:
        description = f"REDACTS threat scan case contract for {case_id}"

    scanners_str = ", ".join(f'"{toml_escape(s)}"' for s in scanners)

    # Normalise separators first (TOML and Windows both accept forward
    # slashes), then escape whatever remains - a path may still contain a
    # quote or other character the template cannot carry raw.
    target_str = toml_escape(str(target_path).replace("\\", "/"))
    ref_str = toml_escape(str(reference_path).replace("\\", "/"))
    case_id = toml_escape(case_id)
    analyst = toml_escape(analyst)
    organization = toml_escape(organization)
    date = toml_escape(date)
    description = toml_escape(description)
    target_sha256 = toml_escape(target_sha256)
    reference_sha256 = toml_escape(reference_sha256)

    toml_content = f"""# REDACTS - Case Contract
# Generated via `python main.py init` on {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}

schema_version = 2

[case]
id = "{case_id}"
analyst = "{analyst}"
organization = "{organization}"
date = "{date}"
description = "{description}"

[paths]
workspace_root = "."

[inputs.target]
path = "{target_str}"
sha256 = "{target_sha256}"

[inputs.reference]
path = "{ref_str}"
sha256 = "{reference_sha256}"

[static]
enabled = true
scanners = [{scanners_str}]
formats = ["html", "json", "markdown", "sarif"]
severity_gate = "high"
max_total_files = 50000
parallel_workers = 4
global_timeout_seconds = 3600

[dynamic]
enabled = false
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
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[dynamic.images.php]
registry = "docker.io"
repo = "library/php"
tag = "8.3-apache"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[dynamic.images.playwright]
registry = "mcr.microsoft.com"
repo = "playwright"
tag = "v1.51.0-noble"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[dynamic.images.sandbox]
registry = "docker.io"
repo = "library/php"
tag = "8.2-cli-alpine"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[dynamic.credentials]
admin_user = "site_admin"
admin_password = "Strong!Password-16+chars"
admin_email = "admin@example.invalid"
db_root_password = "Strong!RootPassword-16+chars"
db_user = "redcap"
db_password = "Strong!DbPassword-16+chars"
salt = "Strong!Salt-16+chars"

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
sha256_table = {{ "windows-64bit" = "", "linux-64bit" = "", "darwin-64bit" = "" }}

[tools.yara]
version = "4.5.2"
url_template = "https://github.com/VirusTotal/yara/releases/download/v{{version}}/yara-v{{version}}-2326-{{os}}.zip"
sha256_table = {{ "win64" = "" }}

[tools.semgrep]
version = "1.85.0"

[tools.repomix]
version = "0.2.31"

[tools.magika]
version = "0.5.1"

[runtime.nix]
flake_ref = "github:NixOS/nixpkgs/nixos-unstable"
nixpkgs_rev = "0123456789abcdef0123456789abcdef01234567"
php_attr = "php83"
mariadb_attr = "mariadb_1011"
chromium_attr = "chromium"
playwright_browsers = "playwright-driver.browsers"

[security]
network_disabled = false
ssrf_allowlist = [
    "cwe.mitre.org",
    "services.nvd.nist.gov",
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
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
    return toml_content


def _prompt(prompt_text: str, default_val: str) -> str:
    """Helper for reading interactive prompt input with default fallback."""
    suffix = f" [{default_val}]" if default_val else ""
    try:
        val = input(f"{prompt_text}{suffix}: ").strip()
        return val if val else default_val
    except (EOFError, KeyboardInterrupt):
        return default_val


def run_init_wizard(args: argparse.Namespace | None = None) -> int:
    """Run the interactive contract builder wizard.

    Interactively prompts (or uses non-interactive CLI flags) for target/reference
    paths, auto-computes SHA-256 for file targets, auto-detects scanners, builds a valid
    schema_version = 2 TOML configuration, validates it against load_and_freeze(),
    writes case.toml, and runs preflight checks.
    """
    from static.cli._console import RICH_AVAILABLE, cli_print, create_console
    from static.cli.error_recovery import ErrorRecoveryBlock
    from static.cli.preflight import _display_preflight_table, run_preflight
    from static.core import paths, runtime_context
    from static.core.contract import CaseConfigError, load_and_freeze
    from static.core.hashing import compute_single_hash

    console = create_console()

    cli_print(console, "REDACTS Interactive Contract Builder (case.toml)", style="bold cyan")
    cli_print(console, "==================================================", style="dim")
    cli_print(console, "")

    # Non-interactive check flag
    non_interactive = getattr(args, "yes", False) or getattr(args, "non_interactive", False)

    # 1. Target path
    target_val = getattr(args, "target", None)
    if target_val is not None:
        target_path = Path(target_val)
    elif non_interactive or not sys.stdin.isatty():
        target_path = Path("inputs/target.zip")
    else:
        resp = _prompt("Target archive or directory path", "inputs/target.zip")
        target_path = Path(resp)

    # 2. Reference path
    ref_val = getattr(args, "reference", None)
    if ref_val is not None:
        ref_path = Path(ref_val)
    elif non_interactive or not sys.stdin.isatty():
        ref_path = Path("inputs/reference.zip")
    else:
        resp = _prompt("Reference archive or directory path", "inputs/reference.zip")
        ref_path = Path(resp)

    # 3. Case ID
    default_case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}-0001"
    case_id = getattr(args, "case_id", None)
    if not case_id:
        if non_interactive or not sys.stdin.isatty():
            case_id = default_case_id
        else:
            case_id = _prompt("Case ID", default_case_id)

    # 4. Analyst
    analyst = getattr(args, "analyst", None)
    if not analyst:
        if non_interactive or not sys.stdin.isatty():
            analyst = "Security Analyst"
        else:
            analyst = _prompt("Analyst name", "Security Analyst")

    # 5. Organization
    org = getattr(args, "organization", None)
    if not org:
        if non_interactive or not sys.stdin.isatty():
            org = "REDACTS"
        else:
            org = _prompt("Organization name", "REDACTS")

    # Output case file destination
    output_case_path = Path(getattr(args, "output", None) or getattr(args, "case", None) or Path("case.toml")).resolve()
    output_dir = output_case_path.parent

    # Resolve target and reference paths relative to the output directory.
    #
    # Missing inputs are a hard error, never fabricated. Creating a placeholder
    # would seal a contract whose recorded SHA-256 is the digest of an empty
    # file, and the scan would then report a pristine result for evidence that
    # was never actually supplied - a silent false negative in a forensic tool.
    def _prepare_target(p: Path, output_dir: Path | None = None) -> tuple[Path, str]:
        target_p = p if p.is_absolute() or output_dir is None else output_dir / p
        if target_p.is_file():
            return target_p, compute_single_hash(target_p)
        if target_p.is_dir():
            return target_p, ""
        raise MissingInputError(target_p)

    try:
        resolved_target, target_sha256 = _prepare_target(target_path, output_dir=output_dir)
        resolved_ref, ref_sha256 = _prepare_target(ref_path, output_dir=output_dir)
    except MissingInputError as exc:
        block = ErrorRecoveryBlock(
            title="Evidence Input Not Found",
            what_went_wrong=(
                f"The path does not exist: {exc.path}\n"
                "  REDACTS will not create a placeholder in its place - an empty "
                "file would be recorded in the contract as if it were the evidence."
            ),
            how_to_fix=[
                "Stage the target and reference artifacts (archive or extracted "
                "directory) on disk first.",
                "Re-run with explicit paths: python main.py init --target <PATH> "
                "--reference <PATH>",
            ],
            recommended_command="python main.py init --target <PATH> --reference <PATH>",
            exit_code=2,
        )
        block.display(console)
        return 2

    # Auto-detect scanners
    detected_scanners = detect_scanners()
    cli_print(console, f"Auto-detected scanners: {', '.join(detected_scanners)}", style="dim")

    # Generate TOML
    toml_str = generate_case_toml(
        case_id=case_id,
        analyst=analyst,
        organization=org,
        target_path=str(target_path),
        target_sha256=target_sha256,
        reference_path=str(ref_path),
        reference_sha256=ref_sha256,
        scanners=detected_scanners,
    )

    # Write to target case file
    output_case_path.parent.mkdir(parents=True, exist_ok=True)
    output_case_path.write_text(toml_str, encoding="utf-8")
    cli_print(console, f"[OK] Wrote contract template to {output_case_path}", style="green")

    # Validate against load_and_freeze()
    try:
        contract = load_and_freeze(output_case_path)
        try:
            runtime_context.set_contract(contract)
        except RuntimeError:
            pass  # Contract already set in this process
        paths.inject_tools_on_path()
        cli_print(console, "[OK] Contract passed schema_version = 2 validation.", style="green")
    except CaseConfigError as exc:
        cli_print(console, f"[FATAL] Generated case.toml failed validation: {exc}", style="bold red")
        return 2

    # Run preflight validation
    pf_result = run_preflight(phase="check")
    if console and RICH_AVAILABLE:
        _display_preflight_table(console, pf_result)

    if pf_result.blocked:
        cli_print(console, "[WARNING] Preflight check has blocked items. See SETUP.md for step-by-step installation instructions.", style="yellow")
    else:
        cli_print(console, "[OK] Preflight validation passed for generated case.toml.", style="bold green")

    cli_print(console, f"\nReady! You can now run 'python main.py scan' using {output_case_path.name}.", style="bold cyan")
    return 0
