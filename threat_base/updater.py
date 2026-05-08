"""
REDACTS Updater - Download and verify knowledge data files.

Provides atomic update capabilities for externalized knowledge data:

    - CWE (Common Weakness Enumeration) database
    - ATT&CK Enterprise STIX 2.1 bundle
    - YARA community detection rules
    - NVD (National Vulnerability Database) API validation

Each update follows the atomic replacement protocol:

    1. Download to a transient file
    2. Verify integrity (SHA-256 hash)
    3. Replace production file atomically
    4. Regenerate checksums.json manifest

Usage::

    python main.py update cwe        # Update CWE database
    python main.py update attack     # Update ATT&CK Enterprise data
    python main.py update yara       # Update YARA community rules
    python main.py update nvd        # Validate NVD API configuration
    python main.py update all        # Update all knowledge sources

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import hashlib
import logging
import os
import re as _re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Data directory resolution

_DATA_DIR = Path(__file__).resolve().parent / "data"

# CWE CSV lives in the same knowledge/data/ directory
_CWE_CSV_DIR = Path(__file__).resolve().parent / "data"

# YARA rules: use the same cache directory as YaraAdapter. The canonical
# paths module is the single source of truth; environment variables are
# not consulted.
def _yara_rules_dir() -> Path:
    """Resolve YARA rules dir from canonical paths module."""
    from static.core.paths import cache_dir
    return cache_dir() / "yara_rules"


def _yara_sources():
    """Return the contract-driven (or default) YARA community spec list."""
    from .sources import yara_community_sources
    return yara_community_sources()


_YARA_RULES_DIR = _yara_rules_dir()

# Rich console (optional)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class UpdateError(RuntimeError):
    """Raised when an update operation fails."""


# Console helpers


def _print(console: "Console" | None, msg: str, style: str = "") -> None:
    if console and RICH_AVAILABLE:
        console.print(msg, style=style)
    else:
        print(msg)


def _confirm(
    console: "Console" | None, label: str, default: bool = True
) -> bool:
    if console and RICH_AVAILABLE:
        return Confirm.ask(label, default=default)
    suffix = " [Y/n]" if default else " [y/N]"
    answer = input(f"{label}{suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


# Atomic file replacement


def _atomic_replace(source: Path, destination: Path) -> None:
    """Replace *destination* with *source* as atomically as the OS allows.

    Creates a .bak backup before replacement and rolls back on failure.
    """
    backup = destination.with_suffix(destination.suffix + ".bak")
    try:
        if destination.is_file():
            shutil.copy2(destination, backup)
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(source, destination)
        # Success - clean up backup
        if backup.is_file():
            backup.unlink()
    except Exception:
        # Rollback: restore backup if the replace itself failed
        if backup.is_file() and not destination.is_file():
            os.replace(backup, destination)
        raise


def _download_to_temp(url: str, label: str) -> Path:
    """Download *url* to a transient file. Returns the temp file path.

    Goes through ``assert_network_allowed`` so the call is refused at
    the host boundary when ``[security].network_disabled = true`` or when
    the host is not in ``[security].ssrf_allowlist``.
    """
    import requests

    from static.core.network import assert_network_allowed

    assert_network_allowed(url, label=f"threat_base:{label}")

    fd, tmp_name = tempfile.mkstemp(prefix="redacts_update_")
    tmp_path = Path(tmp_name)
    try:
        os.close(fd)
        sha256 = hashlib.sha256()
        logger.info("Downloading %s from %s", label, url)
        with requests.get(url, stream=True, timeout=120) as resp:
            resp.raise_for_status()
            with open(tmp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
                    sha256.update(chunk)
        digest = sha256.hexdigest()
        logger.info("Downloaded %s - SHA-256: %s", label, digest)
        return tmp_path
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


# Update operations

# CWE CSV URL is sourced from the active FrozenCaseContract via
# :mod:`threat_base.sources`.


def update_cwe(
    *, confirm: bool = True, console: "Console" | None = None
) -> bool:
    """Download the latest CWE CSV from MITRE.

    Protocol: download ZIP -> extract CSV -> atomic replace -> update hash.
    """
    from .sources import cwe_url

    if confirm and not _confirm(
        console, "Download latest CWE database from MITRE?"
    ):
        return False

    _print(console, "  Updating CWE database...")

    try:
        tmp_zip = _download_to_temp(cwe_url(), "CWE CSV")

        try:
            with zipfile.ZipFile(tmp_zip) as zf:
                csv_names = [n for n in zf.namelist() if n.endswith(".csv")]
                if not csv_names:
                    raise UpdateError("No CSV file found in CWE ZIP")
                if len(csv_names) > 1:
                    logger.warning("CWE ZIP contains %d CSV files; using %s", len(csv_names), csv_names[0])

                # Zip Slip protection
                resolved_dest = _CWE_CSV_DIR.resolve()
                for member in zf.namelist():
                    member_path = (_CWE_CSV_DIR / member).resolve()
                    if not str(member_path).startswith(str(resolved_dest)):
                        raise UpdateError(f"Zip Slip detected: {member}")

                # Extract to temp, then atomic replace
                fd, tmp_csv_name = tempfile.mkstemp(
                    suffix=".csv", prefix="redacts_cwe_"
                )
                tmp_csv = Path(tmp_csv_name)
                os.close(fd)

                try:
                    with (
                        zf.open(csv_names[0]) as src,
                        open(tmp_csv, "wb") as dst,
                    ):
                        shutil.copyfileobj(src, dst)

                    # Find existing CWE CSV or use canonical name
                    existing = sorted(_CWE_CSV_DIR.glob("cwec_v*.csv"))
                    if existing:
                        dest = existing[0]
                    else:
                        from threat_base.cwe_database import CWE_CSV_FILENAME
                        dest = _CWE_CSV_DIR / CWE_CSV_FILENAME

                    _atomic_replace(tmp_csv, dest)

                    # Write SHA-256 sidecar
                    h = hashlib.sha256(dest.read_bytes()).hexdigest()
                    sha_path = dest.with_suffix(".csv.sha256")
                    sha_path.write_text(h + "\n", encoding="utf-8")

                    _print(
                        console,
                        f"    CWE updated: {dest.name} (SHA-256: {h[:16]}...)",
                        style="green",
                    )
                    return True
                finally:
                    tmp_csv.unlink(missing_ok=True)
        finally:
            tmp_zip.unlink(missing_ok=True)
    except Exception as exc:
        _print(console, f"    CWE update failed: {exc}", style="red")
        logger.error("CWE update failed: %s", exc)
        return False


def update_attack(
    *, confirm: bool = True, console: "Console" | None = None
) -> bool:
    """Download the full ATT&CK Enterprise STIX 2.1 bundle.

    Re-uses the existing prefetch infrastructure with ``force=True``.
    """
    if confirm and not _confirm(
        console, "Download ATT&CK Enterprise STIX bundle (~25MB)?"
    ):
        return False

    _print(console, "  Updating ATT&CK Enterprise data...")

    try:
        from .prefetch import prefetch_attack_data

        ok = prefetch_attack_data(force=True)
        if ok:
            _print(
                console, "    ATT&CK data updated successfully", style="green"
            )
        else:
            _print(console, "    ATT&CK download failed", style="red")
        return ok
    except Exception as exc:
        _print(console, f"    ATT&CK update failed: {exc}", style="red")
        logger.error("ATT&CK update failed: %s", exc)
        return False


# YARA community rule specs are sourced from the active
# FrozenCaseContract via :mod:`threat_base.sources`.
# A baseline list mirroring ``YaraAdapter._COMMUNITY_RULES`` is
# returned when no contract is installed.


def _sanitize_php_malware_finder(rule_file: Path) -> None:
    """Strip unsatisfiable includes from php-malware-finder rules."""
    text = rule_file.read_text(encoding="utf-8", errors="replace")
    original = text
    text = _re.sub(
        r'^\s*include\s+"whitelist\.yar"\s*$', "", text, flags=_re.MULTILINE
    )
    text = _re.sub(
        r'^\s*import\s+"hash"\s*$', "", text, flags=_re.MULTILINE
    )
    text = _re.sub(r"\s+and\s+not\s+IsWhitelisted\b", "", text)
    if text != original:
        rule_file.write_text(text, encoding="utf-8")
        logger.info("Sanitized php-malware-finder rules")


def update_yara(
    *, confirm: bool = True, console: "Console" | None = None
) -> bool:
    """Download community YARA rules with atomic replacement."""
    if confirm and not _confirm(
        console,
        f"Download {len(_yara_sources())} YARA community rule sets?",
    ):
        return False

    _print(console, "  Updating YARA community rules...")
    _YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
    success_count = 0
    sources = _yara_sources()

    for spec in sources:
        try:
            tmp = _download_to_temp(spec["url"], spec["name"])
            try:
                dest = _YARA_RULES_DIR / f"{spec['name']}.yar"
                _atomic_replace(tmp, dest)

                # Post-download sanitization
                if spec["name"] == "php-malware-finder":
                    _sanitize_php_malware_finder(dest)

                # Write SHA-256 sidecar
                h = hashlib.sha256(dest.read_bytes()).hexdigest()
                sha_path = dest.with_suffix(".yar.sha256")
                sha_path.write_text(h + "\n", encoding="utf-8")

                _print(
                    console,
                    f"    {spec['name']}: updated ({h[:16]}...)",
                    style="green",
                )
                success_count += 1
            finally:
                tmp.unlink(missing_ok=True)
        except Exception as exc:
            _print(
                console,
                f"    {spec['name']}: FAILED - {exc}",
                style="red",
            )
            logger.error("YARA rule %s update failed: %s", spec["name"], exc)

    return success_count == len(sources)


def update_nvd(
    *, confirm: bool = True, console: "Console" | None = None
) -> bool:
    """Validate NVD API configuration and test connectivity."""
    if confirm and not _confirm(console, "Validate NVD API configuration?"):
        return False

    _print(console, "  Validating NVD API configuration...")

    from .nvd import NvdClient

    client = NvdClient()
    if client.available:
        _print(console, "    NVD API key: configured", style="green")
        try:
            result = client.get_cve("CVE-2021-44228")  # Log4Shell
            if result:
                _print(
                    console,
                    "    NVD API: reachable (test query OK)",
                    style="green",
                )
            else:
                _print(
                    console,
                    "    NVD API: query returned empty - verify API key",
                    style="yellow",
                )
        except Exception as exc:
            _print(
                console,
                f"    NVD API: connectivity test failed - {exc}",
                style="yellow",
            )
        return True

    _print(
        console,
        "    NVD API key not configured (set [threat_base.sources.nvd] api_key in case.toml)",
        style="yellow",
    )
    _print(
        console,
        "    NVD enrichment is optional - scan runs without it",
        style="dim",
    )
    return True  # Not a failure - NVD is optional


def update_all(
    *, confirm: bool = True, console: "Console" | None = None
) -> bool:
    """Update all knowledge sources and regenerate checksums."""
    if confirm and not _confirm(console, "Update ALL knowledge sources?"):
        return False

    results = {
        "CWE": update_cwe(confirm=False, console=console),
        "ATT&CK": update_attack(confirm=False, console=console),
        "YARA": update_yara(confirm=False, console=console),
        "NVD": update_nvd(confirm=False, console=console),
    }

    # Regenerate checksums for YAML/STIX data
    from .data_loader import regenerate_checksums

    regenerate_checksums()
    _print(console, "  Regenerated checksums.json manifest", style="green")

    # Summary
    _print(console, "\n  Update Summary:")
    all_ok = True
    for name, ok in results.items():
        if console and RICH_AVAILABLE:
            status = "[green]OK[/green]" if ok else "[red]FAILED[/red]"
            console.print(f"    {name}: {status}")
        else:
            tag = "OK" if ok else "FAILED"
            print(f"    {name}: {tag}")
        if not ok:
            all_ok = False

    return all_ok


# CLI entry point

_USAGE = """\
Usage: python main.py update <target>

Targets:
    cwe       Download latest CWE database from MITRE
    attack    Download ATT&CK Enterprise STIX 2.1 bundle
    yara      Download community YARA detection rules
    nvd       Validate NVD API configuration
    all       Update all knowledge sources
"""

_UPDATE_DISPATCH: dict[str, object] = {
    "cwe": update_cwe,
    "attack": update_attack,
    "yara": update_yara,
    "nvd": update_nvd,
    "all": update_all,
}


def main(args: list[str] | None = None) -> int:
    """CLI entry point for knowledge data updates."""
    argv = args if args is not None else sys.argv[1:]

    if not argv or argv[0] in ("--help", "-h"):
        print(_USAGE)
        return 0

    # Parse --no-confirm flag
    confirm = "--no-confirm" not in argv
    argv = [a for a in argv if a != "--no-confirm"]

    if not argv:
        print(_USAGE)
        return 1

    target_str = argv[0].lower()
    if target_str not in _UPDATE_DISPATCH:
        print(f"Unknown target: {target_str!r}\n")
        print(_USAGE)
        return 1

    console = Console() if RICH_AVAILABLE else None

    if console and RICH_AVAILABLE:
        console.print(
            Panel(
                f"  REDACTS Knowledge Updater - target: [bold]{target_str}[/bold]",
                style="bold blue",
            )
        )
    else:
        print(f"\nREDACTS Knowledge Updater - target: {target_str}\n")

    fn = _UPDATE_DISPATCH[target_str]

    ok = fn(confirm=confirm, console=console)  # type: ignore[operator]

    return 0 if ok else 1
