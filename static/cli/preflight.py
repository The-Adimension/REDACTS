"""Pre-scan environment verification - BLOCK / WARN contract.

Scans cost analyst time. A scan that runs to completion and then turns\nout to have skipped Trivy because the binary was missing wastes that\ntime. Preflight runs first, fails loud, and tells the operator exactly\nwhat is missing before any REDCap snapshot is opened.

The contract has two tiers:

* **BLOCK** - Python interpreter >= 3.12, the core ``import`` set, and the\n  three integrity-verified knowledge YAMLs (IoC indicators, SEC* rules,\n  sensitive-data patterns). Any missing BLOCK item exits non-zero. We\n  do not let a run start without these because every scan path depends\n  on them; producing a partial report under those conditions would be\n  misleading.\n* **WARN** - external scanners (Trivy, YARA, Semgrep, Magika), the\n  Docker daemon used by DAST, and enrichment data (MITRE ATT&CK, NVD\n  cache). Missing WARN items are recorded and surfaced as a\n  ``REDUCED COVERAGE`` banner in every output format so the analyst\n  reading the report - likely a REDCap administrator who did not run\n  the scan themselves - sees what was not checked.

Concretely: a REDCap 14.0.40 export run on a workstation without YARA\ngets a finished report with the YARA section stamped\n*\"reduced coverage: yara binary not found\"*. A run on Python 3.11 does\nnot get a report at all.

Usage::

    from static.cli.preflight import run_preflight
    result = run_preflight()
    if result.blocked:
        sys.exit(1)
    # result.coverage_notes is forwarded to the report generator.

Copyright 2024-2026 The Adimension / Shehab Anwer
Apache-2.0.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from .dependencies import (
    PYTHON_PACKAGES,
    SYSTEM_TOOLS,
    fix_hint_for_python,
    fix_hint_for_tool,
)

logger = logging.getLogger(__name__)


@dataclass
class PreflightCheck:
    """Single preflight check result."""

    layer: int
    name: str
    passed: bool
    tier: str  # "BLOCK" or "WARN"
    message: str = ""
    version: str = ""
    fix_hint: str = ""


@dataclass
class PreflightResult:
    """Aggregated preflight outcome."""

    checks: list[PreflightCheck] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        """True if any BLOCK-tier check failed."""
        return any(
            not c.passed and c.tier == "BLOCK" for c in self.checks
        )

    @property
    def block_failures(self) -> list[PreflightCheck]:
        return [c for c in self.checks if not c.passed and c.tier == "BLOCK"]

    @property
    def warn_failures(self) -> list[PreflightCheck]:
        return [c for c in self.checks if not c.passed and c.tier == "WARN"]

    @property
    def coverage_notes(self) -> list[str]:
        """Human-readable annotations for the report provenance section."""
        notes: list[str] = []
        for c in self.warn_failures:
            notes.append(
                f"REDUCED COVERAGE: {c.name} unavailable - {c.message}"
            )
        return notes


# Dependency registries derived from the canonical source in dependencies.py.

# (import_name, pip_name, min_version) - BLOCK-tier only (required=True)
_BLOCK_PYTHON_DEPS: list[tuple[str, str, str]] = [
    (imp, pip, ver)
    for imp, pip, required, ver, _desc in PYTHON_PACKAGES
    if required
]

# BLOCK-tier external tools - required for full coverage
_BLOCK_EXTERNAL_TOOLS: list[dict] = [t for t in SYSTEM_TOOLS if t.get("required")]

# WARN-tier external tools - optional, reduced coverage when absent
_WARN_EXTERNAL_TOOLS: list[dict] = [t for t in SYSTEM_TOOLS if not t.get("required")]


def _check_python_version() -> PreflightCheck:
    """Layer 1: Verify Python >= 3.12."""
    vi = sys.version_info
    version_str = f"{vi.major}.{vi.minor}.{vi.micro}"
    passed = vi >= (3, 12)
    return PreflightCheck(
        layer=1,
        name="Python runtime",
        passed=passed,
        tier="BLOCK",
        version=version_str,
        message="" if passed else f"Python >= 3.12 required, found {version_str}",
        fix_hint="" if passed else "install Python 3.12 or newer (see https://www.python.org/downloads/)",
    )


def _check_block_dependency(
    import_name: str, pip_name: str, min_version: str
) -> PreflightCheck:
    """Layer 2: Verify a single BLOCK-tier Python dependency."""
    hint = fix_hint_for_python(pip_name, min_version)
    try:
        mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", getattr(mod, "VERSION", ""))
        if isinstance(version, tuple):
            version = ".".join(str(v) for v in version)
        return PreflightCheck(
            layer=2,
            name=pip_name,
            passed=True,
            tier="BLOCK",
            version=str(version),
        )
    except ImportError:
        return PreflightCheck(
            layer=2,
            name=pip_name,
            passed=False,
            tier="BLOCK",
            message=f"Not installed. Fix: {hint}",
            fix_hint=hint,
        )


def _check_core_knowledge() -> list[PreflightCheck]:
    """Layer 3: Verify core knowledge data is importable and populated.

    The knowledge module contains IoC definitions, attack vectors, security
    rules, and sensitive-data patterns.  These are Python modules with
    hardcoded data - they MUST be importable for the scanner to function.
    """
    checks: list[PreflightCheck] = []

    knowledge_modules = [
        ("threat_base.ioc_database", "IoCDatabase", "IoC Database"),
        ("threat_base.attack_vectors", "AttackVectorDatabase", "Attack Vectors"),
        ("threat_base.sensitive_data", "SensitiveDataScanner", "Sensitive Data Patterns"),
        ("threat_base.cwe_database", "CweDatabase", "CWE Database"),
        ("threat_base.mitre_mapping", "MITRE_ATTACK_MAP", "MITRE ATT&CK Mapping"),
    ]

    for module_path, attr_name, display_name in knowledge_modules:
        try:
            mod = importlib.import_module(module_path)
            obj = getattr(mod, attr_name, None)
            if obj is None:
                checks.append(PreflightCheck(
                    layer=3,
                    name=display_name,
                    passed=False,
                    tier="BLOCK",
                    message=f"{attr_name} not found in {module_path}",
                ))
            else:
                checks.append(PreflightCheck(
                    layer=3,
                    name=display_name,
                    passed=True,
                    tier="BLOCK",
                ))
        except Exception as exc:
            checks.append(PreflightCheck(
                layer=3,
                name=display_name,
                passed=False,
                tier="BLOCK",
                message=f"Import failed: {exc}",
            ))

    return checks


def _check_data_integrity() -> list[PreflightCheck]:
    """Layer 3b: Verify SHA-256 checksums of knowledge data files.

    Loads the checksums manifest and verifies every tracked data file
    against its recorded hash.  A mismatch raises ``IntegrityError``
    which is caught here and reported as a BLOCK failure.
    """
    checks: list[PreflightCheck] = []
    try:
        from threat_base.data_loader import (
            IntegrityError,
            _CHECKSUMS,
            _DATA_DIR,
            _verify_file,
        )

        if not _CHECKSUMS:
            checks.append(PreflightCheck(
                layer=3,
                name="Data Integrity Manifest",
                passed=False,
                tier="BLOCK",
                message="checksums.json not found - cannot verify data files",
            ))
            return checks

        for rel_path in _CHECKSUMS:
            abs_path = _DATA_DIR / rel_path
            if not abs_path.is_file():
                checks.append(PreflightCheck(
                    layer=3,
                    name=f"Data: {rel_path}",
                    passed=False,
                    tier="BLOCK",
                    message=f"Missing data file: {rel_path}",
                ))
                continue
            try:
                _verify_file(abs_path)
                checks.append(PreflightCheck(
                    layer=3,
                    name=f"Data: {rel_path}",
                    passed=True,
                    tier="BLOCK",
                ))
            except IntegrityError as exc:
                checks.append(PreflightCheck(
                    layer=3,
                    name=f"Data: {rel_path}",
                    passed=False,
                    tier="BLOCK",
                    message=str(exc).split("\n")[0],
                ))
    except Exception as exc:
        checks.append(PreflightCheck(
            layer=3,
            name="Data Integrity",
            passed=False,
            tier="BLOCK",
            message=f"Integrity check failed: {exc}",
        ))

    return checks


def _check_attack_data() -> PreflightCheck:
    """Layer 3c: Check ATT&CK Enterprise data availability.

    WARN-tier: the bundled REDACTS attack vector subset (34 patterns)
    always works.  The full ATT&CK Enterprise bundle (~25MB) is optional
    and provides richer technique descriptions and mitigations.
    """
    try:
        from threat_base.prefetch import is_attack_data_available

        if is_attack_data_available():
            return PreflightCheck(
                layer=3,
                name="ATT&CK Enterprise",
                passed=True,
                tier="WARN",
                message="Full ATT&CK Enterprise bundle available",
            )
        return PreflightCheck(
            layer=3,
            name="ATT&CK Enterprise",
            passed=False,
            tier="WARN",
            message=(
                "Full ATT&CK bundle not cached - using bundled subset "
                "(34 patterns). Run 'python main.py update attack' for full data."
            ),
        )
    except Exception as exc:
        return PreflightCheck(
            layer=3,
            name="ATT&CK Enterprise",
            passed=False,
            tier="WARN",
            message=f"ATT&CK check failed: {exc}",
        )


def _check_network_status() -> PreflightCheck:
    """Layer 5: Probe network connectivity for enrichment services.

    WARN-tier: offline mode is supported via cached/bundled data.
    This check informs the user whether NVD, ATT&CK updates, and
    community rule downloads will work.
    """
    try:
        from static.core import runtime_context

        contract = runtime_context.get_optional_contract()
        if contract is not None and contract.security.network_disabled:
            return PreflightCheck(
                layer=5,
                name="Network",
                passed=False,
                tier="WARN",
                message=(
                    "Disabled by [security].network_disabled - using "
                    "cached/bundled data only. Updates and NVD enrichment "
                    "unavailable."
                ),
                fix_hint="set [security].network_disabled = false in case.toml to enable updates",
            )
    except Exception:
        logger.debug("Could not read runtime network policy", exc_info=True)

    try:
        import socket

        socket.setdefaulttimeout(5)
        socket.create_connection(("cwe.mitre.org", 443), timeout=5).close()
        return PreflightCheck(
            layer=5,
            name="Network",
            passed=True,
            tier="WARN",
            message="Online - enrichment services reachable",
        )
    except (OSError, TimeoutError):
        return PreflightCheck(
            layer=5,
            name="Network",
            passed=False,
            tier="WARN",
            message=(
                "Offline - using cached/bundled data only. "
                "Updates and NVD enrichment unavailable."
            ),
            fix_hint="check network connectivity to cwe.mitre.org:443 (HTTPS)",
        )


def _check_external_tool(tool: dict, tier: str = "WARN") -> PreflightCheck:
    """Layer 4: Probe an external binary."""
    binary = tool["binary"]
    path = shutil.which(binary)
    hint = fix_hint_for_tool(tool)

    if not path:
        return PreflightCheck(
            layer=4,
            name=tool["name"],
            passed=False,
            tier=tier,
            message=f"'{binary}' not found on PATH - {tool['description']} disabled",
            fix_hint=hint,
        )

    # Try to get version
    version = ""
    try:
        proc = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = (proc.stdout or proc.stderr).strip().split("\n")[0][:80]
    except Exception:
        version = "found (version unknown)"

    return PreflightCheck(
        layer=4,
        name=tool["name"],
        passed=True,
        tier=tier,
        version=version,
    )


def run_preflight(
    *,
    check_knowledge: bool = True,
    check_external: bool = True,
    phase: str = "check",
) -> PreflightResult:
    """Execute the full 5-layer preflight verification.

    This is the **single entry point** every code path uses:

    * ``main.py preflight``  -> ``cmd_preflight`` -> ``run_preflight``.
    * ``main.py scan``       -> ``__main__`` -> ``step_preflight`` ->
      ``run_preflight`` (and again after ``auto_install_missing``).

    Parameters
    ----------
    check_knowledge : bool
        If *False*, skip Layer 3 (core knowledge data). Useful when
        running unit tests that don't have the full knowledge base.
    check_external : bool
        If *False*, skip Layer 4 (external tools). Useful for CI
        environments that only need the Python-based analysis.
    phase : str
        Recorded on each check so the post-install recheck can be
        distinguished from the initial gate.

    Returns
    -------
    PreflightResult
        Aggregated result.  Caller must check ``result.blocked`` and
        abort if *True*.  ``result.coverage_notes`` should be passed
        to the report generator for provenance stamping.
    """
    result = PreflightResult()

    def _add(check: PreflightCheck) -> None:
        result.checks.append(check)

    # Layer 1: Python version
    logger.info("Preflight Layer 1: Python version check")
    _add(_check_python_version())

    # Layer 2: BLOCK-tier Python dependencies
    logger.info("Preflight Layer 2: Core Python dependencies")
    for import_name, pip_name, min_ver in _BLOCK_PYTHON_DEPS:
        _add(_check_block_dependency(import_name, pip_name, min_ver))

    # Layer 3: Core knowledge data
    if check_knowledge:
        logger.info("Preflight Layer 3a: Core knowledge module imports")
        for c in _check_core_knowledge():
            _add(c)

        logger.info("Preflight Layer 3b: Data file SHA-256 verification")
        for c in _check_data_integrity():
            _add(c)

        logger.info("Preflight Layer 3c: ATT&CK Enterprise data")
        _add(_check_attack_data())

    # Layer 4: External tools (BLOCK-tier required + WARN-tier optional)
    if check_external:
        logger.info("Preflight Layer 4: External tool availability")
        for tool in _BLOCK_EXTERNAL_TOOLS:
            _add(_check_external_tool(tool, tier="BLOCK"))
        for tool in _WARN_EXTERNAL_TOOLS:
            _add(_check_external_tool(tool, tier="WARN"))

    # Layer 5: Network / offline status
    if check_external:
        logger.info("Preflight Layer 5: Network connectivity")
        _add(_check_network_status())

    # Log summary
    block_fails = result.block_failures
    warn_fails = result.warn_failures
    if block_fails:
        logger.error(
            "Preflight BLOCKED: %d critical check(s) failed",
            len(block_fails),
        )
    if warn_fails:
        logger.warning(
            "Preflight warnings: %d tool(s) unavailable - reduced coverage",
            len(warn_fails),
        )

    return result


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for ``redacts-preflight`` and ``main.py preflight``.

    The single rendering path (``_display_preflight_table``) is shared
    with ``step_preflight`` so the operator sees byte-identical output
    whether they run a standalone preflight or kick off a full scan.
    """
    parser = argparse.ArgumentParser(
        prog="redacts-preflight",
        description="Run REDACTS preflight gate (BLOCK / WARN tiers).",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help=(
            "On BLOCK-tier failure, attempt auto-install (pip + Trivy/YARA)"
            " and re-run.  Honours [security].network_disabled."
        ),
    )
    parser.add_argument(
        "--no-knowledge",
        dest="check_knowledge",
        action="store_false",
        help="Skip Layer 3 (knowledge data) checks.",
    )
    parser.add_argument(
        "--no-external",
        dest="check_external",
        action="store_false",
        help="Skip Layer 4/5 (external tools, network) checks.",
    )
    args = parser.parse_args(argv)

    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None  # type: ignore[assignment]

    result = run_preflight(
        check_knowledge=args.check_knowledge,
        check_external=args.check_external,
        phase="check",
    )
    _display_preflight_table(console, result)

    if result.blocked and args.install:
        result = auto_install_missing(result, console=console)
        _display_preflight_table(console, result)
    elif args.install:
        # User asked for auto-install but nothing is BLOCK-failing.
        # Stay explicit: a silent no-op makes operators think the flag
        # is broken.
        print(
            "\npreflight --install: no BLOCK-tier failures to repair. "
            "All required dependencies are already present."
        )

    if result.blocked:
        print("\nPreflight FAILED - cannot proceed. Fix the BLOCK issues above.")
        if not args.install:
            print("Tip: re-run with '--install' to auto-install missing items.")
        sys.exit(1)
    elif result.warn_failures:
        print(f"\nPreflight passed with {len(result.warn_failures)} warning(s).")
        for note in result.coverage_notes:
            print(f"  {note}")
    else:
        print("\nPreflight passed - all systems go.")


# step_preflight() is the user-facing wrapper that runs the gate, displays a
# Rich table, and offers an auto-install retry pass for BLOCK-tier failures.


def auto_install_missing(result, console=None):  # noqa: ANN001
    """Attempt to auto-install every BLOCK-tier failure in ``result``.

    Single entry point used by both the standalone ``main.py preflight
    --install`` command and the embedded ``step_preflight`` flow inside
    a scan.

    The function:

    1. Builds a fresh :class:`DependencyReport` (the existing installer
       APIs work in terms of dependency reports).
    2. Honours ``[security].network_disabled`` *before* any pip /
       subprocess / network call -- if the contract forbids the network
       we return the original ``result`` unchanged (re-running checks
       would not help: nothing was installed).
    3. Otherwise calls (in order) ``auto_install_python`` ->
       ``_post_install_hooks`` -> ``auto_install_system_tools``, then
       re-runs :func:`run_preflight` with ``phase="recheck"``.

    Returns
    -------
    PreflightResult
        Either the original (network-disabled) or a fresh post-install
        result.  Callers should inspect ``.blocked`` again.
    """
    from ._console import cli_print
    from .auto_install import (
        _post_install_hooks,
        auto_install_python,
        auto_install_system_tools,
    )
    from .dependencies import check_dependencies
    from static.core import runtime_context as _rc

    if not result.block_failures:
        return result

    cli_print(
        console,
        "\n  BLOCK-tier failures detected - attempting auto-install...",
        style="bold yellow",
    )

    contract = _rc.get_optional_contract()
    network_disabled = (
        contract is not None
        and getattr(contract.security, "network_disabled", False)
    )

    if network_disabled:
        cli_print(
            console,
            "   skipping auto-install: [security].network_disabled = true",
            style="yellow",
        )
        return result

    dep_report = check_dependencies(
        include_optional_tools=True, fail_on_missing=False
    )

    installed = auto_install_python(dep_report)

    _post_install_hooks(installed)
    auto_install_system_tools(dep_report)

    return run_preflight(
        check_knowledge=True,
        check_external=True,
        phase="recheck",
    )


def step_preflight(console):  # noqa: ANN001 - Console import is optional
    """Run the 5-layer fail-loud preflight gate.

    Thin wrapper that calls :func:`run_preflight` then -- on BLOCK --
    delegates to :func:`auto_install_missing` and reruns. Both rendering
    passes use :func:`_display_preflight_table`, so the output is byte
    identical to ``python main.py preflight``.

    Returns
    -------
    tuple[bool, list[str], DependencyReport]
        ``(passed, coverage_notes, dep_report)``.  ``passed`` is ``False``
        when BLOCK-tier checks fail even after auto-install.
    """
    from ._console import cli_print
    from .dependencies import check_dependencies

    cli_print(console, "Preflight verification", style="bold yellow")

    result = run_preflight(check_knowledge=True, check_external=True, phase="check")
    _display_preflight_table(console, result)

    if result.blocked:
        result = auto_install_missing(result, console=console)
        _display_preflight_table(console, result)

        if result.blocked:
            cli_print(
                console,
                "\n  x PREFLIGHT FAILED - BLOCK-tier dependencies still missing:",
                style="bold red",
            )
            for fail in result.block_failures:
                cli_print(
                    console,
                    f"    x {fail.name}: {fail.message}"
                    + (f"  [fix: {fail.fix_hint}]" if fail.fix_hint else ""),
                    style="red",
                )
            cli_print(
                console,
                "\n  Install the above and re-run REDACTS.",
                style="bold red",
            )
            dep_report = check_dependencies(
                include_optional_tools=True, fail_on_missing=False
            )
            return False, result.coverage_notes, dep_report

    if result.coverage_notes:
        cli_print(console, "")
        for note in result.coverage_notes:
            cli_print(console, f"  !  {note}", style="yellow")

    cli_print(console, "")

    dep_report = check_dependencies(
        include_optional_tools=True, fail_on_missing=False
    )
    return True, result.coverage_notes, dep_report


def _display_preflight_table(console, result) -> None:  # noqa: ANN001
    """Render preflight check results - the **only** preflight renderer.

    Both ``main()`` and ``step_preflight`` call this so the operator
    sees identical output regardless of entry point.  Falls back to
    plain text when Rich is unavailable.
    """
    from ._console import RICH_AVAILABLE

    if console and RICH_AVAILABLE:
        from rich.table import Table

        table = Table(title="Preflight Status", show_header=True)
        table.add_column("L", style="dim", width=3)
        table.add_column("Check", style="cyan", min_width=20)
        table.add_column("Tier", min_width=6)
        table.add_column("Status", min_width=8)
        table.add_column("Version", style="dim")
        table.add_column("Detail / Fix", style="dim")

        for check in result.checks:
            tier_style = "bold red" if check.tier == "BLOCK" else "yellow"
            status = (
                "[green]PASS[/green]"
                if check.passed
                else (
                    "[red]FAIL[/red]"
                    if check.tier == "BLOCK"
                    else "[yellow]WARN[/yellow]"
                )
            )
            detail = check.message
            if check.fix_hint and not check.passed:
                detail = (
                    f"{detail}\n[bold]fix:[/bold] {check.fix_hint}"
                    if detail
                    else f"[bold]fix:[/bold] {check.fix_hint}"
                )
            table.add_row(
                str(check.layer),
                check.name,
                f"[{tier_style}]{check.tier}[/{tier_style}]",
                status,
                check.version or "-",
                detail,
            )
        console.print(table)
    else:
        for check in result.checks:
            tag = "BLOCK" if check.tier == "BLOCK" else "WARN"
            status = "OK" if check.passed else "FAIL"
            line = f"  [{tag}] L{check.layer} {check.name}: {status}"
            if check.version:
                line += f" ({check.version})"
            if check.message:
                line += f" - {check.message}"
            if check.fix_hint and not check.passed:
                line += f"  fix: {check.fix_hint}"
            print(line)


