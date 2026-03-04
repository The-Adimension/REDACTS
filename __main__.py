"""
REDACTS — REDCap Arbitrary Code Threat Scan
=============================================
Interactive one-way CLI workflow.

Usage:
    python -m REDACTS              # Interactive guided scan
    python -m REDACTS --help       # Show this help

Workflow:
    1. Display banner & version
    2. Check dependencies + environment
    3. Auto-install any missing Python packages
    4. Prompt for the target REDCap files to scan
    5. Prompt for the original (reference) REDCap package
    6. Execute the full scan pipeline and generate reports

DISCLAIMER:
    REDACTS is a forensic analysis AID. It does NOT replace thorough manual
    review by qualified security professionals. Results are not guaranteed to
    be complete or definitive. Use as an auxiliary tool within your incident
    response workflow, not as the sole basis for security decisions.

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
Contact: atrium@theadimension.com
"""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Rich console (optional but strongly recommended) ──────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from .core.constants import VERSION


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _console() -> Optional["Console"]:
    return Console() if RICH_AVAILABLE else None


def _print(console: Optional["Console"], msg: str, style: str = "") -> None:
    if console and RICH_AVAILABLE:
        console.print(msg, style=style)
    else:
        print(msg)


def _prompt(console: Optional["Console"], label: str, default: str = "") -> str:
    if console and RICH_AVAILABLE:
        return Prompt.ask(label, default=default or None) or default
    else:
        suffix = f" [{default}]" if default else ""
        return input(f"{label}{suffix}: ").strip() or default


def _confirm(console: Optional["Console"], label: str, default: bool = True) -> bool:
    if console and RICH_AVAILABLE:
        return Confirm.ask(label, default=default)
    else:
        suffix = " [Y/n]" if default else " [y/N]"
        answer = input(f"{label}{suffix}: ").strip().lower()
        if not answer:
            return default
        return answer in ("y", "yes")


# ═══════════════════════════════════════════════════════════════════════
# Step 1 — Banner
# ═══════════════════════════════════════════════════════════════════════


def step_banner(console: Optional["Console"]) -> None:
    """Display application banner."""
    banner = f"""\
╔═══════════════════════════════════════════════════════════════╗
║                         REDACTS v{VERSION}                      ║
║          REDCap Arbitrary Code Threat Scan                    ║
║                                                               ║
║   Automated forensic analysis for REDCap deployments          ║
║   Semgrep · Trivy · tree-sitter · Magika · YARA · DAST       ║
╚═══════════════════════════════════════════════════════════════╝"""
    if console and RICH_AVAILABLE:
        console.print(Panel(banner, style="bold blue"))
    else:
        print(banner)

    # Disclaimer — always shown
    disclaimer = (
        "⚠  DISCLAIMER: REDACTS is a forensic analysis AID. It does not replace\n"
        "   thorough manual review by qualified security professionals. Results\n"
        "   are not guaranteed to be complete or definitive. Use as an auxiliary\n"
        "   tool within your incident response workflow, not as a sole determination.\n"
        "   \u00a9 2024\u20132026 The Adimension / Shehab Anwer \u2014 atrium@theadimension.com"
    )
    if console and RICH_AVAILABLE:
        console.print(Panel(disclaimer, style="bold yellow", title="Disclaimer"))
    else:
        print(disclaimer)
    _print(console, "")


# ═══════════════════════════════════════════════════════════════════════
# Step 2 — Dependency check
# ═══════════════════════════════════════════════════════════════════════


def step_check_deps(console: Optional["Console"]) -> "DependencyReport":
    """Check all dependencies and display status."""
    from .core.dependencies import check_dependencies

    _print(console, "━━ Step 1: Checking dependencies ━━", style="bold yellow")

    # Run checks without failing — we'll handle missing ones ourselves
    report = check_dependencies(
        include_optional_tools=True,
        fail_on_missing=False,
    )

    if console and RICH_AVAILABLE:
        table = Table(title="Dependency Status", show_header=True)
        table.add_column("Name", style="cyan", min_width=16)
        table.add_column("Status", min_width=10)
        table.add_column("Version", style="dim")
        table.add_column("Category", style="dim")

        for c in report.checks:
            status = (
                "[green]OK[/green]"
                if c.available
                else (
                    "[red]MISSING[/red]" if c.required else "[yellow]MISSING[/yellow]"
                )
            )
            table.add_row(c.name, status, c.version or "-", c.category)

        console.print(table)
    else:
        ok_count = sum(1 for c in report.checks if c.available)
        print(f"  {ok_count}/{len(report.checks)} dependencies available")
        for c in report.checks:
            if not c.available:
                tag = "REQUIRED" if c.required else "optional"
                print(f"    [{tag}] {c.name}: {c.error}")

    _print(console, "")
    return report


# ═══════════════════════════════════════════════════════════════════════
# Step 3 — Auto-install missing
# ═══════════════════════════════════════════════════════════════════════


def step_install_missing(
    console: Optional["Console"],
    report: "DependencyReport",
) -> bool:
    """Auto-install ALL missing dependencies. Block if any required tool fails."""
    from .core.dependencies import auto_install_python, auto_install_system_tools

    missing_py = report.missing_python
    missing_sys = [
        c for c in report.checks if not c.available and c.category == "system"
    ]

    if not missing_py and not missing_sys:
        _print(console, "  All dependencies satisfied.\n", style="green")
        return True

    # ── Auto-install Python packages (incl. semgrep) ─────────────────
    if missing_py:
        _print(
            console,
            f"━━ Step 2a: Auto-installing {len(missing_py)} Python package(s) ━━",
            style="bold yellow",
        )
        installed = auto_install_python(report)
        if installed:
            _print(
                console,
                f"  Installed: {', '.join(installed)}",
                style="green",
            )
        still_missing_py = report.missing_python
        if still_missing_py:
            _print(console, "  Failed to install:", style="red")
            for m in still_missing_py:
                _print(console, f"    {m.name}: {m.error}", style="red")
    else:
        _print(console, "  All Python packages OK.", style="green")

    # ── Auto-install system tools (trivy, yara) ──────────────────────
    # Re-check: some "system" deps that were missing may be resolved now
    missing_sys = [
        c for c in report.checks if not c.available and c.category == "system"
    ]
    if missing_sys:
        auto_names = [m.name for m in missing_sys if m.name in ("trivy", "yara")]
        manual_names = [m.name for m in missing_sys if m.name not in ("trivy", "yara")]

        if auto_names:
            _print(
                console,
                f"━━ Step 2b: Auto-installing {len(auto_names)} system tool(s) ━━",
                style="bold yellow",
            )
            sys_installed = auto_install_system_tools(report)
            if sys_installed:
                _print(
                    console,
                    f"  Installed: {', '.join(sys_installed)}",
                    style="green",
                )

        if manual_names:
            _print(console, "")
            _print(console, "  Optional system tools not installed:", style="dim")
            for m in missing_sys:
                if m.name in manual_names:
                    _print(console, f"    {m.name}: {m.description}", style="dim")
                    if m.install_url:
                        _print(console, f"      Docs: {m.install_url}", style="dim")
    else:
        _print(console, "  All system tools OK.", style="green")

    _print(console, "")

    # ── Hard gate: block if any REQUIRED dependency is still missing ─
    still_missing_required = report.missing_required
    if still_missing_required:
        _print(
            console,
            "  Cannot proceed — required dependencies are missing:",
            style="bold red",
        )
        for m in still_missing_required:
            _print(console, f"    ✗ {m.name}: {m.error}", style="red")
            if m.install_url:
                _print(console, f"      → {m.install_url}", style="cyan")
        _print(console, "")
        _print(
            console,
            "  Install the above and re-run REDACTS.",
            style="bold red",
        )
        return False

    _print(console, "")
    return True


# ═══════════════════════════════════════════════════════════════════════
# Step 4 — Prompt for target
# ═══════════════════════════════════════════════════════════════════════


def step_prompt_target(console: Optional["Console"]) -> str:
    """Ask user for the REDCap deployment to scan."""
    _print(
        console,
        "━━ Step 3: Select target REDCap to scan ━━",
        style="bold yellow",
    )
    _print(console, "  Provide the path to the REDCap files under scrutiny.")
    _print(console, "  Accepts: directory, ZIP file, or URL\n")

    while True:
        target = _prompt(console, "  Target path")
        if not target:
            _print(console, "  Target is required.", style="red")
            continue

        # Basic validation
        p = Path(target)
        if p.exists() or target.startswith(("http://", "https://", "ftp://")):
            _print(console, f"  Target: {target}\n", style="green")
            return target
        else:
            _print(console, f"  Path not found: {target}", style="red")
            _print(console, "  Please enter a valid path, ZIP file, or URL.\n")


# ═══════════════════════════════════════════════════════════════════════
# Step 5 — Prompt for reference
# ═══════════════════════════════════════════════════════════════════════


def step_prompt_reference(console: Optional["Console"]) -> str:
    """Ask user for the clean reference REDCap package."""
    _print(
        console,
        "━━ Step 4: Select reference REDCap (clean source) ━━",
        style="bold yellow",
    )
    _print(console, "  Provide the clean/original REDCap package to compare against.")
    _print(console, "  Accepts: directory, ZIP file, or URL\n")

    while True:
        reference = _prompt(console, "  Reference path")
        if not reference:
            _print(console, "  Reference is required.", style="red")
            continue

        p = Path(reference)
        if p.exists() or reference.startswith(("http://", "https://", "ftp://")):
            _print(console, f"  Reference: {reference}\n", style="green")
            return reference
        else:
            _print(console, f"  Path not found: {reference}", style="red")
            _print(console, "  Please enter a valid path, ZIP file, or URL.\n")


# ═══════════════════════════════════════════════════════════════════════
# Step 6 — Full scan workflow
# ═══════════════════════════════════════════════════════════════════════


def step_run_scan(
    console: Optional["Console"],
    target: str,
    reference: str,
    dep_report: Optional["DependencyReport"] = None,
) -> int:
    """Execute the complete REDACTS scan workflow.

    Phases:
        A. Evidence collection (Tier 1)
        B. Baseline audit (reference vs target) + delta-scoped investigation
        C. Tool orchestration — delta-aware (Semgrep + Trivy + YARA + Magika + tree-sitter)
        D. Report generation (HTML + JSON + Markdown + SARIF)
    """
    from .core import REDACTSConfig, setup_logging
    from .audit.pipeline import AuditPipeline
    from .evidence.collector import EvidenceCollector
    from .orchestration.tool_orchestrator import ToolOrchestrator, OrchestratorConfig
    from .reporting.forensic_report import ForensicReportGenerator
    from .reporting.sarif_exporter import SarifExporter
    import re as _re

    config = REDACTSConfig()
    setup_logging(config.log_level)

    # Extract REDCap version from target filename if present.
    # Typical names: redcap_v15.7.4-server.zip, redcap_v16.0.1.zip
    _version_match = _re.search(r"redcap_v([\d.]+)", Path(target).name)
    redcap_version = _version_match.group(1) if _version_match else ""

    # Output directory — resolve to absolute so results are consistent
    # regardless of the working directory the user launches from.
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(config.output_dir).resolve() / f"scan_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    _print(console, "━━ Step 5: Running full scan ━━", style="bold yellow")
    _print(console, f"  Target:    {target}")
    _print(console, f"  Reference: {reference}")
    _print(console, f"  Output:    {output_dir}\n")

    start = time.time()
    errors: list[str] = []

    # ── Phase A: Evidence Collection ─────────────────────────────────
    _print(console, "[A] Evidence collection...", style="bold cyan")
    try:
        collector = EvidenceCollector(config)
        package = collector.collect(
            source=target,
            output_dir=str(output_dir),
            label=f"REDACTS-scan-{ts}",
            notes="Automated scan via REDACTS interactive workflow",
            progress_callback=lambda step, total, msg: _print(
                console, f"    [{step}/{total}] {msg}", style="dim"
            ),
        )
        if package.success:
            _print(
                console,
                f"    {package.manifest.total_files} files catalogued, "
                f"{sum(1 for e in package.manifest.entries if e.anomalies)} anomalies",
                style="green",
            )
        else:
            msg = f"Evidence collection failed: {'; '.join(package.errors)}"
            errors.append(msg)
            _print(console, f"    {msg}", style="red")
    except Exception as exc:
        errors.append(f"Evidence collection error: {exc}")
        _print(console, f"    ERROR: {exc}", style="red")
        package = None

    _print(console, "")

    # ── Phase B: Baseline Audit ──────────────────────────────────────
    _print(console, "[B] Baseline audit (reference vs target)...", style="bold cyan")
    audit_result = None
    try:
        pipeline = AuditPipeline(config)
        audit_result = pipeline.run(
            reference=reference,
            target=target,
            output_dir=str(output_dir / "audit"),
            run_external_tools=True,
            formats=["html", "json", "markdown"],
            progress_callback=lambda stage, pct: _print(
                console, f"    {stage} ({pct:.0%})", style="dim"
            ),
        )
        if audit_result.success:
            _print(
                console,
                f"    {audit_result.files_modified} modified, "
                f"{audit_result.files_added} added, "
                f"{audit_result.files_removed} removed | "
                f"Risk: {audit_result.overall_risk_level}",
                style="green",
            )
        else:
            msg = f"Audit failed: {'; '.join(audit_result.errors)}"
            errors.append(msg)
            _print(console, f"    {msg}", style="red")
    except Exception as exc:
        errors.append(f"Audit error: {exc}")
        _print(console, f"    ERROR: {exc}", style="red")

    _print(console, "")

    # ── Phase C: Tool Orchestration ──────────────────────────────────
    _print(
        console,
        "[C] Tool orchestration (Semgrep + Trivy + YARA + Magika + tree-sitter)...",
        style="bold cyan",
    )
    orchestrator = None
    try:
        # Determine scan root: use evidence source_root if available,
        # otherwise resolve the target directly
        scan_root = target
        if package and package.source_root:
            scan_root = package.source_root

        orch_config = OrchestratorConfig(
            enable_dast=True,
            redcap_version=redcap_version,
            docker_available=(dep_report.docker_available if dep_report else None),
            docker_compose_available=(
                dep_report.docker_compose_available if dep_report else None
            ),
        )

        # Extract delta set from the baseline audit so that the
        # orchestrator only produces findings on files that actually
        # differ from the clean reference.  This eliminates the ~20 K
        # false-positive noise from scanning stock REDCap code.
        delta_set: set[str] | None = None
        if audit_result and audit_result.baseline_diff:
            raw = audit_result.baseline_diff.get("delta_files")
            if raw:
                delta_set = set(raw)

        orchestrator = ToolOrchestrator(
            target_path=Path(scan_root),
            config=orch_config,
            only_files=delta_set,
            output_dir=output_dir,
        )
        orchestrator.run_all()

        findings = orchestrator.findings
        _print(
            console,
            f"    {len(findings.findings)} findings from "
            f"{len(orchestrator.tool_availability)} tools",
            style="green",
        )

        # Show tool availability
        for tool, available in orchestrator.tool_availability.items():
            status = "OK" if available else "skip"
            _print(console, f"      {tool}: {status}", style="dim")

        # Show suspicious files
        suspicious = orchestrator.get_suspicious_files()
        if suspicious:
            _print(
                console,
                f"    {len(suspicious)} suspicious files (multi-tool corroboration)",
                style="yellow",
            )
            for sf in suspicious[:5]:
                _print(
                    console,
                    f"      {sf['path']} — {sf['source_count']} tools, "
                    f"severity={sf['max_severity']}",
                    style="yellow",
                )

        # Phase timings
        for phase, elapsed in orchestrator.phase_timings.items():
            _print(console, f"      {phase}: {elapsed:.1f}s", style="dim")

    except Exception as exc:
        errors.append(f"Orchestration error: {exc}")
        _print(console, f"    ERROR: {exc}", style="red")

    _print(console, "")

    # Phase D removed — the baseline audit (Phase B) already runs a
    # delta-scoped Investigator.  Running another unscoped Investigator
    # here was the root cause of the ~20 K inflated finding count.
    # The InvestigationReport is now available as
    # audit_result.investigation_report_obj for report generation.

    _print(console, "")

    # ── Phase D: Report Generation ─────────────────────────────────
    _print(console, "[D] Generating reports...", style="bold cyan")
    report_files: list[str] = []

    # Use the investigation report from the baseline audit (Phase B)
    investigation_report = (
        audit_result.investigation_report_obj if audit_result else None
    )

    # Forensic reports (HTML/JSON/Markdown)
    if investigation_report:
        try:
            gen = ForensicReportGenerator()
            report_files.extend(
                gen.generate(
                    investigation=investigation_report,
                    evidence=package,
                    output_dir=str(output_dir),
                    formats=["html", "json", "markdown"],
                    report_title=f"REDACTS Forensic Report — {ts}",
                )
            )
        except Exception as exc:
            errors.append(f"Forensic report error: {exc}")
            _print(console, f"    Forensic report error: {exc}", style="red")

    # SARIF export (from orchestrator findings)
    if orchestrator:
        try:
            sarif = SarifExporter()
            sarif_data = sarif.export(orchestrator.findings)

            sarif_path = output_dir / f"redacts_sarif_{ts}.json"
            import json

            sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
            report_files.append(str(sarif_path))
        except Exception as exc:
            errors.append(f"SARIF export error: {exc}")
            _print(console, f"    SARIF export error: {exc}", style="red")

    elapsed = time.time() - start

    # ── Cleanup: remove bulky temp directories ───────────────────────
    # Evidence staging, reference/target extractions, and orchestrator
    # scratch dirs are only needed during the pipeline.  Reports have
    # already been written, so we can safely remove these.
    import shutil

    cleanup_dirs = [
        output_dir / "_staging",
        output_dir / "audit" / "_ref_extract",
        output_dir / "audit" / "_tgt_extract",
        output_dir / "_orchestrator",
    ]
    cleaned = 0
    for d in cleanup_dirs:
        if d.is_dir():
            try:
                shutil.rmtree(d)
                cleaned += 1
            except Exception as exc:
                logger.debug("Cleanup of %s failed: %s", d, exc)

    if cleaned:
        _print(console, f"  Cleaned up {cleaned} temporary directories", style="dim")

    # ── Summary ──────────────────────────────────────────────────────
    _print(console, "")
    _print(console, "═" * 63, style="bold")

    if not errors:
        _print(
            console,
            f"  Scan complete in {elapsed:.1f}s — no errors",
            style="bold green",
        )
    else:
        _print(
            console,
            f"  Scan finished in {elapsed:.1f}s with {len(errors)} warning(s)",
            style="bold yellow",
        )

    if console and RICH_AVAILABLE:
        # Summary table
        table = Table(title="Scan Summary", show_header=True)
        table.add_column("Phase", style="cyan")
        table.add_column("Result", min_width=40)

        # Evidence
        if package:
            table.add_row(
                "Evidence",
                f"[green]{package.manifest.total_files} files[/green]"
                if package.success
                else "[red]FAILED[/red]",
            )

        # Audit (includes delta-scoped investigation)
        if audit_result:
            if audit_result.success:
                risk = audit_result.overall_risk_level
                risk_style = {
                    "CRITICAL": "bold red",
                    "HIGH": "bold yellow",
                    "MEDIUM": "yellow",
                    "LOW": "cyan",
                    "CLEAN": "bold green",
                }.get(risk, "white")
                table.add_row(
                    "Audit",
                    f"[{risk_style}]{risk}[/{risk_style}] | "
                    f"Δ{audit_result.delta_count} files, "
                    f"{audit_result.deep_scan_findings} findings",
                )
            else:
                table.add_row("Audit", "[red]FAILED[/red]")

        # Orchestrator
        if orchestrator:
            table.add_row(
                "Tool Scan",
                f"[green]{len(orchestrator.findings.findings)} findings[/green]",
            )

        table.add_row("Duration", f"{elapsed:.1f}s")
        console.print(table)
    else:
        print(f"\n  Duration: {elapsed:.1f}s")

    # Report file list
    if report_files:
        _print(console, "\n  Generated reports:", style="bold")
        for rf in report_files:
            _print(console, f"    → {rf}")

    if errors:
        _print(console, "\n  Warnings:", style="bold yellow")
        for err in errors:
            _print(console, f"    ⚠ {err}", style="yellow")

    _print(console, "")
    return 0 if not errors else 1


# ═══════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════


def main() -> int:
    """Interactive one-way REDACTS workflow."""
    # Handle --help
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0

    console = _console()

    # Step 1: Banner
    step_banner(console)

    # Step 2: Check dependencies
    report = step_check_deps(console)

    # Step 3: Auto-install everything missing (pip + system binaries)
    if not step_install_missing(console, report):
        return 1  # Required dependencies still missing after auto-install

    # Step 4: Prompt for target
    target = step_prompt_target(console)

    # Step 5: Prompt for reference
    reference = step_prompt_reference(console)

    # Step 6: Run the full scan
    return step_run_scan(console, target, reference, dep_report=report)


if __name__ == "__main__":
    sys.exit(main())
