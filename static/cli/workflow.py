"""CLI scan workflow - splits the pipeline into ``_phase_*`` functions.

``step_run_scan`` reads top-to-bottom as a sequence of phase calls;
the phases themselves live here. The split is for readability and
testability, not extensibility - phase order is fixed and reflects
data dependencies (collect -> analyse -> audit -> report).

Known limits:

    * Phases are not transactional. If the analyse phase fails after
      collect has written to the output directory, the partial
      output is left behind and the next run will refuse to overwrite
      unless ``--force`` is passed. This is deliberate - partial
      evidence is preserved for review rather than auto-cleaned.
    * Signal handling is best-effort: ``atexit`` and ``signal``
      hooks flush in-flight artefacts on SIGINT, but a SIGKILL or a
      power loss will still strand the run. The audit phase recovers
      by recomputing manifests on the next invocation.
"""

from __future__ import annotations

import atexit
import json
import logging
import os as _os
import re as _re
import shutil
import signal
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from ._console import RICH_AVAILABLE, cli_print

if TYPE_CHECKING:
    from collections.abc import Callable

    from rich.console import Console
    from .dependencies import DependencyReport

logger = logging.getLogger(__name__)


# Tool-backed scanners selectable via ``[static].scanners``. ``regex`` needs no
# external tool; the rest are gated on availability as well as selection.
KNOWN_SCANNERS: frozenset[str] = frozenset({"regex", "yara", "trivy", "semgrep"})


def select_scanners(
    selected: "tuple[str, ...] | None",
    tool_ok: "Callable[[str], bool]",
) -> "tuple[dict[str, bool], list[tuple[str, bool]]]":
    """Decide which scanners run, honoring the contract's selection.

    A tool-backed scanner (semgrep/trivy/yara) runs iff it is **both** selected
    in ``[static].scanners`` **and** installed. ``regex`` needs only selection.
    This mirrors how ``[static].severity_gate`` is treated: the contract is the
    source of truth, not merely "whatever happens to be installed".

    Args:
        selected: Scanner names from the contract, or ``None`` when no contract
            is installed (fall back to "run whatever is installed").
        tool_ok: ``callable(name) -> bool`` reporting whether a tool is present.

    Returns:
        ``(enables, notices)`` where ``enables`` maps
        ``semgrep``/``trivy``/``yara``/``regex`` to booleans, and ``notices`` is
        a list of ``(message, is_gap)`` pairs: ``is_gap`` marks a real coverage
        loss (selected-but-missing, or an unknown scanner name) versus an
        informational skip (installed-but-not-selected).
    """
    chosen = None if selected is None else {s.strip().lower() for s in selected}
    notices: list[tuple[str, bool]] = []

    def _enabled(name: str) -> bool:
        installed = tool_ok(name)
        if chosen is None:
            return installed
        is_selected = name in chosen
        if is_selected and not installed:
            notices.append(
                (
                    f"{name}: selected in [static].scanners but not installed "
                    "- skipped (no coverage from this scanner)",
                    True,
                )
            )
        elif installed and not is_selected:
            notices.append(
                (
                    f"{name}: installed but not selected in [static].scanners "
                    "- skipped by choice",
                    False,
                )
            )
        return is_selected and installed

    enables = {
        "semgrep": _enabled("semgrep"),
        "trivy": _enabled("trivy"),
        "yara": _enabled("yara"),
        "regex": chosen is None or "regex" in chosen,
    }

    # Surface names the contract lists but REDACTS does not recognise, so a
    # typo cannot silently reduce coverage.
    if chosen is not None:
        for name in sorted(chosen - KNOWN_SCANNERS):
            notices.append(
                (f"unknown scanner '{name}' in [static].scanners - ignored", True)
            )

    return enables, notices


def _severity_rank(sev: "str | object | None") -> "int | None":
    """Best-effort numeric rank for a severity value from any layer.

    Accepts a ``SeverityLevel`` (uses its ``numeric_rank``) or a string
    (parsed via ``SeverityLevel.from_string``). Returns ``None`` for values
    that are not real severities - notably ``"CLEAN"`` and empty/unknown
    strings - so they never trip the gate.
    """
    from ..core.findings import SeverityLevel

    if sev is None:
        return None
    rank = getattr(sev, "numeric_rank", None)
    if isinstance(rank, int):
        return rank
    try:
        return SeverityLevel.from_string(str(sev)).numeric_rank
    except (ValueError, AttributeError):
        return None


def evaluate_severity_gate(
    gate: str,
    *,
    orchestrator_findings: "object | None" = None,
    investigation_findings: "object | None" = None,
    baseline_findings: "object | None" = None,
    overall_risk: "str | None" = None,
) -> "tuple[bool, dict[str, int]]":
    """Decide whether the scan trips the ``[static].severity_gate``.

    The gate must reflect **every** analysis layer, not just the tool scan.
    A forensic finding (investigation), a structural change (baseline), or a
    holistic CRITICAL/HIGH verdict (``overall_risk``) must be able to fail CI
    just as a tool-scan finding does - otherwise a compromised deployment can
    exit 0. See the severity-gate regression this closes.

    Args:
        gate: The configured gate level (e.g. ``"high"``).
        orchestrator_findings: Iterable of tool-scan findings (objects with a
            ``.severity`` carrying ``.numeric_rank``).
        investigation_findings: Iterable of investigation finding dicts, each
            with a ``"severity"`` string.
        baseline_findings: Iterable of baseline structural finding dicts, each
            with a ``"severity"`` string.
        overall_risk: The audit's holistic risk level string, or ``None``.

    Returns:
        ``(triggered, breakdown)`` - ``triggered`` is ``True`` if any source
        has a finding at or above the gate, or ``overall_risk`` is at or above
        it. ``breakdown`` maps each contributing source to its count (findings)
        or ``1`` (overall_risk), for a transparent message. Empty breakdown
        means nothing tripped.

    Raises:
        ValueError: If *gate* is not a valid severity level.
    """
    from ..core.findings import SeverityLevel

    gate_rank = SeverityLevel.from_string(gate).numeric_rank
    breakdown: dict[str, int] = {}

    def _count(findings: "object | None", severity_of) -> int:
        if not findings:
            return 0
        n = 0
        for f in findings:
            rank = severity_of(f)
            if rank is not None and rank >= gate_rank:
                n += 1
        return n

    tool_n = _count(
        orchestrator_findings, lambda f: _severity_rank(getattr(f, "severity", None))
    )
    inv_n = _count(
        investigation_findings, lambda f: _severity_rank(f.get("severity"))
    )
    base_n = _count(
        baseline_findings, lambda f: _severity_rank(f.get("severity"))
    )

    if tool_n:
        breakdown["tool-scan"] = tool_n
    if inv_n:
        breakdown["investigation"] = inv_n
    if base_n:
        breakdown["baseline"] = base_n

    risk_rank = _severity_rank(overall_risk)
    if risk_rank is not None and risk_rank >= gate_rank:
        breakdown["overall-risk"] = 1

    return (bool(breakdown), breakdown)


def _phase_evidence(
    console: "Console" | None,
    config: object,
    target: str,
    output_dir: Path,
    ts: str,
) -> tuple[object | None, list[str]]:
    """Collect and catalogue evidence from the target.

    Returns ``(package, errors)`` - *package* is ``None`` on failure.
    """
    from ..collect.collector import EvidenceCollector

    cli_print(console, "[A] Evidence collection...", style="bold cyan")
    errors: list[str] = []
    package = None

    try:
        collector = EvidenceCollector(config)
        package = collector.collect(
            source=target,
            output_dir=str(output_dir),
            label=f"REDACTS-scan-{ts}",
            notes="Automated scan via REDACTS",
            progress_callback=lambda step, total, msg: cli_print(
                console, f"    [{step}/{total}] {msg}", style="dim"
            ),
        )
        if package.success:
            cli_print(
                console,
                f"    {package.manifest.total_files} files catalogued, "
                f"{package.anomalies.total_anomalies} anomalies",
                style="green",
            )
        else:
            msg = f"Evidence collection failed: {'; '.join(package.errors)}"
            errors.append(msg)
            cli_print(console, f"    {msg}", style="red")
    except Exception as exc:
        errors.append(f"Evidence collection error: {exc}")
        cli_print(console, f"    ERROR: {exc}", style="red")

    cli_print(console, "")
    return package, errors




def _phase_audit(
    console: "Console" | None,
    config: object,
    target: str,
    reference: str,
    output_dir: Path,
    check_deadline: object,
) -> tuple[object | None, list[str]]:
    """Run baseline audit comparing reference to target.

    Returns ``(audit_result, errors)``.
    """
    from ..audit.pipeline import AuditPipeline

    check_deadline("before_audit")
    cli_print(console, "[B] Baseline audit (reference vs target)...", style="bold cyan")
    errors: list[str] = []
    audit_result = None

    try:
        pipeline = AuditPipeline(config)
        audit_result = pipeline.run(
            reference=reference,
            target=target,
            output_dir=str(output_dir / "audit"),
            run_external_tools=True,
            formats=["html", "json", "markdown"],
            progress_callback=lambda stage, pct: cli_print(
                console, f"    {stage} ({pct:.0%})", style="dim"
            ),
        )
        if audit_result.success:
            cli_print(
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
            cli_print(console, f"    {msg}", style="red")
    except Exception as exc:
        errors.append(f"Audit error: {exc}")
        cli_print(console, f"    ERROR: {exc}", style="red")

    cli_print(console, "")
    return audit_result, errors




def _phase_orchestration(
    console: "Console" | None,
    config: object,
    target: str,
    output_dir: Path,
    package: object | None,
    audit_result: object | None,
    dep_report: "DependencyReport" | None,
    redcap_version: str,
    check_deadline: object,
) -> tuple[object | None, list[str], list[str]]:
    """Run all external tools (Semgrep, Trivy, YARA, Magika, tree-sitter).

    Returns ``(orchestrator, errors, runtime_gaps)``.
    """
    from ..scanners.orchestrator import ToolOrchestrator, OrchestratorConfig

    check_deadline("before_orchestration")
    cli_print(
        console,
        "[C] Tool orchestration (Semgrep + Trivy + YARA + Magika + tree-sitter)...",
        style="bold cyan",
    )
    errors: list[str] = []
    runtime_gaps: list[str] = []
    orchestrator = None

    try:
        scan_root = target
        if package and package.source_root:
            scan_root = package.source_root

        def _tool_ok(name: str) -> bool:
            if not dep_report:
                return True
            return any(c.available for c in dep_report.checks if c.name == name)

        # Honor the contract's ``[static].scanners`` selection. The contract
        # is the source of truth (exactly as ``[static].severity_gate`` is):
        # a tool-backed scanner runs only if it is BOTH selected in the
        # contract AND installed. Previously enablement came only from "is it
        # installed", so the analyst's scanner selection was silently ignored.
        from ..core.runtime_context import get_optional_contract

        _contract = get_optional_contract()
        selected = (
            tuple(_contract.static.scanners) if _contract is not None else None
        )
        enables, notices = select_scanners(selected, _tool_ok)
        for message, is_gap in notices:
            cli_print(
                console,
                f"  {'!' if is_gap else '-'} {message}",
                style="yellow" if is_gap else "dim",
            )
            if is_gap:
                runtime_gaps.append(message)

        # DAST is gated by the case contract's ``[dynamic].enabled``
        # flag, which ``REDACTSConfig.from_contract`` projects onto
        # ``config.dast.enabled``. Hard-coding ``True`` here would
        # silently ignore the contract and cause Phase C to attempt
        # docker-compose even when the analyst opted into a
        # static-only run --- exactly the kind of "looked OK but ran
        # something the analyst said no to" failure the contract is
        # supposed to prevent.
        orch_config = OrchestratorConfig(
            enable_semgrep=enables["semgrep"],
            enable_trivy=enables["trivy"],
            enable_yara=enables["yara"],
            enable_regex_scanner=enables["regex"],
            enable_dast=bool(config.dast.enabled),
            redcap_version=redcap_version,
            dast_package=str(target),
            docker_available=(dep_report.docker_available if dep_report else None),
            docker_compose_available=(
                dep_report.docker_compose_available if dep_report else None
            ),
        )

        delta_set: set[str] | None = None
        if audit_result and audit_result.baseline_diff:
            raw = audit_result.baseline_diff.get("delta_files")
            # Explicit empty set when audit ran but found zero deltas,
            # so the orchestrator scans nothing instead of falling
            # back to the full corpus.
            delta_set = set(raw) if raw else set()

        orchestrator = ToolOrchestrator(
            target_path=Path(scan_root),
            config=orch_config,
            only_files=delta_set,
            output_dir=output_dir,
            max_file_size_mb=config.analysis.max_file_size_mb,
        )
        orchestrator.run_all()

        findings = orchestrator.findings
        cli_print(
            console,
            f"    {len(findings.findings)} findings from "
            f"{len(orchestrator.tool_availability)} tools",
            style="green",
        )

        # Set of tool names whose phase recorded a runtime failure.
        # We use this to distinguish "tool was never installed"
        # (SKIPPED) from "tool ran and failed" (FAILED) in the
        # per-tool status line --- a tool reporting OK because it was
        # detected at startup, while the run actually crashed mid-
        # phase, is the same dishonest-summary failure mode the
        # workflow's error pipeline guards against.
        failed_phases = {name for name, _ in orchestrator.phase_failures}

        for tool, available in orchestrator.tool_availability.items():
            if tool in failed_phases:
                cli_print(
                    console,
                    f"      {tool}: FAILED  (runtime error - see logs above)",
                    style="red",
                )
                runtime_gaps.append(f"REDUCED COVERAGE: {tool} failed at runtime")
            elif available:
                cli_print(console, f"      {tool}: OK", style="dim")
            else:
                cli_print(
                    console,
                    f"      {tool}: SKIPPED !  (unavailable at runtime)",
                    style="yellow",
                )
                runtime_gaps.append(f"REDUCED COVERAGE: {tool} unavailable at runtime")

        suspicious = orchestrator.get_suspicious_files()
        if suspicious:
            cli_print(
                console,
                f"    {len(suspicious)} suspicious files (multi-tool corroboration)",
                style="yellow",
            )
            for sf in suspicious[:5]:
                cli_print(
                    console,
                    f"      {sf['path']} - {sf['source_count']} tools, "
                    f"severity={sf['max_severity']}",
                    style="yellow",
                )

        for phase, elapsed in orchestrator.phase_timings.items():
            cli_print(console, f"      {phase}: {elapsed:.1f}s", style="dim")

        # Surface in-phase exceptions that the orchestrator captured
        # into ``phase_failures`` so the run exits non-zero.
        for phase_name, exc_repr in orchestrator.phase_failures:
            msg = f"Phase '{phase_name}' raised: {exc_repr}"
            errors.append(msg)
            cli_print(console, f"    ERROR: {msg}", style="red")

    except Exception as exc:
        errors.append(f"Orchestration error: {exc}")
        cli_print(console, f"    ERROR: {exc}", style="red")

    cli_print(console, "")
    return orchestrator, errors, runtime_gaps




def _phase_reports(
    console: "Console" | None,
    output_dir: Path,
    ts: str,
    target: str,
    reference: str,
    orchestrator: object | None,
    audit_result: object | None,
    package: object | None,
    coverage_notes: list[str],
    runtime_gaps: list[str],
    *,
    pipeline_started_iso: str | None = None,
) -> tuple[list[str], list[str]]:
    """Generate HTML/JSON/Markdown/SARIF reports.

    Returns ``(report_files, errors)``.
    """
    from ..report.generator import ForensicReportGenerator
    from ..report.sarif_exporter import SarifExporter
    from ..collect.provenance import compute_provenance

    cli_print(console, "[D] Generating reports...", style="bold cyan")
    report_files: list[str] = []
    errors: list[str] = []

    # Merge coverage notes with runtime gaps (deduplicated)
    all_gaps: list[str] = list(coverage_notes or [])
    if orchestrator:
        existing = set(all_gaps)
        for gap in runtime_gaps:
            if gap not in existing:
                all_gaps.append(gap)

    # Drop the "repomix unavailable" coverage gap when the evidence
    # collector actually produced a repomix snapshot. A phase may flag
    # repomix as unavailable while the collector still wrote a snapshot
    # (via the repomix Python package) earlier in the run - keeping both
    # the gap and the artifact in the same output dir is self-contradictory.
    repomix_artifact = ""
    if package is not None:
        repomix_artifact = str(getattr(package, "repomix_path", "") or "")
    if repomix_artifact and Path(repomix_artifact).is_file():
        all_gaps = [
            g for g in all_gaps
            if "repomix" not in g.lower()
        ]

    provenance = compute_provenance(
        target_path=target,
        reference_path=reference,
        tool_versions=(orchestrator.findings.tool_versions if orchestrator else {}),
        scan_started=(
            # Prefer the true pipeline start time (workflow entry) over
            # the orchestrator-phase start so report consumers see the
            # whole run wall-clock, not just the tool-scan slice.
            pipeline_started_iso
            or (
                orchestrator.findings.scan_started
                if orchestrator
                else datetime.now().isoformat()
            )
        ),
        coverage_gaps=all_gaps,
    )
    provenance.scan_completed = datetime.now().isoformat()

    investigation_report = (
        audit_result.investigation_report_obj if audit_result else None
    )

    if investigation_report:
        try:
            gen = ForensicReportGenerator()
            report_files.extend(
                gen.generate(
                    investigation=investigation_report,
                    evidence=package,
                    output_dir=str(output_dir),
                    formats=["html", "json", "markdown"],
                    report_title=f"REDACTS Forensic Report - {ts}",
                    provenance=provenance,
                )
            )
        except Exception as exc:
            errors.append(f"Forensic report error: {exc}")
            cli_print(console, f"    Forensic report error: {exc}", style="red")

    if orchestrator:
        try:
            sarif = SarifExporter()
            sarif_data = sarif.export(orchestrator.findings, provenance=provenance)
            sarif_path = output_dir / f"redacts_sarif_{ts}.json"
            sarif_path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
            report_files.append(str(sarif_path))
        except Exception as exc:
            errors.append(f"SARIF export error: {exc}")
            cli_print(console, f"    SARIF export error: {exc}", style="red")

    return report_files, errors




def _phase_cleanup(console: "Console" | None, output_dir: Path) -> None:
    """Remove bulky transient directories that are no longer needed."""
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
            except OSError as exc:
                # Forensic invariant: if we cannot remove an extracted source
                # tree, the operator must know about it. PHI may persist on
                # disk and the scan host is no longer in a clean state.
                logger.warning("Residue not removed: %s \u2014 %s", d, exc)
    if cleaned:
        cli_print(console, f"  Cleaned up {cleaned} transient directories", style="dim")


def _register_cleanup(output_dir: Path) -> None:
    """Wire cleanup of *output_dir* into atexit and signal handlers.

    Forensic invariant: extracted REDCap source trees (``_ref_extract``,
    ``_tgt_extract``) must not survive the process. atexit covers normal
    exit and uncaught exceptions; SIGINT/SIGTERM cover operator Ctrl-C
    and container shutdown. Signal handler installation is best-effort;
    on Windows or when called from a non-main thread some signals are
    not available, in which case atexit alone carries the invariant.
    """
    def _cleanup() -> None:
        with suppress(Exception):
            _phase_cleanup(None, output_dir)

    atexit.register(_cleanup)

    def _on_signal(signum: int, _frame) -> None:
        _cleanup()
        # Restore default disposition and re-raise so the process exits
        # with the conventional 128+signum status that wrappers expect.
        with suppress(ValueError, OSError):
            signal.signal(signum, signal.SIG_DFL)
        _os.kill(_os.getpid(), signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(ValueError, OSError, AttributeError):
            signal.signal(sig, _on_signal)




def _print_summary(
    console: "Console" | None,
    elapsed: float,
    errors: list[str],
    package: object | None,
    audit_result: object | None,
    orchestrator: object | None,
    report_files: list[str],
) -> None:
    """Render the final scan summary to the terminal."""
    cli_print(console, "")
    cli_print(console, "=" * 63, style="bold")

    if not errors:
        cli_print(
            console,
            f"  Scan complete in {elapsed:.1f}s - no errors",
            style="bold green",
        )
    else:
        cli_print(
            console,
            f"  Scan finished in {elapsed:.1f}s with {len(errors)} warning(s)",
            style="bold yellow",
        )

    if console and RICH_AVAILABLE:
        from rich.table import Table

        table = Table(title="Scan Summary", show_header=True)
        table.add_column("Phase", style="cyan")
        table.add_column("Result", min_width=40)

        if package:
            table.add_row(
                "Evidence",
                f"[green]{package.manifest.total_files} files[/green]"
                if package.success
                else "[red]FAILED[/red]",
            )

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
                delta_n = audit_result.delta_count
                finding_n = audit_result.deep_scan_findings
                table.add_row(
                    "Audit",
                    f"[{risk_style}]{risk}[/{risk_style}] | "
                    f"Delta {delta_n} file{'' if delta_n == 1 else 's'}, "
                    f"{finding_n} finding{'' if finding_n == 1 else 's'}",
                )
            else:
                table.add_row("Audit", "[red]FAILED[/red]")

        if orchestrator:
            tool_count = len(orchestrator.findings.findings)
            table.add_row(
                "Tool Scan",
                f"[green]{tool_count} findings[/green]",
            )
            # Render a combined total alongside the per-stream counts
            # so a user reading the banner does not believe the
            # tool-scan count is the entire run's finding count.
            audit_count = (
                getattr(audit_result, "deep_scan_findings", 0) or 0
                if audit_result and getattr(audit_result, "success", False)
                else 0
            )
            combined = audit_count + tool_count
            if audit_count:
                table.add_row(
                    "Combined",
                    f"[bold]{combined}[/bold] total "
                    f"({audit_count} forensic + {tool_count} tool)",
                )

        table.add_row("Duration", f"{elapsed:.1f}s")
        console.print(table)
    else:
        print(f"\n  Duration: {elapsed:.1f}s")

    if report_files:
        cli_print(console, "\n  Generated reports:", style="bold")
        for rf in report_files:
            cli_print(console, f"    -> {rf}")

    if errors:
        cli_print(console, "\n  Warnings:", style="bold yellow")
        for err in errors:
            cli_print(console, f"    ! {err}", style="yellow")

    cli_print(console, "")




def step_run_scan(
    console: "Console" | None,
    target: str,
    reference: str,
    dep_report: "DependencyReport" | None = None,
    coverage_notes: list[str] | None = None,
) -> int:
    """Execute the complete REDACTS scan workflow.

    Phases:
        A. Evidence collection (Tier 1)
        B. Baseline audit (reference vs target) + delta-scoped investigation
        C. Tool orchestration - delta-aware (Semgrep + Trivy + YARA + Magika + tree-sitter)
        D. Report generation (HTML + JSON + Markdown + SARIF)

    All configuration flows through the ``FrozenCaseContract`` installed
    on :mod:`static.core.runtime_context` by ``main.py``.
    """
    from ..core import REDACTSConfig, setup_logging
    from ..core.runtime_context import get_optional_contract

    _frozen = get_optional_contract()
    config = REDACTSConfig.from_contract(_frozen) if _frozen is not None else REDACTSConfig()
    setup_logging(config.log_level)

    # Global timeout watchdog
    _scan_deadline = time.monotonic() + config.global_timeout_seconds
    _timed_out = False

    def _check_deadline(stage: str) -> None:
        nonlocal _timed_out
        if time.monotonic() > _scan_deadline:
            _timed_out = True
            raise TimeoutError(
                f"Global scan timeout ({config.global_timeout_seconds}s) exceeded "
                f"during '{stage}'. Partial results may be available in the output directory."
            )

    # Extract REDCap version from target filename
    _version_match = _re.search(r"redcap_v([\d.]+)", Path(target).name)
    redcap_version = _version_match.group(1) if _version_match else ""

    # Output directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(config.output_dir).resolve() / f"scan_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Register cleanup before any extraction work. If audit extraction crashes
    # halfway through unzipping the target, atexit still fires and the
    # half-extracted tree gets removed.
    _register_cleanup(output_dir)

    cli_print(console, "Running full scan", style="bold yellow")
    cli_print(console, f"  Target:    {target}")
    cli_print(console, f"  Reference: {reference}")
    cli_print(console, f"  Output:    {output_dir}")
    cli_print(
        console,
        f"  Timeout:   {config.global_timeout_seconds}s | "
        f"Max files: {config.analysis.max_total_files:,}\n",
        style="dim",
    )

    start = time.time()
    # Capture the true pipeline start (workflow entry) so the forensic
    # report's `Scan Started` provenance reflects the whole run rather
    # than the orchestrator phase only.
    pipeline_started_iso = datetime.now().astimezone().isoformat()
    all_errors: list[str] = []
    package = None
    audit_result = None
    orchestrator = None
    report_files: list[str] = []

    def _run_phase(name: str, fn):
        return fn()

    try:
        # Phase A
        def _a():
            return _phase_evidence(console, config, target, output_dir, ts)
        package, errs = _run_phase("evidence", _a)
        all_errors.extend(errs)

        # Phase B
        def _b():
            return _phase_audit(
                console, config, target, reference, output_dir, _check_deadline,
            )
        audit_result, errs = _run_phase("audit", _b)
        all_errors.extend(errs)

        # Phase C
        def _c():
            return _phase_orchestration(
                console, config, target, output_dir, package, audit_result,
                dep_report, redcap_version, _check_deadline,
            )
        orchestrator, errs, runtime_gaps = _run_phase("scan", _c)
        all_errors.extend(errs)

        cli_print(console, "")

        # Report output
        def _d():
            return _phase_reports(
                console, output_dir, ts, target, reference,
                orchestrator, audit_result, package,
                coverage_notes or [], runtime_gaps,
                pipeline_started_iso=pipeline_started_iso,
            )
        report_files, errs = _run_phase("report", _d)
        all_errors.extend(errs)
    finally:
        # The atexit hook also runs this, but doing it here keeps the
        # console output ordered ("Cleaned up N" prints before summary)
        # and lets us free disk before _print_summary walks reports.
        _phase_cleanup(console, output_dir)

    elapsed = time.time() - start

    # Summary
    _print_summary(
        console, elapsed, all_errors, package, audit_result, orchestrator, report_files,
    )

    # Exit-code policy:
    # The historical policy ("0 if no errors else 1") meant a clean run
    # with 50 HIGH-severity findings exited 0 - silently passing CI.
    # The contract's ``[static].severity_gate`` gates the exit code. The gate
    # spans EVERY analysis layer - tool scan, deep investigation, baseline
    # structural changes, and the holistic risk verdict - so a compromised
    # deployment cannot exit 0 just because the tool-scan layer was empty:
    #
    #   * Any phase-level error                          -> exit 1
    #   * Any finding (any layer) >= gate, or risk >= gate -> exit 2
    #   * Otherwise                                       -> exit 0
    #
    # Exit 2 is distinct from exit 1 so CI can tell "the scan worked
    # and found real issues" apart from "the scan itself broke".
    exit_code = 0 if not all_errors else 1

    try:
        from ..core.runtime_context import get_optional_contract

        contract = get_optional_contract()
        gate_str = (
            (contract.static.severity_gate or "").strip().lower()
            if contract is not None
            else ""
        )
        if gate_str:
            inv = (audit_result.investigation or {}) if audit_result else {}
            base = (audit_result.baseline_diff or {}) if audit_result else {}
            try:
                triggered, breakdown = evaluate_severity_gate(
                    gate_str,
                    orchestrator_findings=(
                        orchestrator.findings.findings if orchestrator else None
                    ),
                    investigation_findings=inv.get("findings"),
                    baseline_findings=base.get("findings"),
                    overall_risk=(
                        audit_result.overall_risk_level if audit_result else None
                    ),
                )
            except ValueError:
                logger.warning(
                    "Invalid severity_gate %r in contract - skipping enforcement.",
                    gate_str,
                )
                triggered, breakdown = False, {}

            if triggered:
                detail = ", ".join(f"{src}: {n}" for src, n in breakdown.items())
                cli_print(
                    console,
                    f"  Severity gate '{gate_str}' triggered [{detail}].",
                    style="bold red",
                )
                # Gate trumps "no errors -> 0" but does not downgrade an
                # existing phase-level failure.
                exit_code = max(exit_code, 2)
    except Exception:  # pragma: no cover - gate evaluation must never
        # itself crash the CLI; log and fall back to phase-error policy.
        logger.exception("Severity-gate evaluation failed")

    return exit_code
