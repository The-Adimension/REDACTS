"""Shared SARIF parsing utilities for REDACTS.

Replaces identical ``_extract_sarif_results`` methods on
:class:`SemgrepAdapter` and :class:`TrivyAdapter` (DUP-007) and the
duplicate ``_count_by_severity`` static methods on both adapters
(DUP-008) with canonical free-functions that live outside any adapter.

Design patterns
---------------
* **Strategy** – :func:`extract_location` accepts a *strategy* callback
  (``field_selector``) so each adapter can request the exact location
  fields it cares about without modifying shared code.
* **Plugin registry** – :data:`_SARIF_PROCESSORS` maps processor names to
  callables; new post-parse steps can be registered via
  :func:`register_sarif_processor` without touching existing code.
* **Configuration-driven** – threshold / default values are keyword-only
  arguments (``max_results``, ``default_severity_value``) so callers can
  override them via config objects without forking the implementation.

Backward-compatibility
----------------------
* :func:`extract_sarif_results` returns the same ``list[dict[str, Any]]``
  that both adapters' ``_extract_sarif_results`` produced.
* :func:`count_by_severity` returns the same ``dict[str, int]`` with
  severity *.value* keys.
* :func:`extract_location` is additive — no existing consumer yet.
* :func:`extract_rules` matches ``SemgrepAdapter._extract_rules``.
* :func:`count_files_scanned` matches
  ``SemgrepAdapter._count_files_scanned``.
* This file is purely additive (blast-radius **NONE**).

Addresses
---------
DUP-007 (2 ``_extract_sarif_results``), DUP-008 (2 ``_count_by_severity``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Strategy protocol for location extraction
# ═══════════════════════════════════════════════════════════════════════════

@runtime_checkable
class LocationStrategy(Protocol):
    """Callable that extracts location fields from a SARIF physical-location.

    Implementations decide which fields to keep (e.g. Trivy only needs
    ``file_path`` + ``line_start``; Semgrep wants columns and snippet too).
    """

    def __call__(
        self,
        physical_location: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a flat dict of extracted location fields."""
        ...  # pragma: no cover


# ═══════════════════════════════════════════════════════════════════════════
# Built-in location strategies
# ═══════════════════════════════════════════════════════════════════════════

def full_location(physical_location: dict[str, Any]) -> dict[str, Any]:
    """Extract all location fields (Semgrep-style).

    Returns ``file_path``, ``line_start``, ``line_end``, ``column_start``,
    ``column_end``, and ``snippet``.
    """
    artifact = physical_location.get("artifactLocation", {})
    region = physical_location.get("region", {})
    return {
        "file_path": artifact.get("uri", ""),
        "line_start": region.get("startLine", 0),
        "line_end": region.get("endLine", 0),
        "column_start": region.get("startColumn", 0),
        "column_end": region.get("endColumn", 0),
        "snippet": region.get("snippet", {}).get("text", ""),
    }


def minimal_location(physical_location: dict[str, Any]) -> dict[str, Any]:
    """Extract only ``file_path`` and ``line_start`` (Trivy-style)."""
    artifact = physical_location.get("artifactLocation", {})
    region = physical_location.get("region", {})
    return {
        "file_path": artifact.get("uri", ""),
        "line_start": region.get("startLine", 0),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Plugin registry — post-parse processors
# ═══════════════════════════════════════════════════════════════════════════

SarifProcessor = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
"""Signature for a post-parse processor: takes results, returns results."""

_SARIF_PROCESSORS: dict[str, SarifProcessor] = {}


def register_sarif_processor(name: str, processor: SarifProcessor) -> None:
    """Register a named post-parse processor.

    Processors are applied in registration order by :func:`extract_sarif_results`
    when ``processors`` are requested.

    Parameters
    ----------
    name:
        Unique processor name.
    processor:
        A callable ``(list[dict]) -> list[dict]`` that filters or enriches
        the raw SARIF result list.

    Raises
    ------
    ValueError
        If *name* is already registered (use :func:`replace_sarif_processor`).
    """
    if name in _SARIF_PROCESSORS:
        raise ValueError(
            f"SARIF processor {name!r} already registered; "
            f"use replace_sarif_processor() to overwrite"
        )
    _SARIF_PROCESSORS[name] = processor
    logger.debug("Registered SARIF processor: %s", name)


def replace_sarif_processor(name: str, processor: SarifProcessor) -> None:
    """Replace an existing processor (or register if absent)."""
    _SARIF_PROCESSORS[name] = processor
    logger.debug("Replaced SARIF processor: %s", name)


def get_registered_processors() -> dict[str, SarifProcessor]:
    """Return a *copy* of the processor registry."""
    return dict(_SARIF_PROCESSORS)


# ═══════════════════════════════════════════════════════════════════════════
# DUP-007 — extract_sarif_results (identical on both adapters)
# ═══════════════════════════════════════════════════════════════════════════

def extract_sarif_results(
    sarif: dict[str, Any],
    *,
    max_results: int = 0,
    processors: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Extract result objects from parsed SARIF data.

    This is the canonical replacement for the identical static methods
    ``SemgrepAdapter._extract_sarif_results`` and
    ``TrivyAdapter._extract_sarif_results``.

    Parameters
    ----------
    sarif:
        Parsed SARIF JSON (the top-level object with ``$schema``, ``runs``, …).
    max_results:
        If > 0, stop after collecting this many results (configuration-driven
        cap).  0 means unlimited.
    processors:
        Ordered tuple of registered :data:`_SARIF_PROCESSORS` names to apply
        after extraction.  Unknown names are silently skipped with a warning.

    Returns
    -------
    list[dict[str, Any]]
        Flat list of SARIF ``result`` objects across all runs.
    """
    results: list[dict[str, Any]] = []
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            results.append(r)
            if max_results > 0 and len(results) >= max_results:
                break
        if max_results > 0 and len(results) >= max_results:
            break

    # Apply registered post-processors
    for proc_name in processors:
        proc = _SARIF_PROCESSORS.get(proc_name)
        if proc is None:
            logger.warning("Unknown SARIF processor %r — skipping", proc_name)
            continue
        results = proc(results)

    return results


# ═══════════════════════════════════════════════════════════════════════════
# DUP-008 — count_by_severity (identical on both adapters)
# ═══════════════════════════════════════════════════════════════════════════

def count_by_severity(
    findings: Any,
    *,
    default_severity_value: str = "",
) -> dict[str, int]:
    """Count findings grouped by severity level.

    This is the canonical replacement for the identical static methods
    ``SemgrepAdapter._count_by_severity`` and
    ``TrivyAdapter._count_by_severity``.

    Parameters
    ----------
    findings:
        Iterable of objects with a ``.severity`` attribute that exposes
        a ``.value`` string (i.e. ``UnifiedFinding`` instances).
    default_severity_value:
        Fallback key if ``finding.severity.value`` raises.  Empty string
        means use ``"UNKNOWN"`` as the bucket.

    Returns
    -------
    dict[str, int]
        ``{severity_value: count}`` e.g. ``{"HIGH": 3, "LOW": 1}``.
    """
    counts: dict[str, int] = {}
    fallback = default_severity_value or "UNKNOWN"
    for f in findings:
        try:
            key = f.severity.value
        except AttributeError:
            key = fallback
        counts[key] = counts.get(key, 0) + 1
    return counts


# ═══════════════════════════════════════════════════════════════════════════
# Location extraction — Strategy-based
# ═══════════════════════════════════════════════════════════════════════════

def extract_location(
    result: dict[str, Any],
    *,
    strategy: LocationStrategy | None = None,
) -> dict[str, Any]:
    """Extract location fields from a single SARIF result.

    Parameters
    ----------
    result:
        A single SARIF ``result`` object.
    strategy:
        A :class:`LocationStrategy` callable.  Defaults to
        :func:`full_location`.

    Returns
    -------
    dict[str, Any]
        Flat dict of location fields.  Empty dict if no locations present.
    """
    if strategy is None:
        strategy = full_location

    locations = result.get("locations", [])
    if not locations:
        return {}

    phys = locations[0].get("physicalLocation", {})
    return strategy(phys)


# ═══════════════════════════════════════════════════════════════════════════
# CWE extraction — shared between both adapters
# ═══════════════════════════════════════════════════════════════════════════

def extract_cwe(result: dict[str, Any]) -> str:
    """Extract CWE identifier from a SARIF result.

    Checks the ``taxa`` array first (standard SARIF CWE taxonomy),
    then falls back to ``properties.cwe``.

    Parameters
    ----------
    result:
        A single SARIF ``result`` object.

    Returns
    -------
    str
        CWE identifier (e.g. ``"CWE-89"``) or ``""`` if not found.
    """
    for taxa in result.get("taxa", []):
        component = taxa.get("toolComponent", {}).get("name", "")
        if component.upper() == "CWE":
            taxa_id = taxa.get("id", "")
            if taxa_id:
                return f"CWE-{taxa_id}"
    # Fallback: check properties
    props = result.get("properties", {})
    return props.get("cwe", "")


# ═══════════════════════════════════════════════════════════════════════════
# Rule extraction — from SemgrepAdapter._extract_rules
# ═══════════════════════════════════════════════════════════════════════════

def extract_rules(sarif: dict[str, Any]) -> list[dict[str, str]]:
    """Extract rule definitions from SARIF ``tool.driver.rules``.

    Canonical replacement for ``SemgrepAdapter._extract_rules``.

    Parameters
    ----------
    sarif:
        Parsed SARIF JSON (top-level object).

    Returns
    -------
    list[dict[str, str]]
        Each dict has ``"id"``, ``"name"``, ``"shortDescription"`` keys.
    """
    rules: list[dict[str, str]] = []
    for run in sarif.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []):
            rules.append({
                "id": rule.get("id", ""),
                "name": rule.get("name", ""),
                "shortDescription": (
                    rule.get("shortDescription", {}).get("text", "")
                ),
            })
    return rules


# ═══════════════════════════════════════════════════════════════════════════
# File counting — from SemgrepAdapter._count_files_scanned
# ═══════════════════════════════════════════════════════════════════════════

def count_files_scanned(sarif: dict[str, Any]) -> int:
    """Count unique files referenced in SARIF artifacts and results.

    Canonical replacement for ``SemgrepAdapter._count_files_scanned``.

    Parameters
    ----------
    sarif:
        Parsed SARIF JSON (top-level object).

    Returns
    -------
    int
        Count of unique file URIs.
    """
    files: set[str] = set()
    for run in sarif.get("runs", []):
        for artifact in run.get("artifacts", []):
            uri = artifact.get("location", {}).get("uri", "")
            if uri:
                files.add(uri)
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                uri = (
                    loc.get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri", "")
                )
                if uri:
                    files.add(uri)
    return len(files)


# ═══════════════════════════════════════════════════════════════════════════
# Execution-error extraction — from SemgrepAdapter.run
# ═══════════════════════════════════════════════════════════════════════════

def extract_execution_errors(sarif: dict[str, Any]) -> list[str]:
    """Extract tool execution error messages from SARIF invocations.

    Looks in ``runs[*].invocations[*].toolExecutionNotifications[*].message.text``.

    Parameters
    ----------
    sarif:
        Parsed SARIF JSON (top-level object).

    Returns
    -------
    list[str]
        Error messages; empty list if none found.
    """
    errors: list[str] = []
    for run in sarif.get("runs", []):
        for inv in run.get("invocations", []):
            for note in inv.get("toolExecutionNotifications", []):
                msg = note.get("message", {}).get("text", "")
                if msg:
                    errors.append(msg)
    return errors


# ═══════════════════════════════════════════════════════════════════════════
# Convenience: load + extract in one call
# ═══════════════════════════════════════════════════════════════════════════

def load_sarif_file(
    path: Path,
    *,
    max_results: int = 0,
    processors: tuple[str, ...] = (),
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read a SARIF JSON file and extract results.

    Parameters
    ----------
    path:
        Path to ``.sarif`` / ``.json`` file.
    max_results:
        Forwarded to :func:`extract_sarif_results`.
    processors:
        Forwarded to :func:`extract_sarif_results`.

    Returns
    -------
    tuple[dict, list[dict]]
        ``(sarif_root, results)`` — the raw parsed SARIF and the extracted
        result list.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    json.JSONDecodeError
        If the file content is not valid JSON.
    """
    sarif = json.loads(path.read_text(encoding="utf-8"))
    results = extract_sarif_results(
        sarif, max_results=max_results, processors=processors
    )
    return sarif, results
