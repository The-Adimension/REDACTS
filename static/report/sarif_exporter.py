"""
REDACTS SARIF Exporter - SARIF v2.1.0 compliant export.

Converts a FindingCollection into a SARIF v2.1.0 log for CI/CD
platform ingestion (GitHub Code Scanning, Azure DevOps, GitLab SAST).

Each UnifiedFinding already knows how to render itself as a SARIF result
via ``to_sarif_result()``.  This module wraps those individual results
into a complete SARIF log with tool metadata, taxonomies, and provenance.

CI/CD Compliance Features:
    - Rule hydration from YAML knowledge bases (SEC* rules get full descriptions)
    - ``%SRCROOT%`` uriBaseId for strict relative URIs
    - MITRE ATT&CK TXXXX tags in rule properties for GitHub security badges
    - CWE + ATT&CK dual taxonomy injection
    - Full ProvenanceData serialization with ATT&CK disclaimer

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.findings import FindingCollection

logger = logging.getLogger(__name__)

# SARIF v2.1.0 - canonical OASIS JSON schema
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Tool identity
_TOOL_NAME = "REDACTS"
_TOOL_FULL_NAME = "REDACTS - REDCap Arbitrary Code Threat Scan"
_TOOL_INFO_URI = "https://github.com/The-Adimension/REDACTS"


class SarifExporter:
    """Export a FindingCollection to SARIF v2.1.0 format.

    CI/CD compliance enhancements:
        1. Rule hydration from YAML knowledge bases
        2. ``%SRCROOT%`` uriBaseId with ``originalUriBaseIds``
        3. MITRE ATT&CK TXXXX tags for GitHub security badges
        4. CWE + ATT&CK dual taxonomy
        5. Full provenance property bag with disclaimer
    """

    def export(
        self,
        findings: FindingCollection,
        provenance: "ProvenanceData | None" = None,
        *,
        source_root: str = "",
    ) -> dict[str, Any]:
        """Convert a FindingCollection to a complete SARIF log dict.

        Args:
            findings: The unified finding collection from ToolOrchestrator.
            provenance: Optional provenance record to embed in the log.
            source_root: Absolute path to the scan root (used to define
                ``%SRCROOT%`` in ``originalUriBaseIds``).

        Returns:
            A dict representing a valid SARIF v2.1.0 log.
        """
        results = [f.to_sarif_result() for f in findings.findings]

        # Hydrated rules - enriched from YAML + MITRE mapping
        rules = self._build_rules(findings)

        # Build tool component descriptors for each integrated tool
        tool_components = self._build_tool_components(findings)

        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "fullName": _TOOL_FULL_NAME,
                    "informationUri": _TOOL_INFO_URI,
                    "version": self._get_redacts_version(),
                    "rules": rules,
                },
            },
            "results": results,
            "invocations": [
                {
                    "executionSuccessful": True,
                    "startTimeUtc": findings.scan_started,
                    "endTimeUtc": findings.scan_completed
                    or datetime.now(timezone.utc).isoformat(),
                }
            ],
        }

        # %SRCROOT% definition - tells consumers what the base URI is
        uri_base: dict[str, Any] = {"uri": ""}
        if source_root:
            uri_base["uri"] = Path(source_root).as_posix().rstrip("/") + "/"
        run["originalUriBaseIds"] = {"%SRCROOT%": uri_base}

        # Add tool extensions (sub-tools) if present
        if tool_components:
            run["tool"]["extensions"] = tool_components

        # Taxonomies: CWE + ATT&CK
        taxonomies: list[dict[str, Any]] = []
        cwe_taxa = self._build_cwe_taxonomy(findings)
        if cwe_taxa:
            taxonomies.append({
                "name": "CWE",
                "version": "4.16",
                "informationUri": "https://cwe.mitre.org/",
                "taxa": cwe_taxa,
            })

        attack_taxa = self._build_attack_taxonomy(findings)
        if attack_taxa:
            taxonomies.append({
                "name": "MITRE ATT&CK",
                "version": "14.1",
                "informationUri": "https://attack.mitre.org/",
                "taxa": attack_taxa,
            })

        if taxonomies:
            run["taxonomies"] = taxonomies

        # Provenance property bag
        prov_data: dict[str, Any] = {
            "target_path": findings.target_path,
            "baseline_path": findings.baseline_path,
            "tool_versions": findings.tool_versions,
            "scan_started": findings.scan_started,
            "scan_completed": findings.scan_completed
            or datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings.findings),
            "severity_counts": findings.severity_counts,
        }

        if provenance:
            prov_data.update(provenance.to_dict())

        # Per-tool decomposition index. The consolidated
        # ``runs[0]`` shape is preserved for existing
        # SARIF consumers (GitHub Code Scanning, Azure DevOps), but we
        # additionally publish a ``redacts:tool_decomposition`` map so
        # downstream tooling can split findings by originating scanner
        # (trivy, yara, regex_scanner, tree_sitter, sensitive_data, ...)
        # without scanning every result's ``properties.source`` field.
        tool_decomposition = self._build_tool_decomposition(findings)

        run["properties"] = {
            "redacts:provenance": prov_data,
            "redacts:tool_decomposition": tool_decomposition,
        }

        sarif_log: dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [run],
        }

        return sarif_log

    @staticmethod
    def _build_tool_decomposition(
        findings: FindingCollection,
    ) -> dict[str, Any]:
        """Group findings by originating scanner for SARIF consumers.

        Returns a mapping ``{tool_name: {count, severity_counts, rule_ids,
        result_indices}}`` that mirrors the per-tool counts shown in the
        CLI orchestrator summary so SARIF consumers can split, filter,
        and badge results without recomputing the index.
        """
        decomposition: dict[str, dict[str, Any]] = {}
        for idx, f in enumerate(findings.findings):
            tool = f.source.value
            entry = decomposition.setdefault(
                tool,
                {
                    "count": 0,
                    "severity_counts": {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                    "rule_ids": [],
                    "result_indices": [],
                },
            )
            entry["count"] += 1
            sev_key = f.severity.value
            if sev_key in entry["severity_counts"]:
                entry["severity_counts"][sev_key] += 1
            if f.rule_id and f.rule_id not in entry["rule_ids"]:
                entry["rule_ids"].append(f.rule_id)
            entry["result_indices"].append(idx)
        return decomposition

    def write(
        self, collection: FindingCollection, path: Path
    ) -> None:
        """Export and write SARIF to a file.

        Args:
            collection: The finding collection to export.
            path: Destination file path.
        """
        sarif_data = self.export(collection)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        logger.info("SARIF report written to %s", path)

    # Private helpers

    @staticmethod
    def _get_redacts_version() -> str:
        """Read REDACTS version from package metadata."""
        try:
            from importlib.metadata import version

            return version("redacts")
        except Exception:
            from static.core.constants import VERSION

            return VERSION

    @staticmethod
    def _build_rules(findings: FindingCollection) -> list[dict[str, Any]]:
        """Build SARIF rules array with YAML hydration and ATT&CK tags.

        For SEC* rules, enriches shortDescription, fullDescription, and
        defaultConfiguration.level from the compiled YAML rule set.
        Adds MITRE ATT&CK technique IDs as ``properties.tags`` for
        GitHub security badge integration.
        """
        # Lazy-load YAML rules and MITRE mapping for hydration
        yaml_rules: dict[str, dict[str, Any]] = {}
        try:
            from threat_base.data_loader import load_security_rules

            for r in load_security_rules():
                yaml_rules[r["id"]] = r
        except Exception:
            logger.debug("YAML security rules unavailable for SARIF hydration")

        mitre_lookup = None
        try:
            from threat_base.mitre_mapping import get_mitre_attack

            mitre_lookup = get_mitre_attack
        except Exception:
            logger.debug("MITRE mapping unavailable for SARIF hydration")

        seen: dict[str, dict[str, Any]] = {}
        for f in findings.findings:
            if f.rule_id in seen:
                continue

            # Start with finding data
            short_desc = f.title
            full_desc = f.description
            level = f.sarif_level

            # Hydrate from YAML if available (canonical descriptions)
            yaml_rule = yaml_rules.get(f.rule_id)
            if yaml_rule:
                full_desc = yaml_rule.get("message", full_desc)
                level = _severity_to_sarif_level(
                    yaml_rule.get("severity", "")
                ) or level

            rule: dict[str, Any] = {
                "id": f.rule_id,
                "shortDescription": {"text": short_desc},
                "fullDescription": {"text": full_desc},
                "defaultConfiguration": {"level": level},
            }
            if f.tool_rule_url:
                rule["helpUri"] = f.tool_rule_url

            properties: dict[str, Any] = {
                "source": f.source.value,
                "category": f.category,
            }

            # Build tags array for GitHub security badges
            tags: list[str] = []
            if f.cwe_id:
                properties["cwe"] = f.cwe_id
                tags.append(f.cwe_id)

            # ATT&CK technique tag - from finding or MITRE mapping
            attack_id = f.mitre_attack_id
            attack_name = f.mitre_attack_name
            if not attack_id and mitre_lookup:
                attack_id, attack_name = mitre_lookup(f.rule_id)
            if attack_id:
                properties["mitre_attack_id"] = attack_id
                properties["mitre_attack_name"] = attack_name
                tags.append(attack_id)

            if yaml_rule and yaml_rule.get("recommendation"):
                properties["recommendation"] = yaml_rule["recommendation"]

            if tags:
                properties["tags"] = tags

            rule["properties"] = properties
            seen[f.rule_id] = rule

        return list(seen.values())

    @staticmethod
    def _build_tool_components(
        findings: FindingCollection,
    ) -> list[dict[str, Any]]:
        """Build SARIF tool extension entries from tool_versions."""
        components: list[dict[str, Any]] = []
        for tool_name, ver in findings.tool_versions.items():
            components.append(
                {
                    "name": tool_name,
                    "version": ver,
                }
            )
        return components

    @staticmethod
    def _build_cwe_taxonomy(
        findings: FindingCollection,
    ) -> list[dict[str, Any]]:
        """Build unique CWE taxa referenced by findings."""
        seen: dict[str, dict[str, Any]] = {}
        for f in findings.findings:
            if not f.cwe_id:
                continue
            cwe_num = f.cwe_id.replace("CWE-", "")
            if cwe_num in seen:
                continue
            taxon: dict[str, Any] = {"id": cwe_num}
            if f.cwe_name:
                taxon["name"] = f.cwe_name
            seen[cwe_num] = taxon
        return list(seen.values())

    @staticmethod
    def _build_attack_taxonomy(
        findings: FindingCollection,
    ) -> list[dict[str, Any]]:
        """Build unique MITRE ATT&CK taxa referenced by findings."""
        mitre_lookup = None
        try:
            from threat_base.mitre_mapping import get_mitre_attack

            mitre_lookup = get_mitre_attack
        except Exception:
            mitre_lookup = None

        seen: dict[str, dict[str, Any]] = {}
        for f in findings.findings:
            attack_id = f.mitre_attack_id
            attack_name = f.mitre_attack_name
            if not attack_id and mitre_lookup:
                attack_id, attack_name = mitre_lookup(f.rule_id)
            if not attack_id:
                continue
            if attack_id in seen:
                continue
            taxon: dict[str, Any] = {"id": attack_id}
            if attack_name:
                taxon["name"] = attack_name
            seen[attack_id] = taxon
        return list(seen.values())


def _severity_to_sarif_level(severity: str) -> str:
    """Map REDACTS severity string to SARIF level."""
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }.get(severity.upper(), "")
