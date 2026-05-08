"""
REDACTS Provenance Model - scan input attestation.

Records the SHA-256 hashes of all scan inputs, tool versions,
knowledge data file hashes, and scan timing for reproducibility
and forensic chain-of-custody.

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.hashing import compute_single_hash

logger = logging.getLogger(__name__)

ATTACK_COVERAGE_DISCLAIMER = (
    "ATT&CK COVERAGE: REDACTS maps findings to a targeted subset of "
    "MITRE ATT&CK Enterprise techniques focused on web application "
    "compromise. Full matrix coverage is not claimed."
)


@dataclass
class ProvenanceData:
    """Immutable provenance record for a single scan run.

    Attributes:
        input_hashes:              SHA-256 of all scan input artifacts.
        tool_versions:             Tool name -> version mapping.
        knowledge_data_hashes:     Knowledge file name -> SHA-256.
        scan_started:              ISO 8601 UTC timestamp.
        scan_completed:            ISO 8601 UTC timestamp.
        attack_coverage_disclaimer: ATT&CK coverage limitation text.
    """

    input_hashes: dict[str, str] = field(default_factory=dict)
    tool_versions: dict[str, str] = field(default_factory=dict)
    knowledge_data_hashes: dict[str, str] = field(default_factory=dict)
    scan_started: str = ""
    scan_completed: str = ""
    attack_coverage_disclaimer: str = ATTACK_COVERAGE_DISCLAIMER
    coverage_gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON/SARIF output."""
        return {
            "input_hashes": dict(self.input_hashes),
            "tool_versions": dict(self.tool_versions),
            "knowledge_data_hashes": dict(self.knowledge_data_hashes),
            "scan_started": self.scan_started,
            "scan_completed": self.scan_completed,
            "attack_coverage_disclaimer": self.attack_coverage_disclaimer,
            "coverage_gaps": list(self.coverage_gaps),
        }


def hash_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file.

    Returns empty string if the file is unreadable.
    """
    return compute_single_hash(path, suppress_errors=True)


def compute_provenance(
    *,
    target_path: Path | str | None = None,
    reference_path: Path | str | None = None,
    tool_versions: dict[str, str] | None = None,
    scan_started: str = "",
    coverage_gaps: list[str] | None = None,
) -> ProvenanceData:
    """Build a ProvenanceData by hashing inputs and knowledge files.

    Args:
        target_path:  Path to the target artifact (ZIP or directory).
        reference_path: Path to the reference artifact.
        tool_versions: Dict of tool_name -> version.
        scan_started: ISO 8601 timestamp when the scan began.
        coverage_gaps: List of human-readable coverage-gap notes from preflight.

    Returns:
        A populated ProvenanceData instance.
    """
    input_hashes: dict[str, str] = {}

    if target_path:
        tp = Path(target_path)
        if tp.is_file():
            input_hashes["target"] = hash_file(tp)

    if reference_path:
        rp = Path(reference_path)
        if rp.is_file():
            input_hashes["reference"] = hash_file(rp)

    # Hash knowledge data files
    knowledge_dir = Path(__file__).parent.parent / "knowledge" / "data"
    knowledge_hashes: dict[str, str] = {}
    if knowledge_dir.is_dir():
        for data_file in sorted(knowledge_dir.iterdir()):
            if data_file.is_file() and data_file.suffix in (
                ".yaml",
                ".yml",
                ".json",
            ):
                digest = hash_file(data_file)
                if digest:
                    knowledge_hashes[data_file.name] = digest

    return ProvenanceData(
        input_hashes=input_hashes,
        tool_versions=tool_versions or {},
        knowledge_data_hashes=knowledge_hashes,
        scan_started=scan_started or datetime.now(timezone.utc).isoformat(),
        coverage_gaps=list(coverage_gaps) if coverage_gaps else [],
    )
