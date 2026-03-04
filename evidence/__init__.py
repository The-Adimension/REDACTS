"""
REDACTS Evidence Module (Tier 1) — Forensic Evidence Collection & Preservation.

This module implements the "bible" — faithful, unopinionated evidence collection
with chain-of-custody metadata. Every file is hashed, timestamped, classified,
and preserved. Nothing is removed, nothing is judged at this tier.

Components:
    - collector.py: Orchestrates evidence collection from a source
    - manifest.py: Generates file manifests with hashes, timestamps, permissions
"""

from .collector import (
    AnomalySummary,
    EvidenceCollector,
    EvidenceMetadata,
    EvidencePackage,
)
from .manifest import EvidenceManifest, FileManifestEntry, ManifestBuilder
