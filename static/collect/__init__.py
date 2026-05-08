"""
REDACTS Collect Module (Phase A) - Forensic Evidence Collection & Preservation.

This module implements the "bible" - faithful, unopinionated evidence collection
with chain-of-custody metadata. Every file is hashed, timestamped, classified,
and preserved. Nothing is removed, nothing is judged at this tier.

Components:
    - collector.py: Orchestrates evidence collection from a source
    - manifest.py: Generates file manifests with hashes, timestamps, permissions
    - loaders.py: Source loaders (ZIP, dir, HTTP, FTP)
    - anomaly.py: Filesystem anomaly detection
    - repomix.py: Repomix snapshot runner
    - provenance.py: Chain-of-custody attestation
"""

# Namespace package: import directly from submodules
# (e.g. ``from static.collect.loaders import LocalLoader``).
__all__: list[str] = []
