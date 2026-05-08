"""
ATT&CK Data Prefetch - Download and verify STIX 2.1 bundle.

Downloads the ATT&CK Enterprise STIX 2.1 bundle from the official
mitre-attack/attack-stix-data GitHub repository.  The bundle is
saved alongside this module in ``data/enterprise-attack.json``.

This is a WARN-tier operation:
    - Required on first run (unless ``--offline`` is passed)
    - After first download, data is cached locally
    - ``redacts preflight --fetch-attack`` triggers this explicitly
    - Air-gapped users: ``redacts preflight --export-dast-images``
      can pre-bundle this alongside Docker images

Source:
    https://github.com/mitre-attack/attack-stix-data
    Tag: v18.1
    File: enterprise-attack.json
    License: Apache 2.0

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_ATTACK_BUNDLE = _DATA_DIR / "enterprise-attack.json"
_ATTACK_SHA256 = _DATA_DIR / "enterprise-attack.json.sha256"

# The ATT&CK STIX bundle URL is sourced from the active
# FrozenCaseContract via :mod:`threat_base.sources`.


def prefetch_attack_data(
    dest_dir: Path | None = None,
    force: bool = False,
) -> bool:
    """Download the ATT&CK Enterprise STIX 2.1 bundle.

    Args:
        dest_dir: Override destination directory (default: ``data/``).
        force: Re-download even if cached bundle exists and is valid.

    Returns:
        True if the bundle is available (downloaded or cached).
    """
    data_dir = dest_dir or _DATA_DIR
    bundle_path = data_dir / "enterprise-attack.json"
    sha_path = data_dir / "enterprise-attack.json.sha256"

    # Check cache
    if not force and bundle_path.is_file():
        if _verify_bundle(bundle_path, sha_path):
            logger.info("ATT&CK bundle cached and verified: %s", bundle_path)
            return True
        logger.warning("ATT&CK bundle exists but integrity check failed - re-downloading")

    try:
        import requests
    except ImportError:
        logger.error("requests not available - cannot download ATT&CK data")
        return False

    data_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Downloading ATT&CK Enterprise STIX bundle...")

    # SSRF protection: validate the (contract-pinned) URL before each
    # request; also guards against DNS rebinding during the request.
    from urllib.parse import urlparse as _urlparse
    from static.core.network import reject_ssrf_target as _reject_ssrf
    from .sources import attack_stix_url
    _url = attack_stix_url()
    _parsed = _urlparse(_url)
    try:
        _reject_ssrf(_parsed.hostname or "")
    except ValueError as exc:
        logger.error("SSRF check failed for ATT&CK download: %s", exc)
        return False

    try:
        resp = requests.get(_url, timeout=120, stream=True)
        resp.raise_for_status()

        sha256 = hashlib.sha256()
        with open(bundle_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
                sha256.update(chunk)

        digest = sha256.hexdigest()
        sha_path.write_text(digest + "\n", encoding="utf-8")

        # Validate JSON structure
        data = json.loads(bundle_path.read_text(encoding="utf-8"))
        obj_count = len(data.get("objects", []))
        logger.info(
            "ATT&CK bundle downloaded: %d objects, SHA-256: %s",
            obj_count,
            digest,
        )
        return True

    except Exception as exc:
        logger.error("Failed to download ATT&CK data: %s", exc)
        # Clean up partial downloads
        if bundle_path.is_file():
            bundle_path.unlink(missing_ok=True)
        if sha_path.is_file():
            sha_path.unlink(missing_ok=True)
        return False


def _verify_bundle(bundle_path: Path, sha_path: Path) -> bool:
    """Verify bundle integrity against stored SHA-256."""
    if not sha_path.is_file():
        return False

    stored_hash = sha_path.read_text(encoding="utf-8").strip().split()[0]
    actual_hash = hashlib.sha256(
        bundle_path.read_bytes()
    ).hexdigest()

    return stored_hash == actual_hash


def is_attack_data_available(data_dir: Path | None = None) -> bool:
    """Check if ATT&CK data is cached and valid."""
    d = data_dir or _DATA_DIR
    bundle = d / "enterprise-attack.json"
    sha = d / "enterprise-attack.json.sha256"
    return bundle.is_file() and _verify_bundle(bundle, sha)
