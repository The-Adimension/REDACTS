"""
ATT&CK Enterprise Knowledge - STIX 2.1 data access.

Loads the ATT&CK Enterprise STIX 2.1 bundle (downloaded by prefetch)
and provides indexed access to techniques, mitigations, and relationships.

Data source:
    mitre-attack/attack-stix-data (GitHub)
    Enterprise ATT&CK only (no Mobile/ICS per architectural decision)
    License: Apache 2.0

This module is WARN-tier.  If the STIX bundle is not available,
all methods return empty/None and the scan continues.

Copyright 2024-2026 The Adimension / Shehab Anwer
Licensed under the Apache License, Version 2.0
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default data directory - sibling to this module
_DATA_DIR = Path(__file__).parent / "data"
_ATTACK_BUNDLE = _DATA_DIR / "enterprise-attack.json"


class AttackKnowledge:
    """Indexed access to ATT&CK Enterprise technique data.

    Usage::

        ak = AttackKnowledge()
        if ak.available:
            info = ak.get_technique("T1505.003")
            # info = {"id": "T1505.003", "name": "Web Shell", "description": ..., ...}
    """

    def __init__(self, bundle_path: Path | None = None) -> None:
        self._bundle_path = bundle_path or _ATTACK_BUNDLE
        self._techniques: dict[str, dict[str, Any]] = {}
        self._mitigations: dict[str, dict[str, Any]] = {}
        self._loaded = False
        self._load()

    def _load(self) -> None:
        """Parse the STIX bundle and build technique/mitigation indexes."""
        if not self._bundle_path.is_file():
            logger.warning(
                "ATT&CK STIX bundle not found at %s - "
                "ATT&CK enrichment disabled. Run 'python main.py update attack' "
                "to download the full Enterprise ATT&CK dataset.",
                self._bundle_path,
            )
            return

        try:
            data = json.loads(self._bundle_path.read_text(encoding="utf-8"))
            objects = data.get("objects", [])

            for obj in objects:
                obj_type = obj.get("type", "")
                if obj_type == "attack-pattern":
                    self._index_technique(obj)
                elif obj_type == "course-of-action":
                    self._index_mitigation(obj)

            self._loaded = True
            logger.info(
                "ATT&CK loaded: %d techniques, %d mitigations",
                len(self._techniques),
                len(self._mitigations),
            )
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Failed to parse ATT&CK STIX bundle: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error loading ATT&CK data: %s", exc)

    def _index_technique(self, obj: dict[str, Any]) -> None:
        """Extract and index a single attack-pattern object."""
        refs = obj.get("external_references", [])
        technique_id = ""
        for ref in refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break
        if not technique_id:
            return

        self._techniques[technique_id] = {
            "id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
            ],
            "detection": obj.get("x_mitre_detection", ""),
            "revoked": obj.get("revoked", False),
            "deprecated": obj.get("x_mitre_deprecated", False),
        }

    def _index_mitigation(self, obj: dict[str, Any]) -> None:
        """Extract and index a single course-of-action object."""
        refs = obj.get("external_references", [])
        mit_id = ""
        for ref in refs:
            if ref.get("source_name") == "mitre-attack":
                mit_id = ref.get("external_id", "")
                break
        if not mit_id:
            return

        self._mitigations[mit_id] = {
            "id": mit_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
        }

    @property
    def available(self) -> bool:
        """Whether ATT&CK data was loaded successfully."""
        return self._loaded

    @property
    def technique_count(self) -> int:
        return len(self._techniques)

    def get_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Look up an ATT&CK technique by ID (e.g. 'T1505.003')."""
        return self._techniques.get(technique_id)

    def get_mitigation(self, mitigation_id: str) -> dict[str, Any] | None:
        """Look up a mitigation by ID (e.g. 'M1042')."""
        return self._mitigations.get(mitigation_id)

    def enrich_description(self, technique_id: str) -> str:
        """Return technique description or empty string if unavailable."""
        tech = self._techniques.get(technique_id)
        return tech["description"] if tech else ""

    def list_techniques_for_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """Return all techniques associated with a given kill-chain phase."""
        return [
            t for t in self._techniques.values()
            if tactic in t.get("tactics", []) and not t.get("revoked")
        ]
