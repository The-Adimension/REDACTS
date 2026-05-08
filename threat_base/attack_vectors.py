"""Attack-vector catalogue - what the filesystem layer can detect.

30+ vectors grouped into seven categories (A-G), each documenting the
on-disk artefact a forensic scanner can match on, the conclusiveness
of the match, and the corresponding IoC IDs from
:mod:`threat_base.ioc_database`.

The catalogue is REDCap-specific. Two facts drive it:

    * REDCap is MySQL-only (per the official installation guide). A
      SQLite file in the webroot is an anomaly; the InfiniteRed
      campaign (Vanderbilt advisories, Dec 2025 - Feb 2026) is the
      reason category A exists in its current form.
    * REDCap exposes admin-driven file-write surfaces (External
      Modules, ``.user.ini`` for some hosting setups, hook function
      registration). Categories B, C, and F enumerate the artefacts
      those produce when abused.

Known limits: filesystem-only detection misses runtime-only attacks
that live in process memory or in MySQL rows that never reach disk
as a separate file. Pair with the dynamic stage and with database-
level monitoring outside REDACTS.

Vector data is loaded from ``data/yaml/attack_vectors.yaml`` via
:func:`threat_base.data_loader.load_attack_vectors`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .data_loader import load_attack_vectors


# - Categories -

CATEGORY_A = "DATABASE_TO_FILESYSTEM"
CATEGORY_B = "FEATURE_ABUSE"
CATEGORY_C = "CONFIG_PERSISTENCE"
CATEGORY_D = "SUPPLY_CHAIN"
CATEGORY_E = "SERVER_CONFIG"
CATEGORY_F = "PHP_RUNTIME"
CATEGORY_G = "ADDITIONAL"

ALL_CATEGORIES: list[str] = [
    CATEGORY_A,
    CATEGORY_B,
    CATEGORY_C,
    CATEGORY_D,
    CATEGORY_E,
    CATEGORY_F,
    CATEGORY_G,
]


@dataclass
class AttackVector:
    """A single attack vector detectable via filesystem forensics."""

    id: str
    name: str
    description: str
    category: str
    subcategory: str
    filesystem_artifacts: list[str] = field(default_factory=list)
    detection_patterns: list[str] = field(default_factory=list)
    conclusiveness: str = "suspicious"  # conclusive | suspicious | informational
    severity: str = "MEDIUM"
    detection_method: str = ""
    redacts_coverage: str = "none"  # covered | partial | none
    related_iocs: list[str] = field(default_factory=list)
    out_of_scope_note: str = ""


# - Load externalized data -

_raw_vectors = load_attack_vectors()


class AttackVectorDatabase:
    """
    Structured knowledge base of filesystem-detectable attack vectors.

    Instantiation builds the full vector catalogue. Query helpers expose
    vectors by category, conclusiveness, and filesystem-detectability.
    """

    def __init__(self) -> None:
        self._vectors: list[AttackVector] = []
        self._by_id: dict[str, AttackVector] = {}
        self._by_category: dict[str, list[AttackVector]] = {}
        self._by_conclusiveness: dict[str, list[AttackVector]] = {}
        self._build_database()

    # - public properties -

    @property
    def all_vectors(self) -> list[AttackVector]:
        """Every attack vector in the database."""
        return list(self._vectors)

    # - internal -

    def _register(self, vector: AttackVector) -> None:
        self._vectors.append(vector)
        self._by_id[vector.id] = vector
        self._by_category.setdefault(vector.category, []).append(vector)
        self._by_conclusiveness.setdefault(vector.conclusiveness, []).append(vector)

    def _build_database(self) -> None:
        """Build the complete vector catalogue from externalized YAML data."""
        for raw in _raw_vectors:
            vector = AttackVector(
                id=raw["id"],
                name=raw["name"],
                description=raw["description"],
                category=raw["category"],
                subcategory=raw.get("subcategory", ""),
                filesystem_artifacts=raw.get("filesystem_artifacts", []),
                detection_patterns=raw.get("detection_patterns", []),
                conclusiveness=raw.get("conclusiveness", "suspicious"),
                severity=raw.get("severity", "MEDIUM"),
                detection_method=raw.get("detection_method", ""),
                redacts_coverage=raw.get("redacts_coverage", "none"),
                related_iocs=raw.get("related_iocs", []),
                out_of_scope_note=raw.get("out_of_scope_note", ""),
            )
            self._register(vector)
