"""
REDACTS Report Renderer Protocol - plug-in interface for report formats.

Defines the :class:`ReportRenderer` Protocol and the :class:`ReportContext`
dataclass that every renderer receives.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ..analyze.investigator import InvestigationReport


@dataclass
class ReportContext:
    """Immutable context handed to every renderer."""

    investigation: InvestigationReport
    meta: Any | None  # EvidenceMetadata or None
    title: str
    sorted_findings: list[Any]
    provenance: Any | None = None  # ProvenanceData or None


@runtime_checkable
class ReportRenderer(Protocol):
    """Protocol that all renderers must satisfy."""

    @property
    def format_name(self) -> str: ...

    @property
    def file_extension(self) -> str: ...

    def render(self, context: ReportContext) -> str: ...
