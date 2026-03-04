"""
REDACTS Forensic Report Generator — Tier 2 Investigation Reports.

Generates comprehensive, forensic-grade reports from completed REDACTS
investigations. Supports HTML (with dark-theme styling and interactive
elements), JSON (machine-readable), and Markdown output formats.

Designed for HIPAA-regulated environments: all sensitive values are
redacted in reports while preserving forensic completeness.

Rendering is delegated to pluggable :class:`ReportRenderer` implementations
discovered in :mod:`reporting.renderers`.  See :mod:`reporting.renderer_protocol`
for the Protocol definition.

Usage::

    generator = ForensicReportGenerator()
    paths = generator.generate(
        investigation=report,
        evidence=evidence_pkg,
        output_dir="/tmp/reports",
    )
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..evidence.collector import EvidencePackage
from ..investigation.investigator import InvestigationReport
from .renderer_protocol import ReportContext, ReportRenderer
from .renderers import HtmlReportRenderer, JsonReportRenderer, MarkdownReportRenderer
from .renderers._shared import _sorted_findings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------


class ForensicReportGenerator:
    """Generate forensic reports in HTML, JSON, and Markdown.

    Rendering is delegated to pluggable :class:`ReportRenderer` instances.
    The three built-in formats (``html``, ``json``, ``markdown``) are
    registered automatically; additional renderers may be added via
    :meth:`register_renderer`.
    """

    def __init__(
        self,
        *,
        renderers: dict[str, ReportRenderer] | None = None,
    ) -> None:
        self._renderers: dict[str, ReportRenderer] = (
            renderers
            if renderers is not None
            else {
                "html": HtmlReportRenderer(),
                "json": JsonReportRenderer(),
                "markdown": MarkdownReportRenderer(),
            }
        )

    # -- Plugin API --------------------------------------------------------

    def register_renderer(self, renderer: ReportRenderer) -> None:
        """Register (or replace) a renderer for *renderer.format_name*."""
        self._renderers[renderer.format_name] = renderer

    @property
    def renderers(self) -> dict[str, ReportRenderer]:
        """Read-only snapshot of the current renderer registry."""
        return dict(self._renderers)

    # -- Generation --------------------------------------------------------

    def generate(
        self,
        investigation: InvestigationReport,
        evidence: Optional[EvidencePackage] = None,
        output_dir: Optional[str] = None,
        formats: Optional[list[str]] = None,
        report_title: Optional[str] = None,
    ) -> list[str]:
        """Generate one or more forensic report files.

        Args:
            investigation: Completed investigation report.
            evidence: Optional evidence package for chain-of-custody info.
            output_dir: Directory to write reports into.
            formats: List of output formats (html, json, markdown).
            report_title: Custom report title (default auto-generated).

        Returns:
            List of absolute paths to generated report files.
        """
        formats = formats or list(("html", "json", "markdown"))

        output_dir_path = Path(output_dir) if output_dir else Path.cwd().resolve()

        if not report_title:
            report_title = "REDACTS Forensic Report — " + (
                (evidence and evidence.metadata and evidence.metadata.label)
                or (evidence and evidence.metadata and evidence.metadata.evidence_id)
                or "Investigation"
            )

        output_dir_path.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        meta = evidence.metadata if evidence else None

        sorted_f = _sorted_findings(investigation.findings)
        context = ReportContext(
            investigation=investigation,
            meta=meta,
            title=report_title,
            sorted_findings=sorted_f,
        )

        generated: list[str] = []
        for fmt in formats:
            renderer = self._renderers.get(fmt)
            if renderer is None:
                logger.warning("No renderer registered for format %r — skipping", fmt)
                continue
            ext = renderer.file_extension.lstrip(".")
            fname = f"redacts_forensic_{ts}.{ext}"
            path = output_dir_path / fname
            content = renderer.render(context)
            path.write_text(content, encoding="utf-8")
            generated.append(str(path))

        logger.info(
            "Generated %d forensic reports in %s", len(generated), output_dir_path
        )
        return generated
