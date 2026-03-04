"""
tree-sitter enrichment phase — add structural context to findings.
"""

from __future__ import annotations

import logging
from typing import Any

from ...core.models import UnifiedFinding
from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)


class TreeSitterPhase:
    """Phase 4: Enrich findings with structural context from tree-sitter.

    For every finding on a PHP file, parse the file with tree-sitter
    and determine which function/method/class contains the finding.
    This adds context that is critical for triage.
    """

    name: str = "tree_sitter"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        if not context.config.enable_tree_sitter:
            return PhaseResult(skipped=True)

        if not context.tool_availability.get("tree_sitter", False):
            return PhaseResult(skipped=True)

        logger.info("Phase 4: tree-sitter enrichment…")

        try:
            from ...forensics.tree_sitter_analyzer import TreeSitterAnalyzer

            analyzer = TreeSitterAnalyzer()
        except Exception as exc:
            logger.debug("tree-sitter not available for enrichment: %s", exc)
            return PhaseResult()

        # Collect PHP files that have findings
        php_files_with_findings: dict[str, list[UnifiedFinding]] = {}
        for f in context.collection.findings:
            if f.file_path and (
                f.file_path.endswith(".php") or f.file_path.endswith(".inc")
            ):
                php_files_with_findings.setdefault(f.file_path, []).append(f)

        enriched_count = 0
        for rel_path, findings in php_files_with_findings.items():
            abs_path = context.target_path / rel_path
            if not abs_path.is_file():
                continue

            try:
                ast = analyzer.parse_file(abs_path, context.target_path)
            except Exception as exc:
                logger.debug("tree-sitter failed on %s: %s", rel_path, exc)
                continue

            # For each finding, find the enclosing function/method/class
            for finding in findings:
                if finding.line_start <= 0:
                    continue

                ctx = _find_enclosing_context(ast, finding.line_start)
                if ctx:
                    finding.evidence["enclosing_function"] = ctx.get(
                        "function", ""
                    )
                    finding.evidence["enclosing_class"] = ctx.get("class", "")
                    finding.evidence["function_complexity"] = ctx.get(
                        "complexity", 0
                    )
                    enriched_count += 1

        logger.info(
            "  tree-sitter: enriched %d/%d PHP findings",
            enriched_count,
            sum(len(v) for v in php_files_with_findings.values()),
        )
        return PhaseResult()


def _find_enclosing_context(
    ast: Any, line: int
) -> dict[str, Any] | None:
    """Find the function/method/class enclosing a given line number."""
    # Check class methods
    for cls in ast.classes:
        if cls.line <= line <= cls.end_line:
            for method in cls.methods:
                if method.line <= line <= (method.line + method.body_lines):
                    return {
                        "class": cls.name,
                        "function": f"{cls.name}::{method.name}",
                        "complexity": method.complexity,
                        "visibility": method.visibility,
                    }
            # Inside class but not in a specific method
            return {
                "class": cls.name,
                "function": "",
                "complexity": 0,
            }

    # Check top-level functions
    for func in ast.functions:
        if func.line <= line <= (func.line + func.body_lines):
            return {
                "class": "",
                "function": func.name,
                "complexity": func.complexity,
            }

    return None
