"""
Discovery phase — probe which external tools are installed.

Populates :attr:`OrchestratorContext.tool_availability` and
:attr:`OrchestratorContext.collection.tool_versions`.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..phase_protocol import OrchestratorContext, PhaseResult

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class DiscoverPhase:
    """Phase 1: Probe tool availability and record versions."""

    name: str = "discover"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        logger.info("Phase 1: Discovering tools…")

        cfg = context.config

        # Semgrep
        if cfg.enable_semgrep:
            self._probe_semgrep(context)

        # Trivy
        if cfg.enable_trivy:
            self._probe_trivy(context)

        # YARA
        if cfg.enable_yara:
            self._probe_yara(context)

        # Magika
        if cfg.enable_magika:
            self._probe_magika(context)

        # tree-sitter
        if cfg.enable_tree_sitter:
            self._probe_tree_sitter(context)

        # Docker (for DAST)
        if cfg.enable_dast:
            self._probe_docker(context)

        return PhaseResult()

    # ── tool probes ──────────────────────────────────────────────────

    @staticmethod
    def _probe_semgrep(ctx: OrchestratorContext) -> None:
        try:
            from ...investigation.semgrep_adapter import SemgrepAdapter

            adapter = SemgrepAdapter()
            available = adapter.is_available()
            ctx.tool_availability["semgrep"] = available
            if available:
                ctx.collection.tool_versions["semgrep"] = adapter.get_version()
                logger.info("  Semgrep: available (v%s)", adapter.get_version())
            else:
                logger.warning(
                    "  Semgrep: NOT available — %s", adapter.install_hint
                )
        except Exception as exc:
            logger.warning("  Semgrep probe failed: %s", exc)
            ctx.tool_availability["semgrep"] = False

    @staticmethod
    def _probe_trivy(ctx: OrchestratorContext) -> None:
        try:
            from ...investigation.trivy_adapter import TrivyAdapter

            adapter = TrivyAdapter()
            available = adapter.is_available()
            ctx.tool_availability["trivy"] = available
            if available:
                ctx.collection.tool_versions["trivy"] = adapter.get_version()
                logger.info("  Trivy: available (v%s)", adapter.get_version())
            else:
                logger.warning(
                    "  Trivy: NOT available — %s", adapter.install_hint
                )
        except Exception as exc:
            logger.warning("  Trivy probe failed: %s", exc)
            ctx.tool_availability["trivy"] = False

    @staticmethod
    def _probe_yara(ctx: OrchestratorContext) -> None:
        try:
            from ...investigation.external_tools import YaraAdapter

            adapter = YaraAdapter()
            available = adapter.is_available()
            ctx.tool_availability["yara"] = available
            if available:
                ctx.collection.tool_versions["yara"] = adapter.get_version()
                logger.info("  YARA: available (v%s)", adapter.get_version())
            else:
                logger.warning(
                    "  YARA: NOT available — %s", adapter.install_hint
                )
        except Exception as exc:
            logger.warning("  YARA probe failed: %s", exc)
            ctx.tool_availability["yara"] = False

    @staticmethod
    def _probe_magika(ctx: OrchestratorContext) -> None:
        try:
            from ...forensics.magika_analyzer import MagikaAnalyzer

            MagikaAnalyzer()  # Triggers model load
            ctx.tool_availability["magika"] = True
            ctx.collection.tool_versions["magika"] = ">=0.6.0"
            logger.info("  Magika: available")
        except Exception as exc:
            logger.warning("  Magika: NOT available — %s", exc)
            ctx.tool_availability["magika"] = False

    @staticmethod
    def _probe_tree_sitter(ctx: OrchestratorContext) -> None:
        try:
            from ...forensics.tree_sitter_analyzer import TreeSitterAnalyzer

            TreeSitterAnalyzer()  # Triggers language load
            ctx.tool_availability["tree_sitter"] = True
            logger.info("  tree-sitter-php: available")
        except Exception as exc:
            logger.warning("  tree-sitter-php: NOT available — %s", exc)
            ctx.tool_availability["tree_sitter"] = False

    @staticmethod
    def _probe_docker(ctx: OrchestratorContext) -> None:
        cfg = ctx.config
        if (
            cfg.docker_available is not None
            and cfg.docker_compose_available is not None
        ):
            # Pre-checked by core.dependencies — skip redundant probe
            ctx.tool_availability["docker"] = cfg.docker_available
            ctx.tool_availability["dast"] = (
                cfg.docker_available and cfg.docker_compose_available
            )
            if ctx.tool_availability["dast"]:
                logger.info("  Docker + Compose: available (DAST enabled)")
            elif cfg.docker_available:
                logger.warning("  Docker: available but Compose not working")
            else:
                logger.info(
                    "  Docker: NOT available — DAST phase will be skipped"
                )
        else:
            # Fallback: probe Docker ourselves
            import shutil

            docker_path = shutil.which("docker")
            if docker_path:
                try:
                    import subprocess

                    # Get Docker version
                    dv = subprocess.run(
                        ["docker", "--version"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if dv.returncode == 0:
                        ctx.collection.tool_versions["docker"] = (
                            dv.stdout.strip().split("\n")[0][:80]
                        )
                    # Check Docker Compose
                    proc = subprocess.run(
                        ["docker", "compose", "version"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if proc.returncode == 0:
                        ctx.tool_availability["docker"] = True
                        ctx.tool_availability["dast"] = True
                        ctx.collection.tool_versions["docker_compose"] = (
                            proc.stdout.strip().split("\n")[0][:80]
                        )
                        logger.info(
                            "  Docker + Compose: available (DAST enabled)"
                        )
                    else:
                        ctx.tool_availability["docker"] = True
                        ctx.tool_availability["dast"] = False
                        logger.warning(
                            "  Docker: available but Compose not working"
                        )
                except Exception as exc:
                    ctx.tool_availability["docker"] = False
                    ctx.tool_availability["dast"] = False
                    logger.warning("  Docker: probe failed — %s", exc)
            else:
                ctx.tool_availability["docker"] = False
                ctx.tool_availability["dast"] = False
                logger.info(
                    "  Docker: NOT available — DAST phase will be skipped"
                )
