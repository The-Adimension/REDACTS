"""Discover available external tools and record their versions."""

from __future__ import annotations

import logging

from ..phase_protocol import OrchestratorContext, PhaseResult

logger = logging.getLogger(__name__)

__all__ = ["DiscoverPhase"]


class DiscoverPhase:
    """Probe tool availability and record versions."""

    name: str = "discover"

    def execute(self, context: OrchestratorContext) -> PhaseResult:
        logger.info("Discovering scanner tools...")

        cfg = context.config

        if cfg.enable_semgrep:
            self._probe_semgrep(context)
        if cfg.enable_trivy:
            self._probe_trivy(context)
        if cfg.enable_yara:
            self._probe_yara(context)
        if cfg.enable_magika:
            self._probe_magika(context)
        if cfg.enable_tree_sitter:
            self._probe_tree_sitter(context)
        if cfg.enable_dast:
            self._probe_docker(context)

        return PhaseResult()

    # --- tool probes -----------------

    @staticmethod
    def _probe_adapter(
        ctx: OrchestratorContext,
        tool_name: str,
        display_name: str,
        adapter_factory: type,
    ) -> None:
        """Probe an ExternalToolAdapter for availability and version."""
        try:
            adapter = adapter_factory()
            available = adapter.is_available()
            ctx.tool_availability[tool_name] = available
            if available:
                ctx.collection.tool_versions[tool_name] = adapter.get_version()
                logger.info("  %s: available (v%s)", display_name, adapter.get_version())
            else:
                logger.warning(
                    "  %s: NOT available - %s", display_name, adapter.install_hint
                )
        except Exception as exc:
            logger.warning("  %s probe failed: %s", display_name, exc)
            ctx.tool_availability[tool_name] = False

    @staticmethod
    def _probe_semgrep(ctx: OrchestratorContext) -> None:
        from ..semgrep_adapter import SemgrepAdapter

        DiscoverPhase._probe_adapter(ctx, "semgrep", "Semgrep", SemgrepAdapter)

    @staticmethod
    def _probe_trivy(ctx: OrchestratorContext) -> None:
        from ..trivy_adapter import TrivyAdapter

        DiscoverPhase._probe_adapter(ctx, "trivy", "Trivy", TrivyAdapter)

    @staticmethod
    def _probe_yara(ctx: OrchestratorContext) -> None:
        from ..yara_adapter import YaraAdapter

        DiscoverPhase._probe_adapter(ctx, "yara", "YARA", YaraAdapter)

    @staticmethod
    def _probe_magika(ctx: OrchestratorContext) -> None:
        class _MagikaProbe:
            install_hint = "pip install magika"

            def __init__(self) -> None:
                from ..magika_adapter import MagikaAnalyzer
                MagikaAnalyzer()  # Triggers model load; raises if unavailable

            def is_available(self) -> bool:
                return True

            def get_version(self) -> str:
                return ">=0.6.0"

        DiscoverPhase._probe_adapter(ctx, "magika", "Magika", _MagikaProbe)

    @staticmethod
    def _probe_tree_sitter(ctx: OrchestratorContext) -> None:
        class _TreeSitterProbe:
            install_hint = "pip install tree-sitter tree-sitter-php"

            def __init__(self) -> None:
                from ..tree_sitter_adapter import TreeSitterAnalyzer
                TreeSitterAnalyzer()  # Triggers language load; raises if unavailable

            def is_available(self) -> bool:
                return True

            def get_version(self) -> str:
                return ""

        DiscoverPhase._probe_adapter(ctx, "tree_sitter", "tree-sitter-php", _TreeSitterProbe)

    @staticmethod
    def _probe_docker(ctx: OrchestratorContext) -> None:
        cfg = ctx.config
        if (
            cfg.docker_available is not None
            and cfg.docker_compose_available is not None
        ):
            # Pre-checked by core.dependencies - skip redundant probe
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
                    "  Docker: NOT available - DAST phase will be skipped"
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
                    logger.warning("  Docker: probe failed - %s", exc)
            else:
                ctx.tool_availability["docker"] = False
                ctx.tool_availability["dast"] = False
                logger.info(
                    "  Docker: NOT available - DAST phase will be skipped"
                )
