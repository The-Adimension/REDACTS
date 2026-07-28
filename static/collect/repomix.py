"""
REDACTS Repomix Integration - Generate compressed codebase representations.

Produces a single compressed snapshot of a REDCap tree for analyst review,
plus file/token/character counts, using the ``repomix`` Python package
(``pip install repomix``).

This runs entirely in-process via the package's Python API. It replaces the
earlier integration that shelled out to the Node ``repomix`` / ``npx`` CLI,
which required Node.js on the host and, on Windows, routed a ``.cmd`` shim
through ``cmd.exe`` (a command-injection surface). Neither is needed now.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RepomixResult:
    """Result from a repomix run."""

    success: bool = False
    output_file: str = ""
    total_files: int = 0
    total_chars: int = 0
    total_tokens: int = 0
    output_size_bytes: int = 0
    output_hash: str = ""
    error: str | None = None
    command_used: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return asdict(self)


class RepomixRunner:
    """Generate compressed codebase snapshots via the ``repomix`` Python API.

    Requires the ``repomix`` package (``pip install repomix``); it is declared
    as a REDACTS Python dependency, so a correctly provisioned environment
    always has it. When absent, :meth:`run` returns a failed result rather than
    raising, so the surrounding collection step degrades gracefully.
    """

    DEFAULT_EXCLUDE = [
        # A prior Repomix dump left in the tree would otherwise be re-bundled
        # into this run's output (a bundle inside a bundle).
        "**/repomix-output.*",
        "repomix-output.*",
        "vendor/**",
        "node_modules/**",
        ".git/**",
        "*.min.js",
        "*.min.css",
        "*.map",
        "*.png",
        "*.jpg",
        "*.gif",
        "*.ico",
        "*.svg",
        "*.woff",
        "*.woff2",
        "*.ttf",
        "*.eot",
        "*.pdf",
        "*.zip",
        "*.tar",
        "*.gz",
    ]

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
        timeout: int = 600,
        output_style: str = "plain",
    ):
        self.exclude = exclude_patterns or self.DEFAULT_EXCLUDE
        # ``timeout`` is retained for call-site compatibility. The Python API
        # is synchronous and in-process; there is no subprocess to bound, so
        # this is advisory only.
        self.timeout = timeout
        self.output_style = output_style

    def is_available(self) -> bool:
        """Return ``True`` if the ``repomix`` package can be imported."""
        try:
            import repomix  # noqa: F401

            return True
        except ImportError:
            return False

    def run(
        self,
        source_dir: Path,
        output_file: Path,
        label: str = "",
    ) -> RepomixResult:
        """Pack *source_dir* into *output_file* and return counts.

        Args:
            source_dir: Directory to process.
            output_file: Where to write the packed snapshot.
            label: Label for logging.
        """
        result = RepomixResult()
        start = time.time()

        try:
            from repomix import RepoProcessor, RepomixConfig
        except ImportError as exc:
            result.error = (
                f"repomix package not installed: {exc}. Install with "
                "'pip install repomix'."
            )
            logger.warning(result.error)
            return result

        output_file = Path(output_file)

        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)

            config = RepomixConfig()
            config.output.file_path = str(output_file.resolve())
            config.output.style = self.output_style
            config.output.calculate_tokens = True
            config.output.show_file_stats = True
            # REDACTS supplies its own ignore list; keep repomix's built-in
            # default ignores and .gitignore handling enabled as well so junk
            # directories are still excluded if the caller's list is short.
            config.ignore.custom_patterns = list(self.exclude)

            logger.info("Running repomix (Python API) on %s...", label or source_dir)
            processor = RepoProcessor(directory=str(source_dir), config=config)
            api_result = processor.process(write_output=True)

            result.duration_seconds = round(time.time() - start, 2)
            result.command_used = (
                f"repomix(python API) style={self.output_style} dir={source_dir}"
            )
            result.total_files = int(getattr(api_result, "total_files", 0) or 0)
            result.total_chars = int(getattr(api_result, "total_chars", 0) or 0)
            result.total_tokens = int(getattr(api_result, "total_tokens", 0) or 0)

            if output_file.exists():
                result.success = True
                result.output_file = str(output_file)
                result.output_size_bytes = output_file.stat().st_size
                result.output_hash = self._file_hash(output_file)
                # Fall back to on-disk size when the API reports no char count.
                if result.total_chars == 0:
                    result.total_chars = result.output_size_bytes
            else:
                result.error = "repomix produced no output file"
                logger.warning(result.error)

        except Exception as exc:  # noqa: BLE001 - collection is non-fatal
            result.error = str(exc)
            result.duration_seconds = round(time.time() - start, 2)
            logger.warning("Repomix (Python API) failed: %s", exc)

        return result

    def _file_hash(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
