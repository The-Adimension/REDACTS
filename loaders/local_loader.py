"""
REDACTS Local Loader - Import REDCap from local filesystem paths.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from ..sandbox.isolation import PathSecurity
from .base import BaseLoader, LoaderError, detect_redcap_root

logger = logging.getLogger(__name__)


class LocalLoader(BaseLoader):
    """Load REDCap from a local directory or file."""

    @property
    def name(self) -> str:
        return "local"

    def can_handle(self, source: str) -> bool:
        """Local loader handles anything that's a valid path."""
        path = Path(source)
        return path.exists()

    def validate(self, source: str) -> bool:
        """Validate local path exists."""
        path = Path(source)
        return path.exists()

    def load(self, source: str, destination: Path) -> Path:
        """
        Copy or link local REDCap directory.

        For directories: copies the tree.
        For archives: delegates to ZipLoader.
        """
        source_path = Path(source).resolve()

        if not source_path.exists():
            raise LoaderError(f"Path not found: {source}")

        # Validate path safety
        PathSecurity.validate_path(source_path)

        if source_path.is_file():
            # Might be an archive - delegate
            from .zip_loader import ZipLoader

            loader = ZipLoader()
            if loader.can_handle(str(source_path)):
                return loader.load(str(source_path), destination)
            else:
                raise LoaderError(f"Not a directory or recognized archive: {source}")

        if source_path.is_dir():
            destination.mkdir(parents=True, exist_ok=True)

            # Copy directory tree
            dest_path = destination / source_path.name
            if dest_path.exists():
                shutil.rmtree(dest_path)

            shutil.copytree(
                source_path,
                dest_path,
                symlinks=False,  # Don't follow symlinks for security
                ignore=shutil.ignore_patterns(
                    "__pycache__",
                    "*.pyc",
                    ".git",
                    "node_modules",
                ),
            )

            root = detect_redcap_root(dest_path)
            logger.info(f"Copied local directory: {source_path} → {root}")
            return root

        raise LoaderError(f"Unsupported source type: {source}")
