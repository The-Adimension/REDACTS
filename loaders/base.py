"""
REDACTS Base Loader - Abstract interface for all source loaders.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class LoaderError(Exception):
    """Raised when source loading fails."""

    pass


class BaseLoader(ABC):
    """Abstract base for all source loaders."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Loader identifier."""
        pass

    @abstractmethod
    def can_handle(self, source: str) -> bool:
        """Check if this loader can handle the given source."""
        pass

    @abstractmethod
    def load(self, source: str, destination: Path) -> Path:
        """
        Load source into destination directory.

        Args:
            source: Source URI/path
            destination: Directory to extract/copy into

        Returns:
            Path to the loaded REDCap root directory

        Raises:
            LoaderError: If loading fails
        """
        pass

    @abstractmethod
    def validate(self, source: str) -> bool:
        """Validate source is accessible before loading."""
        pass


def detect_loader(source: str) -> BaseLoader:
    """
    Auto-detect the appropriate loader for a source.

    Args:
        source: Source URI, path, or URL

    Returns:
        Appropriate loader instance

    Raises:
        LoaderError: If no loader can handle the source
    """
    from .zip_loader import ZipLoader
    from .ftp_loader import FTPLoader
    from .http_loader import HTTPLoader
    from .local_loader import LocalLoader

    loaders: list[BaseLoader] = [
        ZipLoader(),
        HTTPLoader(),
        FTPLoader(),
        LocalLoader(),
    ]

    for loader in loaders:
        if loader.can_handle(source):
            logger.info(f"Auto-detected loader: {loader.name} for source: {source}")
            return loader

    raise LoaderError(
        f"No loader can handle source: {source}\n"
        f"Supported: ZIP files, HTTP/HTTPS URLs, FTP/SFTP, local directories"
    )


def detect_redcap_root(path: Path) -> Path:
    """
    Detect the REDCap root directory within an extracted archive.
    Looks for characteristic REDCap files/directories.

    Args:
        path: Directory to search

    Returns:
        Path to the REDCap root
    """
    # Markers that identify a REDCap installation
    markers = [
        "redcap_connect.php",
        "database.php",
        "cron.php",
    ]

    # Check if path itself is the root
    if any((path / m).exists() for m in markers):
        return path

    # Check one level deep
    for child in path.iterdir():
        if child.is_dir():
            if any((child / m).exists() for m in markers):
                return child

    # Check two levels deep (e.g., zip contains a wrapper folder)
    for child in path.iterdir():
        if child.is_dir():
            for grandchild in child.iterdir():
                if grandchild.is_dir():
                    if any((grandchild / m).exists() for m in markers):
                        return grandchild

    # Fall back to the path itself
    logger.warning(f"Could not detect REDCap root markers in {path}, using as-is")
    return path
