"""Logging configuration for REDACTS."""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path


def setup_logging(
    log_level: str = "INFO",
    log_file: Path | None = None,
    verbose: bool = False,
) -> None:
    """Configure logging for REDACTS."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    handlers: list[logging.Handler] = []

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else level)
    console.setFormatter(logging.Formatter(fmt))
    handlers.append(console)

    # File handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10_000_000, backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(fmt))
        handlers.append(file_handler)

    logging.basicConfig(level=logging.DEBUG, handlers=handlers, force=True)
