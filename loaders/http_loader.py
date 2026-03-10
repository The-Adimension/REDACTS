"""
REDACTS HTTP Loader - Import REDCap from HTTP/HTTPS URLs.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from ..core.network_security import reject_ssrf_target
from ..sandbox.isolation import InputSanitizer
from .base import BaseLoader, LoaderError

logger = logging.getLogger(__name__)

# Maximum download size: 2GB
MAX_DOWNLOAD_SIZE = 2 * 1024 * 1024 * 1024

#: Timeout (seconds) for lightweight probe requests (HEAD).
HEAD_REQUEST_TIMEOUT: int = 10

#: Timeout (seconds) for streaming file downloads.
DOWNLOAD_TIMEOUT: int = 300


class HTTPLoader(BaseLoader):
    """Load REDCap from HTTP/HTTPS URLs."""

    @property
    def name(self) -> str:
        return "http"

    def can_handle(self, source: str) -> bool:
        """Check if source is an HTTP/HTTPS URL."""
        return source.lower().startswith(("http://", "https://"))

    def validate(self, source: str) -> bool:
        """Validate URL is accessible (HEAD request)."""
        try:
            import requests

            resp = requests.head(source, timeout=HEAD_REQUEST_TIMEOUT, allow_redirects=True)
            return resp.status_code < 400
        except Exception:
            return False

    def load(self, source: str, destination: Path) -> Path:
        """
        Download file from HTTP and extract.

        Includes size limit checking and streaming download.
        """
        try:
            import requests
        except ImportError:
            raise LoaderError("requests not installed. Run: pip install requests")

        # Sanitize URL
        source = InputSanitizer.sanitize_url(source)
        destination.mkdir(parents=True, exist_ok=True)

        # Check Content-Length first
        try:
            head = requests.head(source, timeout=HEAD_REQUEST_TIMEOUT, allow_redirects=True)
            content_length = int(head.headers.get("Content-Length", 0))
            if content_length > MAX_DOWNLOAD_SIZE:
                raise LoaderError(
                    f"File too large: {content_length / 1_000_000:.0f}MB "
                    f"(max {MAX_DOWNLOAD_SIZE / 1_000_000:.0f}MB)"
                )
        except requests.RequestException as e:
            logger.warning(f"HEAD request failed, proceeding anyway: {e}")

        # SSRF protection: resolve hostname and reject internal/metadata IPs
        parsed = urlparse(source)
        self._reject_ssrf_target(parsed.hostname or "")

        # Determine filename from URL
        filename = Path(parsed.path).name or "download.zip"

        # Use mkstemp for atomic file creation (no TOCTOU race)
        fd, tmp_name = tempfile.mkstemp(
            suffix=f"_{filename}", prefix="redacts_http_"
        )
        temp_file = Path(tmp_name)
        os.close(fd)  # close fd — streaming download will open by path

        try:
            # Streaming download with progress
            logger.info(f"Downloading {source}...")
            with requests.get(source, stream=True, timeout=DOWNLOAD_TIMEOUT) as r:
                r.raise_for_status()
                downloaded = 0
                with open(temp_file, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        downloaded += len(chunk)
                        if downloaded > MAX_DOWNLOAD_SIZE:
                            raise LoaderError("Download exceeded size limit")
                        f.write(chunk)

            logger.info(f"Downloaded {downloaded / 1_000_000:.1f}MB → {temp_file.name}")

            # Extract downloaded archive
            from .zip_loader import ZipLoader

            zip_loader = ZipLoader()
            if zip_loader.can_handle(str(temp_file)):
                return zip_loader.load(str(temp_file), destination)
            else:
                # Maybe it's a plain directory/file - copy it
                raise LoaderError(
                    f"Downloaded file is not a recognized archive format. "
                    f"Expected ZIP, TAR, 7Z, or RAR."
                )

        except requests.RequestException as e:
            raise LoaderError(f"HTTP download failed: {e}")

        finally:
            if temp_file.exists():
                temp_file.unlink()

    @staticmethod
    def _reject_ssrf_target(hostname: str) -> None:
        """Block requests to internal/reserved IPs (delegates to shared utility)."""
        try:
            reject_ssrf_target(hostname)
        except ValueError as exc:
            raise LoaderError(str(exc)) from exc
