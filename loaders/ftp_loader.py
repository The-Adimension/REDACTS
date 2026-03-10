"""
REDACTS FTP Loader - Import REDCap from FTP/SFTP servers.
"""

from __future__ import annotations

import ftplib
import logging
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from ..sandbox.isolation import InputSanitizer
from .base import BaseLoader, LoaderError
from .http_loader import MAX_DOWNLOAD_SIZE

logger = logging.getLogger(__name__)


class FTPLoader(BaseLoader):
    """Load REDCap from FTP/SFTP servers."""

    @property
    def name(self) -> str:
        return "ftp"

    def can_handle(self, source: str) -> bool:
        """Check if source is an FTP/SFTP URL."""
        return source.lower().startswith(("ftp://", "sftp://"))

    def validate(self, source: str) -> bool:
        """Validate FTP URL format."""
        try:
            parsed = urlparse(source)
            if parsed.scheme not in ("ftp", "sftp"):
                return False
            if not parsed.hostname:
                return False
            return True
        except Exception:
            return False

    def load(
        self,
        source: str,
        destination: Path,
        username: str | None = None,
        password: str | None = None,
    ) -> Path:
        """
        Download file from FTP and extract.

        Args:
            source: FTP URL
            destination: Extraction directory
            username: FTP username (default: anonymous)
            password: FTP password
        """
        # Sanitize URL before parsing (wire the imported InputSanitizer)
        source = InputSanitizer.sanitize_url(source)
        parsed = urlparse(source)
        hostname = parsed.hostname
        port = parsed.port or (22 if parsed.scheme == "sftp" else 21)
        remote_path = parsed.path

        if not hostname:
            raise LoaderError(f"Invalid FTP URL: {source}")

        destination.mkdir(parents=True, exist_ok=True)

        # Download to temp file (use mkstemp for race-condition safety)
        fd, tmp_name = tempfile.mkstemp(suffix=".zip", prefix="redacts_ftp_")
        temp_file = Path(tmp_name)
        try:
            os.close(fd)  # close the fd — downloaders will open by path
            if parsed.scheme == "sftp":
                self._download_sftp(
                    hostname,
                    port,
                    remote_path,
                    temp_file,
                    username or "anonymous",
                    password or "",
                )
            else:
                self._download_ftp(
                    hostname,
                    port,
                    remote_path,
                    temp_file,
                    username or parsed.username or "anonymous",
                    password or parsed.password or "",
                )

            # Extract downloaded archive
            from .zip_loader import ZipLoader

            zip_loader = ZipLoader()
            if zip_loader.can_handle(str(temp_file)):
                return zip_loader.load(str(temp_file), destination)
            else:
                raise LoaderError("Downloaded file is not a recognized archive")

        finally:
            if temp_file.exists():
                temp_file.unlink()

    def _download_ftp(
        self,
        host: str,
        port: int,
        path: str,
        local_path: Path,
        username: str,
        password: str,
    ) -> None:
        """Download file via FTP."""
        try:
            with ftplib.FTP() as ftp:
                ftp.connect(host, port, timeout=30)
                ftp.login(username, password)
                ftp.set_pasv(True)

                with open(local_path, "wb") as f:
                    ftp.retrbinary(f"RETR {path}", f.write)

                logger.info(f"Downloaded {path} from {host}")
        except ftplib.all_errors as e:
            raise LoaderError(f"FTP download failed: {e}")

    def _download_sftp(
        self,
        host: str,
        port: int,
        path: str,
        local_path: Path,
        username: str,
        password: str,
    ) -> None:
        """Download file via SFTP."""
        try:
            import paramiko
        except ImportError:
            raise LoaderError("paramiko not installed. Run: pip install paramiko")

        try:
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port or 22,
                username=username,
                password=password
            )
            sftp = client.open_sftp()

            # Enforce download size limit (shared with HTTPLoader)
            try:
                remote_stat = sftp.stat(path)
                if remote_stat.st_size and remote_stat.st_size > MAX_DOWNLOAD_SIZE:
                    sftp.close()
                    client.close()
                    raise LoaderError(
                        f"Remote file too large: {remote_stat.st_size / 1_000_000:.0f}MB "
                        f"(max {MAX_DOWNLOAD_SIZE / 1_000_000:.0f}MB)"
                    )
            except OSError:
                pass  # stat failed — proceed without size check

            sftp.get(path, str(local_path))
            sftp.close()
            client.close()

            logger.warning(
                "SFTP host key was NOT verified for %s — MITM risk. "
                "Consider using known_hosts verification in production.",
                host,
            )
            logger.info(f"Downloaded {path} from {host} via SFTP")
        except LoaderError:
            raise
        except Exception as e:
            raise LoaderError(f"SFTP download failed: {e}")
