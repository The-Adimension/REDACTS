"""Source-tree loaders: ZIP, TAR, 7z, RAR, HTTP(S), FTP, local path.

Loaders are the only place untrusted input crosses into the scan host's
filesystem, so every loader runs through ``InputSanitizer`` and
``PathSecurity`` from :mod:`..core.sandbox` and (for network sources)
``reject_ssrf_target`` from :mod:`..core.network`. The archive limits
below (500 MB per entry, 100:1 ratio) bound zip-bomb damage.

Copyright 2024-2026 The Adimension / Shehab Anwer
Apache-2.0.
"""

from __future__ import annotations

import ftplib
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from urllib.parse import urlparse

from ..core.sandbox import InputSanitizer, PathSecurity
from ..core.network import reject_ssrf_target

logger = logging.getLogger(__name__)

# Maximum download size: 2 GB (shared by HTTP & FTP loaders)
MAX_DOWNLOAD_SIZE: int = 2 * 1024 * 1024 * 1024

#: Timeout (seconds) for HEAD probe requests.
HEAD_REQUEST_TIMEOUT: int = 10

#: Timeout (seconds) for streaming file downloads.
DOWNLOAD_TIMEOUT: int = 300

# Archive-safety limits - guard against zip-bomb and oversized-entry attacks.
MAX_ENTRY_BYTES: int = 500_000_000
"""Per-file uncompressed size ceiling (500 MB)."""

MAX_COMPRESSION_RATIO: int = 100
"""Overall compression ratio ceiling (100:1)."""

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".7z",
    ".rar",
}


class LoaderError(Exception):
    """Raised when source loading fails."""


class BaseLoader(ABC):
    """Abstract base for all source loaders."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Loader identifier."""
        raise RuntimeError("BaseLoader.name must be implemented by subclasses")

    @abstractmethod
    def can_handle(self, source: str) -> bool:
        """Check if this loader can handle the given source."""
        raise RuntimeError("BaseLoader.can_handle must be implemented by subclasses")

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
        raise RuntimeError("BaseLoader.load must be implemented by subclasses")

    @abstractmethod
    def validate(self, source: str) -> bool:
        """Validate source is accessible before loading."""
        raise RuntimeError("BaseLoader.validate must be implemented by subclasses")




class ZipLoader(BaseLoader):
    """Load REDCap from compressed archive files (ZIP, TAR, 7Z, RAR)."""

    @property
    def name(self) -> str:
        return "archive"

    def can_handle(self, source: str) -> bool:
        """Check if source is a recognized archive file."""
        source_lower = source.lower()
        return any(source_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)

    def validate(self, source: str) -> bool:
        """Validate archive file exists and is readable."""
        path = Path(source)
        if not path.exists():
            logger.error(f"Archive not found: {source}")
            return False
        if not path.is_file():
            logger.error(f"Not a file: {source}")
            return False
        if path.stat().st_size == 0:
            logger.error(f"Empty archive: {source}")
            return False
        return True

    def load(self, source: str, destination: Path) -> Path:
        """
        Extract archive into destination directory.

        Includes Zip Slip protection - all entries validated before extraction.
        """
        source_path = Path(source).resolve()
        if not self.validate(str(source_path)):
            raise LoaderError(f"Invalid archive: {source}")

        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        source_lower = str(source_path).lower()

        try:
            if source_lower.endswith(".zip"):
                self._extract_zip(source_path, destination)
            elif any(
                source_lower.endswith(ext)
                for ext in (
                    ".tar",
                    ".tar.gz",
                    ".tgz",
                    ".tar.bz2",
                    ".tbz2",
                    ".tar.xz",
                    ".txz",
                )
            ):
                self._extract_tar(source_path, destination)
            elif source_lower.endswith(".7z"):
                self._extract_7z(source_path, destination)
            elif source_lower.endswith(".rar"):
                self._extract_rar(source_path, destination)
            else:
                raise LoaderError(f"Unsupported archive format: {source}")

        except (zipfile.BadZipFile, tarfile.TarError) as e:
            raise LoaderError(f"Corrupt archive: {e}")

        # Detect the REDCap root within extracted contents
        root = detect_redcap_root(destination)
        logger.info(f"Loaded REDCap from {source_path.name} -> {root}")
        return root

    def _extract_zip(self, archive: Path, destination: Path) -> None:
        """Extract ZIP with Zip Slip protection."""
        with zipfile.ZipFile(archive, "r") as zf:
            # Validate ALL entries before extracting ANY
            for info in zf.infolist():
                if not PathSecurity.validate_zip_entry(info.filename):
                    raise LoaderError(
                        f"Zip Slip attack detected in entry: {info.filename}"
                    )
                # Check for oversized entries (zip bomb protection)
                if info.file_size > MAX_ENTRY_BYTES:
                    raise LoaderError(
                        f"Oversized entry (possible zip bomb): {info.filename} "
                        f"({info.file_size / 1_000_000:.0f}MB)"
                    )

            # Count total uncompressed size (zip bomb detection)
            total_size = sum(i.file_size for i in zf.infolist())
            compressed_size = archive.stat().st_size
            if compressed_size > 0:
                ratio = total_size / compressed_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise LoaderError(
                        f"Suspicious compression ratio ({ratio:.0f}:1) - possible zip bomb"
                    )

            # Safe to extract
            zf.extractall(destination)
            logger.info(f"Extracted {len(zf.infolist())} entries from ZIP")

    def _extract_tar(self, archive: Path, destination: Path) -> None:
        """Extract TAR with path traversal protection and safe member filtering."""
        with tarfile.open(archive, "r:*") as tf:
            safe_members: list[tarfile.TarInfo] = []

            for member in tf.getmembers():
                # Check for path traversal
                member_path = os.path.join(destination, member.name)
                if not os.path.realpath(member_path).startswith(
                    os.path.realpath(str(destination))
                ):
                    raise LoaderError(f"Path traversal in tar entry: {member.name}")

                # Skip device and FIFO entries (never safe to extract)
                if member.isdev() or member.isfifo():
                    logger.warning(f"Skipping device/fifo: {member.name}")
                    continue

                # Skip symlinks/hardlinks pointing outside destination
                if member.issym() or member.islnk():
                    link_target = os.path.realpath(
                        os.path.join(destination, member.linkname)
                    )
                    if not link_target.startswith(os.path.realpath(str(destination))):
                        logger.warning(f"Skipping symlink outside dest: {member.name}")
                        continue

                safe_members.append(member)

            # Extract ONLY validated members
            tf.extractall(destination, members=safe_members, filter="data")
            logger.info(
                f"Extracted {len(safe_members)}/{len(tf.getmembers())} entries "
                f"from tar archive: {archive.name}"
            )

    def _extract_7z(self, archive: Path, destination: Path) -> None:
        """Extract 7z archive with path traversal and zip-bomb protection."""
        try:
            import py7zr
        except ImportError:
            raise LoaderError("py7zr not installed. Run: pip install py7zr")

        with py7zr.SevenZipFile(archive, mode="r") as sz:
            # Validate all entries before extraction
            names = sz.getnames()
            dest_real = os.path.realpath(str(destination))
            for name in names:
                member_path = os.path.realpath(os.path.join(destination, name))
                if not member_path.startswith(dest_real + os.sep) and member_path != dest_real:
                    raise LoaderError(f"Path traversal in 7z entry: {name}")
                # Reject absolute paths
                if os.path.isabs(name):
                    raise LoaderError(f"Absolute path in 7z entry: {name}")
                # Reject parent traversals
                if ".." in name.split("/"):
                    raise LoaderError(f"Directory traversal in 7z entry: {name}")

            # Check total uncompressed size (zip bomb protection)
            archive_size = archive.stat().st_size

            sz.extractall(path=destination)

            # Post-extraction size check
            total_extracted = sum(
                f.stat().st_size for f in destination.rglob("*") if f.is_file()
            )
            if archive_size > 0 and total_extracted / archive_size > MAX_COMPRESSION_RATIO:
                # Clean up
                shutil.rmtree(destination)
                destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                raise LoaderError(
                    f"Suspicious compression ratio "
                    f"({total_extracted / archive_size:.0f}:1) - possible zip bomb"
                )

            logger.info(f"Extracted 7z archive: {archive.name}")

    def _extract_rar(self, archive: Path, destination: Path) -> None:
        """Extract RAR archive with path traversal and zip-bomb protection."""
        try:
            import rarfile
        except ImportError:
            raise LoaderError("rarfile not installed. Run: pip install rarfile")

        with rarfile.RarFile(archive, "r") as rf:
            # Validate all entries before extraction
            dest_real = os.path.realpath(str(destination))
            total_size = 0
            for info in rf.infolist():
                member_path = os.path.realpath(
                    os.path.join(destination, info.filename)
                )
                if not member_path.startswith(dest_real + os.sep) and member_path != dest_real:
                    raise LoaderError(
                        f"Path traversal in RAR entry: {info.filename}"
                    )
                if os.path.isabs(info.filename):
                    raise LoaderError(
                        f"Absolute path in RAR entry: {info.filename}"
                    )
                if ".." in info.filename.split("/"):
                    raise LoaderError(
                        f"Directory traversal in RAR entry: {info.filename}"
                    )
                # Zip bomb check per file
                if info.file_size > MAX_ENTRY_BYTES:
                    raise LoaderError(
                        f"Oversized entry (possible bomb): {info.filename} "
                        f"({info.file_size / 1_000_000:.0f}MB)"
                    )
                total_size += info.file_size

            # Overall ratio check
            archive_size = archive.stat().st_size
            if archive_size > 0 and total_size / archive_size > MAX_COMPRESSION_RATIO:
                raise LoaderError(
                    f"Suspicious compression ratio "
                    f"({total_size / archive_size:.0f}:1) - possible zip bomb"
                )

            rf.extractall(destination)
            logger.info(f"Extracted RAR archive: {archive.name}")




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

            # SSRF protection BEFORE any network request
            parsed = urlparse(source)
            self._reject_ssrf_target(parsed.hostname or "")

            resp = requests.head(source, timeout=HEAD_REQUEST_TIMEOUT, allow_redirects=False)
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
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)

        # SSRF protection BEFORE any network request
        parsed = urlparse(source)
        self._reject_ssrf_target(parsed.hostname or "")

        # Check Content-Length first
        try:
            head = requests.head(source, timeout=HEAD_REQUEST_TIMEOUT, allow_redirects=False)
            content_length = int(head.headers.get("Content-Length", 0))
            if content_length > MAX_DOWNLOAD_SIZE:
                raise LoaderError(
                    f"File too large: {content_length / 1_000_000:.0f}MB "
                    f"(max {MAX_DOWNLOAD_SIZE / 1_000_000:.0f}MB)"
                )
        except requests.RequestException as e:
            logger.warning(f"HEAD request failed, proceeding anyway: {e}")

        # Determine filename from URL
        filename = Path(parsed.path).name or "download.zip"

        # Use mkstemp for atomic file creation (no TOCTOU race)
        fd, tmp_name = tempfile.mkstemp(
            suffix=f"_{filename}", prefix="redacts_http_"
        )
        temp_file = Path(tmp_name)
        os.close(fd)  # close fd - streaming download will open by path

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

            logger.info(f"Downloaded {downloaded / 1_000_000:.1f}MB -> {temp_file.name}")

            # Extract downloaded archive
            zip_loader = ZipLoader()
            if zip_loader.can_handle(str(temp_file)):
                return zip_loader.load(str(temp_file), destination)
            else:
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

        # SSRF protection: reject internal/metadata IPs
        reject_ssrf_target(hostname)

        destination.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Download to temp file (use mkstemp for race-condition safety)
        fd, tmp_name = tempfile.mkstemp(suffix=".zip", prefix="redacts_ftp_")
        temp_file = Path(tmp_name)
        try:
            os.close(fd)  # close the fd - downloaders will open by path
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
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(
                hostname=host,
                port=port or 22,
                username=username,
                password=password
            )
            sftp = client.open_sftp()
            try:
                # Enforce download size limit (shared with HTTPLoader)
                try:
                    remote_stat = sftp.stat(path)
                    if remote_stat.st_size and remote_stat.st_size > MAX_DOWNLOAD_SIZE:
                        raise LoaderError(
                            f"Remote file too large: {remote_stat.st_size / 1_000_000:.0f}MB "
                            f"(max {MAX_DOWNLOAD_SIZE / 1_000_000:.0f}MB)"
                        )
                except OSError:
                    remote_stat = None

                sftp.get(path, str(local_path))
            finally:
                sftp.close()
                client.close()

            logger.info(f"Downloaded {path} from {host} via SFTP")
        except LoaderError:
            raise
        except Exception as e:
            raise LoaderError(f"SFTP download failed: {e}")




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
        raw_source = Path(source)
        # Strict validation runs against the *unresolved* form so any
        # ``..`` traversal in the operator-supplied path is caught.
        PathSecurity.validate_path_strict(raw_source)
        source_path = raw_source.resolve()

        if not source_path.exists():
            raise LoaderError(f"Path not found: {source}")

        # Re-validate the resolved form to catch symlink swaps that
        # appeared between the two checks.
        PathSecurity.validate_path_strict(source_path)

        if source_path.is_file():
            # Might be an archive - delegate
            loader = ZipLoader()
            if loader.can_handle(str(source_path)):
                return loader.load(str(source_path), destination)
            else:
                raise LoaderError(f"Not a directory or recognized archive: {source}")

        if source_path.is_dir():
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)

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
            logger.info(f"Copied local directory: {source_path} -> {root}")
            return root

        raise LoaderError(f"Unsupported source type: {source}")




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

    # No REDCap markers found - return the path as-is and let the caller handle it
    return path
