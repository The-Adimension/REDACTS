"""
REDACTS ZIP Loader - Import REDCap from ZIP, TAR.GZ, 7Z, and RAR archives.
"""

from __future__ import annotations

import logging
import os
import tarfile
import zipfile
from pathlib import Path

from ..sandbox.isolation import PathSecurity
from .base import BaseLoader, LoaderError, detect_redcap_root

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Archive-safety limits
# ---------------------------------------------------------------------------
# These guard against zip-bomb and oversized-entry attacks.  No matching
# config field exists yet; they are extracted here as named constants so a
# future config-expansion step can wire them without a code-archaeology hunt.

MAX_ENTRY_BYTES: int = 500_000_000
"""Per-file uncompressed size ceiling (500 MB) — entries above this are
rejected as potential zip-bomb payloads."""

MAX_COMPRESSION_RATIO: int = 100
"""Overall compression ratio ceiling (100:1) — archives that exceed this
are treated as suspicious zip bombs."""

# Supported archive extensions
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

        destination.mkdir(parents=True, exist_ok=True)
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
        logger.info(f"Loaded REDCap from {source_path.name} → {root}")
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
            # py7zr doesn't expose per-file uncompressed sizes easily,
            # so we check after extraction below

            sz.extractall(path=destination)

            # Post-extraction size check
            total_extracted = sum(
                f.stat().st_size for f in destination.rglob("*") if f.is_file()
            )
            if archive_size > 0 and total_extracted / archive_size > MAX_COMPRESSION_RATIO:
                # Clean up
                import shutil
                shutil.rmtree(destination)
                destination.mkdir(parents=True, exist_ok=True)
                raise LoaderError(
                    f"Suspicious compression ratio "
                    f"({total_extracted / archive_size:.0f}:1) — possible zip bomb"
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
                    f"({total_size / archive_size:.0f}:1) — possible zip bomb"
                )

            rf.extractall(destination)
            logger.info(f"Extracted RAR archive: {archive.name}")
