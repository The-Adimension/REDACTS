"""Filesystem anomaly checks run during evidence collection.

``ManifestBuilder`` delegates per-file anomaly classification to
:class:`AnomalyDetector`. The 14 checks live here so that the manifest
module deals only with metadata aggregation and the anomaly rules can
be replaced or subclassed without touching the collection pipeline.

Anomalies fall into three groups:

    * Files that should never exist in a REDCap webroot
      (``.user.ini``, ``.env``, ``.git``) - see ``ANOMALOUS_FILES``.
    * Extensions that should never appear (``.db``, ``.phar``, etc.)
      - see ``ANOMALOUS_EXTENSIONS``. ``.db`` in particular is the
      InfiniteRed marker (REDCap is MySQL-only; any SQLite file is
      anomalous).
    * Content/extension mismatches surfaced by Magika.

Known limits:

    * Detection is name- and extension-driven for two of the three
      groups. An attacker who renames their drop to a benign-sounding
      filename and a benign extension will only be caught by the
      content-type check, which depends on Magika.
    * The static lists are intentionally conservative. Custom modules
      that legitimately ship a ``.db`` cache must allowlist the path
      in the case contract; otherwise they will appear here.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .manifest import FileManifestEntry

logger = logging.getLogger(__name__)



# Files that should NEVER exist in a REDCap webroot
ANOMALOUS_FILES: set[str] = {
    ".user.ini",
    ".env",
    ".git",
    ".gitignore",
}

# Extensions that should NEVER appear in a REDCap webroot
ANOMALOUS_EXTENSIONS: set[str] = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".phar",
    ".so",
    ".dll",
    ".exe",
    ".py",
    ".rb",
    ".pl",
    ".cgi",
}

# Filenames/patterns that are always suspicious in a PHP webroot
SUSPICIOUS_FILENAMES: set[str] = {
    "redcap.db",
    "redcap_.db",
    "shell.php",
    "cmd.php",
    "c99.php",
    "r57.php",
    "wso.php",
    "b374k.php",
    "webshell.php",
    "backdoor.php",
    "eval.php",
    "phpinfo.php",
    "info.php",
    "test.php",
    "x.php",
}

# Sidecar files that indicate active SQLite writes
SQLITE_SIDECAR_EXTENSIONS: set[str] = {
    "-journal",
    "-wal",
    "-shm",
}




class AnomalyDetector:
    """Filesystem anomaly detection for forensic analysis.

    Implements 14 distinct anomaly checks targeting indicators of
    compromise in PHP web-application deployments (specifically REDCap).

    This class is a *Strategy* - ``ManifestBuilder`` delegates anomaly
    detection here.  Subclass and override :meth:`detect` or individual
    ``_check_*`` helpers to customise detection logic without modifying
    the manifest pipeline.
    """

    def detect(
        self, entry: FileManifestEntry, file_path: Path, root: Path
    ) -> None:
        """Run all anomaly checks against a single file entry.

        Anomaly strings are appended to ``entry.anomalies`` in-place.
        """
        name_lower = entry.filename.lower()

        # 1. Known suspicious filenames
        if name_lower in SUSPICIOUS_FILENAMES:
            entry.anomalies.append("suspicious_filename")

        # 2. Anomalous file extensions in webroot
        if entry.extension in ANOMALOUS_EXTENSIONS:
            entry.anomalies.append("anomalous_extension")

        # 3. Dot-prefixed PHP files (hidden backdoors)
        if name_lower.startswith(".") and entry.extension in (".php", ".inc"):
            entry.anomalies.append("hidden_php_file")

        # 4. .user.ini files (PHP config override - persistence vector)
        if name_lower == ".user.ini":
            entry.anomalies.append("user_ini_persistence")

        # 5. .htaccess in unexpected locations
        if name_lower == ".htaccess":
            # .htaccess in edocs/upload dirs is suspicious if it enables PHP
            parts = entry.relative_path.lower().split("/")
            if any(p in ("edocs", "uploads", "temp", "tmp") for p in parts):
                entry.anomalies.append("htaccess_in_upload_dir")

        # 6. SQLite files (REDCap uses MySQL exclusively)
        if entry.extension in (".db", ".sqlite", ".sqlite3"):
            entry.anomalies.append("sqlite_file_in_webroot")

        # 7. SQLite sidecar files (indicate active writes)
        for sidecar in SQLITE_SIDECAR_EXTENSIONS:
            if name_lower.endswith(sidecar):
                entry.anomalies.append("sqlite_sidecar_active_writes")
                break

        # 8. PHP files in upload/temp directories
        if entry.extension in (".php", ".phtml", ".phar", ".php5", ".php7", ".inc"):
            parts = entry.relative_path.lower().split("/")
            if any(p in ("edocs", "uploads", "temp", "tmp") for p in parts):
                entry.anomalies.append("php_in_upload_directory")

        # 9. Polyglot detection: check if image files contain PHP tags
        if entry.extension in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico"):
            try:
                with open(file_path, "rb") as f:
                    head = f.read(8192)
                if b"<?php" in head or b"<? " in head:
                    entry.anomalies.append("polyglot_php_in_image")
            except (OSError, PermissionError):
                head = b""

        # 10. PHAR files (executable archives, should not exist)
        if entry.extension == ".phar":
            entry.anomalies.append("phar_archive")
        else:
            # Check for PHAR magic regardless of extension
            try:
                with open(file_path, "rb") as f:
                    content = f.read(4096)
                if b"__HALT_COMPILER()" in content:
                    entry.anomalies.append("phar_magic_in_non_phar")
            except (OSError, PermissionError):
                content = b""

        # 11. Certificate/key files in webroot
        if entry.extension in (".pem", ".crt", ".key", ".p12", ".pfx"):
            entry.anomalies.append("certificate_in_webroot")

        # 12. Log files containing PHP code
        if entry.extension == ".log":
            try:
                with open(file_path, "rb") as f:
                    head = f.read(16384)
                if b"<?php" in head or b"<?=" in head:
                    entry.anomalies.append("php_code_in_log_file")
            except (OSError, PermissionError):
                head = b""

        # 13. Double extension files (image.php.jpg trick)
        parts_name = entry.filename.split(".")
        if len(parts_name) >= 3:
            inner_ext = f".{parts_name[-2].lower()}"
            if inner_ext in (".php", ".phtml", ".phar", ".php5", ".php7"):
                entry.anomalies.append("double_extension_php")

        # 14. Extremely high entropy in PHP files
        if entry.entropy_assessment == "suspicious" and entry.extension in (
            ".php",
            ".inc",
        ):
            entry.anomalies.append("high_entropy_php")
