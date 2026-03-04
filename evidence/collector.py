"""
REDACTS Evidence Collector — Tier 1 Orchestrator.

Produces a complete, self-contained evidence package from a source:
    1. Load source (ZIP, directory, URL, FTP)
    2. Build file manifest (every file hashed, timestamped, classified)
    3. Detect filesystem anomalies (files that shouldn't exist)
    4. Generate Repomix snapshot (forensic evidence preservation)
    5. Write evidence package to disk with metadata

The evidence package is the "bible" — a faithful, unopinionated snapshot
of reality. No conclusions, no verdicts. Just evidence.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from ..loaders import detect_loader, detect_redcap_root
from ..integration.repomix import RepomixRunner
from ..core import REDACTSConfig
from ..core.constants import VERSION
from ..sandbox.isolation import IntegrityChecker
from .manifest import EvidenceManifest, ManifestBuilder

logger = logging.getLogger(__name__)


@dataclass
class EvidenceMetadata:
    """Chain-of-custody metadata for an evidence package."""

    # Identity
    label: str = ""
    evidence_id: str = ""  # Auto-generated unique ID

    # Provenance
    source_uri: str = ""
    source_type: str = ""  # zip, directory, url, ftp
    collection_timestamp: str = ""
    collection_duration_seconds: float = 0.0

    # Tool info
    tool_name: str = "REDACTS"
    tool_version: str = VERSION
    tool_command: str = ""

    # Analyst notes
    notes: str = ""

    # Integrity
    manifest_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnomalySummary:
    """Summary of filesystem anomalies found during evidence collection."""

    total_anomalies: int = 0
    anomalies_by_type: dict[str, int] = field(default_factory=dict)

    # Categorized anomaly lists
    sqlite_files: list[str] = field(default_factory=list)
    user_ini_files: list[str] = field(default_factory=list)
    htaccess_anomalies: list[str] = field(default_factory=list)
    hidden_php_files: list[str] = field(default_factory=list)
    php_in_uploads: list[str] = field(default_factory=list)
    polyglot_files: list[str] = field(default_factory=list)
    suspicious_filenames: list[str] = field(default_factory=list)
    symlink_escapes: list[str] = field(default_factory=list)
    high_entropy_files: list[str] = field(default_factory=list)
    phar_files: list[str] = field(default_factory=list)
    certificate_files: list[str] = field(default_factory=list)
    log_injection_files: list[str] = field(default_factory=list)
    double_extension_files: list[str] = field(default_factory=list)
    anomalous_extension_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidencePackage:
    """A complete evidence collection result."""

    success: bool = False
    metadata: EvidenceMetadata = field(default_factory=EvidenceMetadata)
    manifest: Optional[EvidenceManifest] = None
    anomalies: AnomalySummary = field(default_factory=AnomalySummary)

    # Root of the actual source files (for Tier 2 investigation scanning).
    # This is the detected REDCap root inside _staging, NOT the output dir.
    source_root: str = ""

    # Paths to generated artifacts
    package_dir: str = ""
    manifest_path: str = ""
    metadata_path: str = ""
    anomalies_path: str = ""
    repomix_path: str = ""

    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.manifest:
            d["manifest"] = self.manifest.to_dict()
        return d


class EvidenceCollector:
    """
    Tier 1: Collects forensic evidence from a REDCap source.

    Produces a self-contained evidence package directory containing:
        - manifest.json: Every file with hashes, timestamps, anomaly flags
        - metadata.json: Chain-of-custody information
        - anomalies.json: Filesystem anomalies found
        - repomix.xml/txt: Complete source snapshot (if repomix available)
    """

    def __init__(
        self,
        config: Optional[REDACTSConfig] = None,
        *,
        manifest_builder: Optional[ManifestBuilder] = None,
    ):
        self.config = config or REDACTSConfig()
        self.manifest_builder = manifest_builder or ManifestBuilder(
            hash_algorithms=self.config.analysis.hash_algorithms
        )

    def collect(
        self,
        source: str,
        output_dir: str,
        label: str = "",
        notes: str = "",
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> EvidencePackage:
        """
        Collect forensic evidence from a source.

        Args:
            source: Path to ZIP, directory, URL, or FTP source
            output_dir: Where to write the evidence package
            label: Human-readable label (e.g., "Production REDCap - Site A")
            notes: Analyst notes for chain-of-custody
            progress_callback: Optional (step, total, message) callback

        Returns:
            EvidencePackage with all collected evidence
        """
        total_steps = 5
        start_time = time.time()

        package = EvidencePackage()
        package.metadata.label = (
            label or f"Evidence-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        )
        package.metadata.source_uri = source
        package.metadata.collection_timestamp = datetime.now(timezone.utc).isoformat()
        package.metadata.notes = notes
        package.metadata.tool_command = f'redacts collect {source} -l "{label}"'

        # Generate evidence ID from timestamp + random suffix
        package.metadata.evidence_id = f"EVD-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"

        def _progress(step: int, msg: str) -> None:
            if progress_callback:
                progress_callback(step, total_steps, msg)
            logger.info(f"[{step}/{total_steps}] {msg}")

        # Step 1: Load source
        _progress(1, f"Loading source: {source}")
        source_path = self._load_source(source, package, output_dir)
        if source_path is None:
            package.success = False
            return package

        # Record where the actual source files live so Tier 2 can scan
        # the source tree instead of the (potentially huge) output dir.
        package.source_root = str(source_path)

        # Step 2: Build file manifest
        _progress(2, "Building file manifest (hashing, timestamping, classifying...)")
        try:
            manifest = self.manifest_builder.build(
                root=source_path,
                label=label,
                source_uri=source,
            )
            package.manifest = manifest
        except Exception as e:
            package.errors.append(f"Manifest build failed: {e}")
            logger.error(f"Manifest build failed: {e}", exc_info=True)
            package.success = False
            return package

        # Step 3: Build anomaly summary
        _progress(3, "Analyzing anomalies...")
        package.anomalies = self._build_anomaly_summary(manifest)

        # Step 4: Generate Repomix snapshot
        _progress(4, "Generating Repomix forensic snapshot...")
        repomix_path = self._generate_repomix(source_path, output_dir, label)

        # Step 5: Write evidence package to disk
        _progress(5, "Writing evidence package...")
        self._write_package(package, output_dir, repomix_path)

        package.metadata.collection_duration_seconds = round(
            time.time() - start_time, 2
        )
        package.success = True

        # Re-write metadata with final duration
        meta_path = Path(output_dir) / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(package.metadata.to_dict(), f, indent=2, default=str)

        logger.info(
            f"Evidence collected: {manifest.total_files} files, "
            f"{package.anomalies.total_anomalies} anomalies, "
            f"{package.metadata.collection_duration_seconds}s"
        )

        return package

    def _load_source(
        self, source: str, package: EvidencePackage, output_dir: str
    ) -> Optional[Path]:
        """Load the source using the appropriate loader."""
        try:
            loader = detect_loader(source)
            package.metadata.source_type = (
                type(loader).__name__.replace("Loader", "").lower()
            )
            staging = Path(output_dir) / "_staging"
            staging.mkdir(parents=True, exist_ok=True)
            source_path = loader.load(source, staging)

            # Detect REDCap root within extracted content
            root = detect_redcap_root(source_path)
            return root
        except Exception as e:
            package.errors.append(f"Source loading failed: {e}")
            logger.error(f"Failed to load source '{source}': {e}", exc_info=True)
            return None

    def _build_anomaly_summary(self, manifest: EvidenceManifest) -> AnomalySummary:
        """Build a categorized anomaly summary from manifest entries."""
        summary = AnomalySummary()
        anomaly_type_counts: dict[str, int] = {}

        # Anomaly routing map
        anomaly_to_field = {
            "sqlite_file_in_webroot": "sqlite_files",
            "sqlite_sidecar_active_writes": "sqlite_files",
            "user_ini_persistence": "user_ini_files",
            "htaccess_in_upload_dir": "htaccess_anomalies",
            "hidden_php_file": "hidden_php_files",
            "php_in_upload_directory": "php_in_uploads",
            "polyglot_php_in_image": "polyglot_files",
            "suspicious_filename": "suspicious_filenames",
            "symlink_escapes_root": "symlink_escapes",
            "symlink_unresolvable": "symlink_escapes",
            "symlink_unreadable": "symlink_escapes",
            "high_entropy_php": "high_entropy_files",
            "phar_archive": "phar_files",
            "phar_magic_in_non_phar": "phar_files",
            "certificate_in_webroot": "certificate_files",
            "php_code_in_log_file": "log_injection_files",
            "double_extension_php": "double_extension_files",
            "anomalous_extension": "anomalous_extension_files",
        }

        for entry in manifest.entries:
            for anomaly in entry.anomalies:
                summary.total_anomalies += 1
                anomaly_type_counts[anomaly] = anomaly_type_counts.get(anomaly, 0) + 1

                target_field = anomaly_to_field.get(anomaly)
                if target_field and hasattr(summary, target_field):
                    getattr(summary, target_field).append(entry.relative_path)

        summary.anomalies_by_type = anomaly_type_counts
        return summary

    def _generate_repomix(
        self, source_path: Path, output_dir: str, label: str
    ) -> Optional[str]:
        """Generate Repomix snapshot for forensic evidence preservation."""
        if not self.config.repomix.enabled:
            logger.info("Repomix disabled, skipping forensic snapshot")
            return None

        try:
            runner = RepomixRunner(
                exclude_patterns=self.config.repomix.exclude_patterns,
            )
            out_dir = Path(output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)

            safe_label = (
                "".join(c if c.isalnum() or c in "-_ " else "_" for c in label)
                .strip()
                .replace(" ", "_")
            )
            output_file = out_dir / f"repomix_{safe_label}.txt"

            result = runner.run(
                source_dir=source_path,
                output_file=output_file,
            )

            if result.success:
                logger.info(
                    f"Repomix snapshot: {result.total_files} files, "
                    f"{result.total_tokens} tokens"
                )
                return str(output_file)
            else:
                logger.warning(f"Repomix failed: {result.error}")
                return None
        except Exception as e:
            logger.warning(f"Repomix generation failed (non-fatal): {e}")
            return None

    def _write_package(
        self,
        package: EvidencePackage,
        output_dir: str,
        repomix_path: Optional[str],
    ) -> None:
        """Write all evidence package files to disk."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # Write manifest
        manifest_path = out / "manifest.json"
        if package.manifest:
            package.manifest.save(manifest_path)
        package.manifest_path = str(manifest_path)

        # Compute manifest integrity hash (chain-of-custody)
        if manifest_path.is_file():
            package.metadata.manifest_sha256 = IntegrityChecker.compute_hash(
                manifest_path, algorithm="sha256"
            )

        # Write metadata (includes manifest_sha256 now)
        metadata_path = out / "metadata.json"
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(package.metadata.to_dict(), f, indent=2, default=str)
        package.metadata_path = str(metadata_path)

        # Write anomalies
        anomalies_path = out / "anomalies.json"
        with open(anomalies_path, "w", encoding="utf-8") as f:
            json.dump(package.anomalies.to_dict(), f, indent=2, default=str)
        package.anomalies_path = str(anomalies_path)

        # Record repomix path
        if repomix_path:
            package.repomix_path = repomix_path

        package.package_dir = str(out)

        logger.info(f"Evidence package written to: {out}")
