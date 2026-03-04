"""
IoC scanning step — checks the filesystem against the IoC knowledge base.

Extracted from ``Investigator._scan_iocs`` and its helper methods.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ..step_protocol import (
    InvestigationContext,
    StepResult,
    iter_scannable_files,
    rel_path,
    sha256,
)
from ..step_protocol import InvestigationFinding
from ...knowledge.ioc_database import IoC, IoCDatabase

logger = logging.getLogger(__name__)


class IocScanStep:
    """Scan for Indicators of Compromise.

    Evaluates every IoC in the database against the target filesystem.

    Implements :class:`~investigation.step_protocol.InvestigationStep`.
    """

    name: str = "ioc_scan"

    def __init__(self, ioc_db: IoCDatabase) -> None:
        self._ioc_db = ioc_db

    # ── protocol entry point ─────────────────────────────────────────────

    def execute(self, context: InvestigationContext) -> StepResult:
        findings = self._scan_iocs(context.root, only_files=context.only_files)
        return StepResult(findings=findings)

    # ── implementation (moved verbatim from Investigator) ────────────────

    def _scan_iocs(
        self, root: Path, *, only_files: Optional[set[str]] = None
    ) -> list[InvestigationFinding]:
        """Check filesystem against the IoC database.

        When *only_files* is set, content-based scans (file_content, regex)
        are restricted to those files.  Structural checks (file_exists,
        directory_exists, structure_validation, function_enum) still run
        against the full tree because they detect added artefacts.
        """
        findings: list[InvestigationFinding] = []

        for ioc in self._ioc_db.all_iocs:
            try:
                ioc_findings = self._evaluate_single_ioc(
                    ioc, root, only_files=only_files
                )
                findings.extend(ioc_findings)
            except Exception as exc:
                logger.warning("IoC %s evaluation failed: %s", ioc.id, exc)

        return findings

    def _evaluate_single_ioc(
        self, ioc: IoC, root: Path, *, only_files: Optional[set[str]] = None
    ) -> list[InvestigationFinding]:
        """Evaluate a single IoC against the filesystem."""
        findings: list[InvestigationFinding] = []
        method = ioc.detection_method

        if method == "file_exists":
            findings.extend(self._ioc_file_exists(ioc, root))
        elif method == "file_content" and ioc.compiled_pattern:
            findings.extend(self._ioc_file_content(ioc, root, only_files=only_files))
        elif method == "structure_validation":
            pass  # handled in config integrity
        elif method == "function_enum":
            pass  # handled in config integrity
        elif method == "regex" and ioc.compiled_pattern:
            findings.extend(self._ioc_regex_scan(ioc, root, only_files=only_files))
        elif method == "directory_exists":
            findings.extend(self._ioc_directory_exists(ioc, root))
        elif method in ("file_location", "content_check"):
            findings.extend(self._ioc_file_location(ioc, root))
        elif method == "hash_compare":
            findings.extend(self._ioc_hash_flag(ioc, root))

        return findings

    def _ioc_file_exists(self, ioc: IoC, root: Path) -> list[InvestigationFinding]:
        """Glob for file-existence IoCs."""
        findings: list[InvestigationFinding] = []
        if not ioc.pattern:
            return findings

        # Handle multi-pattern (pipe-separated globs)
        patterns = [p.strip() for p in ioc.pattern.split("|")]
        for pattern in patterns:
            try:
                for hit in root.glob(pattern):
                    if hit.is_file():
                        rel = rel_path(hit, root)
                        findings.append(
                            InvestigationFinding(
                                id="",
                                source="ioc_scan",
                                severity=ioc.severity,
                                title=ioc.name,
                                description=ioc.description,
                                file_path=rel,
                                line=0,
                                conclusiveness=ioc.conclusiveness.value,
                                category=ioc.category.value,
                                recommendation=ioc.recommendation,
                                evidence={
                                    "ioc_id": ioc.id,
                                    "detection_method": ioc.detection_method,
                                    "matched_path": rel,
                                },
                                related_ioc_ids=[ioc.id],
                            )
                        )
            except Exception as exc:
                logger.debug("Glob pattern %r failed: %s", pattern, exc)

        return findings

    def _ioc_file_content(
        self, ioc: IoC, root: Path, *, only_files: Optional[set[str]] = None
    ) -> list[InvestigationFinding]:
        """Scan file contents for IoC regex patterns."""
        findings: list[InvestigationFinding] = []
        assert ioc.compiled_pattern is not None

        for php_file in iter_scannable_files(root, only_files=only_files):
            try:
                content = php_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for match in ioc.compiled_pattern.finditer(content):
                line_no = content[: match.start()].count("\n") + 1
                rel = rel_path(php_file, root)
                findings.append(
                    InvestigationFinding(
                        id="",
                        source="ioc_scan",
                        severity=ioc.severity,
                        title=ioc.name,
                        description=ioc.description,
                        file_path=rel,
                        line=line_no,
                        conclusiveness=ioc.conclusiveness.value,
                        category=ioc.category.value,
                        recommendation=ioc.recommendation,
                        evidence={
                            "ioc_id": ioc.id,
                            "detection_method": ioc.detection_method,
                            "matched_text": match.group(0)[:120],
                        },
                        related_ioc_ids=[ioc.id],
                    )
                )

        return findings

    def _ioc_regex_scan(
        self, ioc: IoC, root: Path, *, only_files: Optional[set[str]] = None
    ) -> list[InvestigationFinding]:
        """Regex-based IoC scan across all scannable files (same as content)."""
        return self._ioc_file_content(ioc, root, only_files=only_files)

    def _ioc_directory_exists(
        self, ioc: IoC, root: Path
    ) -> list[InvestigationFinding]:
        """Check for existence of indicator directories."""
        findings: list[InvestigationFinding] = []
        if not ioc.pattern:
            return findings

        for pattern in [p.strip() for p in ioc.pattern.split("|")]:
            try:
                for hit in root.glob(pattern):
                    if hit.is_dir():
                        rel = rel_path(hit, root)
                        findings.append(
                            InvestigationFinding(
                                id="",
                                source="ioc_scan",
                                severity=ioc.severity,
                                title=ioc.name,
                                description=ioc.description,
                                file_path=rel,
                                line=0,
                                conclusiveness=ioc.conclusiveness.value,
                                category=ioc.category.value,
                                recommendation=ioc.recommendation,
                                evidence={
                                    "ioc_id": ioc.id,
                                    "detection_method": "directory_exists",
                                    "matched_path": rel,
                                },
                                related_ioc_ids=[ioc.id],
                            )
                        )
            except Exception as exc:
                logger.debug("Directory glob %r failed: %s", pattern, exc)

        return findings

    def _ioc_file_location(
        self, ioc: IoC, root: Path
    ) -> list[InvestigationFinding]:
        """Detect files in forbidden locations (e.g. PHP in upload dirs)."""
        findings: list[InvestigationFinding] = []
        forbidden_dirs = {"edocs", "uploads", "temp"}
        php_exts = {".php", ".phtml", ".phar", ".php5", ".php7", ".inc"}
        image_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp"}

        for fdir in forbidden_dirs:
            target_dir = root / fdir
            if not target_dir.is_dir():
                # Also check inside versioned directories
                for vdir in root.glob("redcap_v*"):
                    cand = vdir / fdir
                    if cand.is_dir():
                        target_dir = cand
                        break
                else:
                    continue

            for fpath in target_dir.rglob("*"):
                if not fpath.is_file():
                    continue
                rel = rel_path(fpath, root)
                ext = fpath.suffix.lower()

                # PHP in upload directory
                if ext in php_exts:
                    findings.append(
                        InvestigationFinding(
                            id="",
                            source="ioc_scan",
                            severity="CRITICAL",
                            title=ioc.name,
                            description=(
                                f"Executable PHP file found in upload directory: {rel}"
                            ),
                            file_path=rel,
                            line=0,
                            conclusiveness="conclusive",
                            category="webshell",
                            recommendation=ioc.recommendation,
                            evidence={
                                "ioc_id": ioc.id,
                                "detection_method": "file_location",
                                "forbidden_directory": fdir,
                            },
                            related_ioc_ids=[ioc.id],
                        )
                    )

                # Polyglot images (image extension containing PHP tags)
                if ioc.detection_method == "content_check" and ext in image_exts:
                    try:
                        raw = fpath.read_bytes()[:8192]
                        if b"<?php" in raw or b"<?" in raw:
                            findings.append(
                                InvestigationFinding(
                                    id="",
                                    source="ioc_scan",
                                    severity="CRITICAL",
                                    title="Polyglot file",
                                    description=(
                                        f"Image file contains embedded PHP code: {rel}"
                                    ),
                                    file_path=rel,
                                    line=0,
                                    conclusiveness="conclusive",
                                    category="webshell",
                                    recommendation=(
                                        "Definitively malicious. Remove and "
                                        "investigate upload mechanism."
                                    ),
                                    evidence={
                                        "ioc_id": ioc.id,
                                        "detection_method": "content_check",
                                        "header_bytes": raw[:32].hex(),
                                    },
                                    related_ioc_ids=[ioc.id],
                                )
                            )
                    except Exception:
                        pass

        return findings

    def _ioc_hash_flag(self, ioc: IoC, root: Path) -> list[InvestigationFinding]:
        """Flag files that need hash comparison (presence-only check)."""
        findings: list[InvestigationFinding] = []
        artifact = ioc.filesystem_artifact.lower()

        # Try to locate the mentioned artifact
        candidates: list[Path] = []
        if "vendor/autoload.php" in artifact:
            candidates = list(root.glob("**/vendor/autoload.php"))
        elif "externalmodules" in artifact:
            candidates = list(root.glob("**/ExternalModules/classes/*.php"))

        for fpath in candidates:
            rel = rel_path(fpath, root)
            sha = sha256(fpath)
            findings.append(
                InvestigationFinding(
                    id="",
                    source="ioc_scan",
                    severity=ioc.severity,
                    title=ioc.name,
                    description=(
                        f"{ioc.description} — hash recorded for comparison: "
                        f"{sha[:16]}…"
                    ),
                    file_path=rel,
                    line=0,
                    conclusiveness="suspicious",
                    category=ioc.category.value,
                    recommendation=ioc.recommendation,
                    evidence={
                        "ioc_id": ioc.id,
                        "detection_method": "hash_compare",
                        "sha256": sha,
                    },
                    related_ioc_ids=[ioc.id],
                )
            )

        return findings
