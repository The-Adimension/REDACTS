"""Filesystem snapshot helper - before/after diffs across REDCap operations.

Compares file lists, sizes, and content hashes so an upgrade or admin
action that quietly mutates the webroot does not slip past review.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class FileEntry:
    path: str
    size: int
    hash: str
    mtime: str


@dataclass
class SuspiciousFile:
    path: str
    reason: str
    detail: str


@dataclass
class SnapshotDiff:
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    modified: list[str] = field(default_factory=list)
    unchanged: int = 0
    suspicious_files: list[SuspiciousFile] = field(default_factory=list)


def take_snapshot(directory: str) -> dict[str, FileEntry]:
    """Take a snapshot of all files under a given directory."""
    root = Path(directory)
    entries: dict[str, FileEntry] = {}
    if not root.exists():
        return entries

    for item in root.rglob("*"):
        if not item.is_file():
            continue
        rel = str(item.relative_to(root))
        content = item.read_bytes()
        file_hash = hashlib.sha256(content).hexdigest()
        stat = item.stat()
        entries[rel] = FileEntry(
            path=rel,
            size=stat.st_size,
            hash=file_hash,
            mtime=str(stat.st_mtime),
        )

    return entries


def diff_snapshots(
    before: dict[str, FileEntry],
    after: dict[str, FileEntry],
) -> SnapshotDiff:
    """Compare two snapshots and return the diff."""
    diff = SnapshotDiff()

    # Check for added and modified
    for rel_path, after_entry in after.items():
        before_entry = before.get(rel_path)
        if before_entry is None:
            diff.added.append(rel_path)
            _check_suspicious(rel_path, after_entry, "added", diff.suspicious_files)
        elif before_entry.hash != after_entry.hash:
            diff.modified.append(rel_path)
            _check_suspicious(rel_path, after_entry, "modified", diff.suspicious_files)
        else:
            diff.unchanged += 1

    # Check for removed
    for rel_path in before:
        if rel_path not in after:
            diff.removed.append(rel_path)

    return diff


def _check_suspicious(
    rel_path: str,
    entry: FileEntry,
    change_type: str,
    findings: list[SuspiciousFile],
) -> None:
    """Flag files that match INFINITERED/backdoor patterns."""
    lc = rel_path.lower()
    basename = Path(rel_path).name

    # Unexpected PHP in non-PHP directories
    if lc.endswith(".php") and ("edocs/" in lc or "temp/" in lc):
        findings.append(SuspiciousFile(
            path=rel_path,
            reason=f"PHP file {change_type} in data directory",
            detail=f"Size: {entry.size}, Hash: {entry.hash}",
        ))

    # Hidden files
    if basename.startswith(".") and lc.endswith(".php"):
        findings.append(SuspiciousFile(
            path=rel_path,
            reason=f"Hidden PHP file {change_type}",
            detail=f"Size: {entry.size}",
        ))

    # Suspiciously large single-line PHP (obfuscated backdoors)
    if lc.endswith(".php") and entry.size > 50_000:
        findings.append(SuspiciousFile(
            path=rel_path,
            reason=f"Large PHP file {change_type} (possible obfuscation)",
            detail=f"Size: {entry.size} bytes",
        ))

    # Files with encoded-looking names
    if re.search(r"[a-f0-9]{32,}", basename, re.IGNORECASE):
        findings.append(SuspiciousFile(
            path=rel_path,
            reason=f"Hash-like filename {change_type} (possible dropper)",
            detail=rel_path,
        ))


def save_diff_report(diff: SnapshotDiff, output_path: str) -> None:
    """Save snapshot diff to JSON for REDACTS reporting."""
    data = {
        "added": diff.added,
        "removed": diff.removed,
        "modified": diff.modified,
        "unchanged": diff.unchanged,
        "suspiciousFiles": [
            {"path": s.path, "reason": s.reason, "detail": s.detail}
            for s in diff.suspicious_files
        ],
    }
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
