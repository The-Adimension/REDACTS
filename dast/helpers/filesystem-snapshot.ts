/**
 * REDACTS DAST — Filesystem Snapshot Helper
 * ==========================================
 * Takes before/after snapshots of the REDCap filesystem to detect
 * unexpected file changes during operations (especially upgrades).
 * Compares file lists, sizes, and content hashes.
 */

import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

export interface FileEntry {
  path: string;
  size: number;
  hash: string;
  mtime: string;
}

export interface SnapshotDiff {
  added: string[];
  removed: string[];
  modified: string[];
  unchanged: number;
  suspiciousFiles: SuspiciousFile[];
}

export interface SuspiciousFile {
  path: string;
  reason: string;
  detail: string;
}

/**
 * Take a snapshot of all files under a given directory.
 */
export function takeSnapshot(dir: string): Map<string, FileEntry> {
  const entries = new Map<string, FileEntry>();
  if (!fs.existsSync(dir)) return entries;

  walkDir(dir, dir, entries);
  return entries;
}

function walkDir(
  root: string,
  current: string,
  entries: Map<string, FileEntry>
): void {
  for (const item of fs.readdirSync(current, { withFileTypes: true })) {
    const full = path.join(current, item.name);
    const rel = path.relative(root, full);

    if (item.isDirectory()) {
      walkDir(root, full, entries);
    } else if (item.isFile()) {
      const stat = fs.statSync(full);
      const content = fs.readFileSync(full);
      const hash = crypto.createHash("sha256").update(content).digest("hex");

      entries.set(rel, {
        path: rel,
        size: stat.size,
        hash,
        mtime: stat.mtime.toISOString(),
      });
    }
  }
}

/**
 * Compare two snapshots and return the diff.
 */
export function diffSnapshots(
  before: Map<string, FileEntry>,
  after: Map<string, FileEntry>
): SnapshotDiff {
  const added: string[] = [];
  const removed: string[] = [];
  const modified: string[] = [];
  let unchanged = 0;
  const suspiciousFiles: SuspiciousFile[] = [];

  // Check for added and modified
  for (const [relPath, afterEntry] of after) {
    const beforeEntry = before.get(relPath);
    if (!beforeEntry) {
      added.push(relPath);
      checkSuspicious(relPath, afterEntry, "added", suspiciousFiles);
    } else if (beforeEntry.hash !== afterEntry.hash) {
      modified.push(relPath);
      checkSuspicious(relPath, afterEntry, "modified", suspiciousFiles);
    } else {
      unchanged++;
    }
  }

  // Check for removed
  for (const relPath of before.keys()) {
    if (!after.has(relPath)) {
      removed.push(relPath);
    }
  }

  return { added, removed, modified, unchanged, suspiciousFiles };
}

/**
 * Flag files that match INFINITERED/backdoor patterns.
 */
function checkSuspicious(
  relPath: string,
  entry: FileEntry,
  changeType: string,
  findings: SuspiciousFile[]
): void {
  const lc = relPath.toLowerCase();

  // Unexpected PHP in non-PHP directories
  if (lc.endsWith(".php") && (lc.includes("edocs/") || lc.includes("temp/"))) {
    findings.push({
      path: relPath,
      reason: `PHP file ${changeType} in data directory`,
      detail: `Size: ${entry.size}, Hash: ${entry.hash}`,
    });
  }

  // Hidden files
  if (path.basename(relPath).startsWith(".") && lc.endsWith(".php")) {
    findings.push({
      path: relPath,
      reason: `Hidden PHP file ${changeType}`,
      detail: `Size: ${entry.size}`,
    });
  }

  // Suspiciously large single-line PHP (obfuscated backdoors)
  if (lc.endsWith(".php") && entry.size > 50_000) {
    findings.push({
      path: relPath,
      reason: `Large PHP file ${changeType} (possible obfuscation)`,
      detail: `Size: ${entry.size} bytes`,
    });
  }

  // Files with encoded-looking names
  if (/[a-f0-9]{32,}/i.test(path.basename(relPath))) {
    findings.push({
      path: relPath,
      reason: `Hash-like filename ${changeType} (possible dropper)`,
      detail: relPath,
    });
  }
}

/**
 * Save snapshot diff to JSON for REDACTS reporting.
 */
export function saveDiffReport(
  diff: SnapshotDiff,
  outputPath: string
): void {
  fs.writeFileSync(outputPath, JSON.stringify(diff, null, 2), "utf-8");
}
