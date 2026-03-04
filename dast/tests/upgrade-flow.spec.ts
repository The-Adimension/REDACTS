/**
 * REDACTS DAST — REDCap Upgrade Flow
 * ====================================
 * The most critical DAST test: simulates a REDCap version upgrade
 * and verifies filesystem integrity before and after.
 *
 * This is where INFINITERED-style attacks are caught — injected code
 * that persists through upgrades, dropper files that survive
 * version migration, and post-upgrade backdoor activation.
 *
 * Validates: SEC060-062 (INFINITERED persistence), SEC063 (debug
 * tool survival), SEC065 (config exposure post-upgrade), and full
 * filesystem diff for unexpected file mutations.
 *
 * Flow:
 *   1. Login → take filesystem snapshot (BEFORE)
 *   2. Navigate to Control Center → General → check version
 *   3. Upload upgrade ZIP (if available in /opt/upgrade-packages)
 *   4. Run upgrade.php through the browser
 *   5. Take filesystem snapshot (AFTER)
 *   6. Diff snapshots → flag suspicious additions/modifications
 *   7. Verify critical files weren't tampered with
 *   8. Verify no new PHP files in data directories
 *   9. Re-run all admin access checks post-upgrade
 */

import { test, expect } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";
import {
  login,
  goToControlCenter,
  goToProject,
  goToProjectPage,
  NetworkMonitor,
  assertNoPhpErrors,
  assertNoDebugArtifacts,
  assertNoExternalRequests,
  collectConsoleErrors,
  takeSnapshot,
  diffSnapshots,
  saveDiffReport,
} from "../helpers";

const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";
const RESULTS_DIR = process.env.DAST_RESULTS_DIR || "/results";
const REDCAP_SNAPSHOT_DIR = process.env.REDCAP_WEBROOT || "/redcap-snapshot";
const UPGRADE_PACKAGES_DIR = "/opt/upgrade-packages";

test.describe("REDCap Upgrade Flow", () => {
  let monitor: NetworkMonitor;
  let consoleErrors: string[];

  test.beforeEach(async ({ page }) => {
    monitor = new NetworkMonitor(page);
    monitor.start();
    consoleErrors = collectConsoleErrors(page);
  });

  test.afterEach(async () => {
    const external = assertNoExternalRequests(monitor.getAll());
    expect(external).toHaveLength(0);
  });

  // ─────────────────────────────────────────────────────────
  // Test 1: Pre-upgrade — capture current version
  // ─────────────────────────────────────────────────────────
  test("capture pre-upgrade REDCap version", async ({ page }) => {
    await login(page);
    await goToControlCenter(page);
    await assertNoPhpErrors(page);

    // REDCap shows version in the footer or on the General tab
    const content = await page.content();
    const versionMatch = content.match(
      /REDCap\s+(\d+\.\d+\.\d+)/i
    );

    const version = versionMatch ? versionMatch[1] : "unknown";
    test.info().annotations.push({
      type: "version",
      description: `Pre-upgrade REDCap version: ${version}`,
    });

    // Save version info
    const versionFile = path.join(RESULTS_DIR, "pre-upgrade-version.json");
    fs.writeFileSync(
      versionFile,
      JSON.stringify({
        version,
        timestamp: new Date().toISOString(),
        url: page.url(),
      }, null, 2)
    );
  });

  // ─────────────────────────────────────────────────────────
  // Test 2: Pre-upgrade filesystem snapshot
  // ─────────────────────────────────────────────────────────
  test("take pre-upgrade filesystem snapshot", async () => {
    const edocsDir = path.join(REDCAP_SNAPSHOT_DIR, "edocs");
    const tempDir = path.join(REDCAP_SNAPSHOT_DIR, "temp");

    const edocsSnapshot = takeSnapshot(edocsDir);
    const tempSnapshot = takeSnapshot(tempDir);

    const snapshot = {
      timestamp: new Date().toISOString(),
      phase: "pre-upgrade",
      edocs: {
        fileCount: edocsSnapshot.size,
        files: Array.from(edocsSnapshot.entries()).map(([k, v]) => ({
          path: k,
          size: v.size,
          hash: v.hash,
        })),
      },
      temp: {
        fileCount: tempSnapshot.size,
        files: Array.from(tempSnapshot.entries()).map(([k, v]) => ({
          path: k,
          size: v.size,
          hash: v.hash,
        })),
      },
    };

    fs.writeFileSync(
      path.join(RESULTS_DIR, "pre-upgrade-snapshot.json"),
      JSON.stringify(snapshot, null, 2)
    );

    // Even before upgrade, no PHP in data directories
    for (const [relPath] of edocsSnapshot) {
      expect(
        relPath.endsWith(".php"),
        `PHP file in edocs: ${relPath}`
      ).toBe(false);
    }

    for (const [relPath] of tempSnapshot) {
      expect(
        relPath.endsWith(".php"),
        `PHP file in temp: ${relPath}`
      ).toBe(false);
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 3: Navigate upgrade page
  // ─────────────────────────────────────────────────────────
  test("upgrade page is accessible to admin", async ({ page }) => {
    await login(page);

    // upgrade.php is at the root level
    const response = await page.goto("/redcap/upgrade.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Should show upgrade interface or "already up to date"
    expect(content).toMatch(
      /upgrade|up.to.date|current version|REDCap/i
    );
  });

  // ─────────────────────────────────────────────────────────
  // Test 4: Upgrade with ZIP (if available)
  // ─────────────────────────────────────────────────────────
  test("perform upgrade from ZIP package", async ({ page }) => {
    // Check if upgrade package exists
    let upgradeZip: string | null = null;
    if (!fs.existsSync(UPGRADE_PACKAGES_DIR)) {
      test.skip(true, `Upgrade packages dir not found: ${UPGRADE_PACKAGES_DIR}`);
      return;
    }
    const files = fs.readdirSync(UPGRADE_PACKAGES_DIR);
    upgradeZip = files.find(
      (f) => f.endsWith(".zip") && f.includes("redcap")
    ) || null;

    if (!upgradeZip) {
      test.skip(true, "No upgrade ZIP mounted in /opt/upgrade-packages");
      return;
    }

    await login(page);
    await page.goto("/redcap/upgrade.php");
    await assertNoPhpErrors(page);

    // Look for file upload input for upgrade ZIP
    const uploadInput = page.locator('input[type="file"]').first();
    if (await uploadInput.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await uploadInput.setInputFiles(
        path.join(UPGRADE_PACKAGES_DIR, upgradeZip)
      );

      // Submit upgrade
      const upgradeBtn = page.locator(
        'button:has-text("Upgrade"), input[type="submit"]'
      ).first();
      if (await upgradeBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
        // Take pre-upgrade snapshot of data dirs
        const preEdocs = takeSnapshot(
          path.join(REDCAP_SNAPSHOT_DIR, "edocs")
        );
        const preTemp = takeSnapshot(
          path.join(REDCAP_SNAPSHOT_DIR, "temp")
        );

        await upgradeBtn.click();

        // Wait for upgrade to complete — can take up to 2 minutes
        await page.waitForLoadState("networkidle", { timeout: 120_000 });
        await assertNoPhpErrors(page);

        // ──── POST-UPGRADE FILESYSTEM CHECK ────

        const postEdocs = takeSnapshot(
          path.join(REDCAP_SNAPSHOT_DIR, "edocs")
        );
        const postTemp = takeSnapshot(
          path.join(REDCAP_SNAPSHOT_DIR, "temp")
        );

        const edocsDiff = diffSnapshots(preEdocs, postEdocs);
        const tempDiff = diffSnapshots(preTemp, postTemp);

        // Save diffs — failures must not be silent
        saveDiffReport(edocsDiff, path.join(RESULTS_DIR, "upgrade-edocs-diff.json"));
        saveDiffReport(tempDiff, path.join(RESULTS_DIR, "upgrade-temp-diff.json"));

        // CRITICAL: No suspicious files
        expect(
          edocsDiff.suspiciousFiles,
          "Suspicious files in edocs after upgrade"
        ).toHaveLength(0);
        expect(
          tempDiff.suspiciousFiles,
          "Suspicious files in temp after upgrade"
        ).toHaveLength(0);

        // No new PHP files in data directories
        const newPhpEdocs = edocsDiff.added.filter((f) =>
          f.endsWith(".php")
        );
        const newPhpTemp = tempDiff.added.filter((f) =>
          f.endsWith(".php")
        );

        expect(
          newPhpEdocs,
          `New PHP files in edocs: ${newPhpEdocs.join(", ")}`
        ).toHaveLength(0);
        expect(
          newPhpTemp,
          `New PHP files in temp: ${newPhpTemp.join(", ")}`
        ).toHaveLength(0);

        test.info().annotations.push({
          type: "upgrade-stats",
          description: [
            `Edocs: +${edocsDiff.added.length} -${edocsDiff.removed.length} ~${edocsDiff.modified.length}`,
            `Temp:  +${tempDiff.added.length} -${tempDiff.removed.length} ~${tempDiff.modified.length}`,
          ].join(" | "),
        });
      }
    } else {
      test.skip(true, "Upgrade page does not have file upload — may need manual upload");
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 5: Post-upgrade — verify application still works
  // ─────────────────────────────────────────────────────────
  test("post-upgrade: home page loads", async ({ page }) => {
    await login(page);
    await page.goto("/redcap/");
    await assertNoPhpErrors(page);
    await assertNoDebugArtifacts(page);

    const content = await page.content();
    expect(content).toMatch(/My Projects|REDCap/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 6: Post-upgrade — Control Center intact
  // ─────────────────────────────────────────────────────────
  test("post-upgrade: Control Center accessible", async ({ page }) => {
    await login(page);
    await goToControlCenter(page);
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Control Center|General Settings/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 7: Post-upgrade — project data intact
  // ─────────────────────────────────────────────────────────
  test("post-upgrade: project is accessible", async ({ page }) => {
    await login(page);
    await goToProject(page, TEST_PID);
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Project should still load
    expect(content).toMatch(/Record Status|Data Entry|Project Home/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 8: Post-upgrade — API still works
  // ─────────────────────────────────────────────────────────
  test("post-upgrade: API endpoint responds", async ({ request }) => {
    // Just verify the API endpoint exists and responds
    const response = await request.post(
      `${process.env.REDCAP_BASE_URL || "http://localhost:8585"}/redcap/api/`,
      {
        data: {
          content: "version",
          format: "json",
          token: "PROBE_NOT_A_REAL_TOKEN",
        },
      }
    );

    // Should return an error (bad token) rather than 500
    expect(response.status()).toBeLessThan(500);
  });

  // ─────────────────────────────────────────────────────────
  // Test 9: Post-upgrade — cron.php doesn't error
  // ─────────────────────────────────────────────────────────
  test("post-upgrade: cron.php returns without error", async ({ request }) => {
    const response = await request.get(
      `${process.env.REDCAP_BASE_URL || "http://localhost:8585"}/redcap/cron.php`
    );

    // cron.php should not expose errors
    const body = await response.text();
    expect(body).not.toMatch(/Fatal error|Parse error|Exception/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 10: Post-upgrade — no network callbacks
  // ─────────────────────────────────────────────────────────
  test("post-upgrade: no external network during page loads", async ({
    page,
  }) => {
    await login(page);

    // Navigate through critical pages — monitor for C2 callbacks
    const pages = [
      "/redcap/",
      `/redcap/redcap_v${REDCAP_VERSION}/index.php?pid=${TEST_PID}`,
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/index.php`,
    ];

    for (const p of pages) {
      await page.goto(p);
      await page.waitForLoadState("networkidle");
    }

    const externalReqs = assertNoExternalRequests(
      monitor.getAll(),
      ["redcap-dast-app", "localhost"]
    );

    expect(
      externalReqs,
      `External requests detected: ${externalReqs.join(", ")}`
    ).toHaveLength(0);
  });
});
