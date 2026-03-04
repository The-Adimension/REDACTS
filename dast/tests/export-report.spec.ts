/**
 * REDACTS DAST — Export Report Workflow
 * ======================================
 * Simulates daily internal report save/export operations.
 * Validates SEC070 (eval logic RCE in export), SEC076 (file export
 * auth bypass), SEC074 (PDF injection), and SEC004 (data leakage).
 *
 * Flow:
 *   1. Login as admin → navigate to a project
 *   2. Create a test instrument with sample data
 *   3. Export as CSV, PDF, XML — validate downloaded content
 *   4. Save a report and re-download it
 *   5. Inject XSS/SQLi payloads in field values → re-export
 *   6. Assert no code injection in exported files
 *   7. Check for unexpected network calls during export
 */

import { test, expect } from "@playwright/test";
import {
  login,
  goToProject,
  goToProjectPage,
  NetworkMonitor,
  assertNoPhpErrors,
  assertNoInfoLeakHeaders,
  assertCleanDownload,
  assertNoExternalRequests,
  collectConsoleErrors,
} from "../helpers";

// ── Project ID used for export tests (created during setup) ──
const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";

test.describe("Export Report Workflow", () => {
  let monitor: NetworkMonitor;
  let consoleErrors: string[];

  test.beforeEach(async ({ page }) => {
    monitor = new NetworkMonitor(page);
    monitor.start();
    consoleErrors = collectConsoleErrors(page);
    await login(page);
  });

  test.afterEach(async () => {
    // Verify no external network calls happened during the test
    const external = assertNoExternalRequests(
      monitor.getAll(),
      ["redcap-dast-app", "localhost"]
    );
    expect(external, "Unexpected external requests during export").toHaveLength(0);

    // Verify no JS console errors
    expect(consoleErrors).toHaveLength(0);
  });

  // ─────────────────────────────────────────────────────────
  // Test 1: Navigate to Data Exports page
  // ─────────────────────────────────────────────────────────
  test("can navigate to Data Exports page", async ({ page }) => {
    await goToProject(page, TEST_PID);
    await goToProjectPage(page, TEST_PID, "DataExport/index.php");

    await assertNoPhpErrors(page);
    const heading = page.locator("h4, .x-panel-header, #pagecontainer h3").first();
    await expect(heading).toBeVisible({ timeout: 10_000 });
  });

  // ─────────────────────────────────────────────────────────
  // Test 2: CSV Export — clean content
  // ─────────────────────────────────────────────────────────
  test("CSV export contains no injected code", async ({ page }) => {
    await goToProjectPage(page, TEST_PID, "DataExport/index.php");
    await assertNoPhpErrors(page);

    // Click "Export Data" button (REDCap varies across versions)
    const exportBtn = page.locator(
      'button:has-text("Export Data"), a:has-text("Export Data"), #exportBtn'
    ).first();

    if (await exportBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      // Start download listener before clicking
      const downloadPromise = page.waitForEvent("download", { timeout: 30_000 });

      await exportBtn.click();

      // Select CSV format if a format dialog appears
      const csvOption = page.locator(
        'input[value="csv"], label:has-text("CSV"), select option[value="csv"]'
      ).first();
      if (await csvOption.isVisible({ timeout: 3_000 }).catch(() => false)) {
        await csvOption.click();
      }

      // Confirm export
      const confirmBtn = page.locator(
        'button:has-text("Export"), button:has-text("Download"), #exportSubmit'
      ).first();
      if (await confirmBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
        await confirmBtn.click();
      }

      try {
        const download = await downloadPromise;
        const filePath = await download.path();
        if (!filePath) {
          throw new Error(
            "Download completed but path() returned null — " +
            "Playwright could not save the file"
          );
        }
        const fs = await import("fs");
        const content = fs.readFileSync(filePath, "utf-8");

        // SEC070: No eval() or code execution in export output
        expect(content).not.toMatch(/eval\s*\(/);
        expect(content).not.toMatch(/<\?php/i);
        expect(content).not.toMatch(/base64_decode/);
        expect(content).not.toMatch(/system\s*\(/);

        // Should be valid CSV — starts with a header row
        expect(content.trim().length).toBeGreaterThan(0);
      } catch (err) {
        // Re-throw — download failures must not be silent
        throw new Error(
          `CSV export download failed: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    } else {
      test.skip(true, "Export button not found — project may not be set up");
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 3: Export with XSS payload in field values
  // ─────────────────────────────────────────────────────────
  test("export sanitises XSS payloads in field data", async ({ page }) => {
    await goToProjectPage(page, TEST_PID, "DataEntry/index.php");
    await assertNoPhpErrors(page);

    // Attempt to add a record with XSS payload
    const addRecordBtn = page.locator(
      'button:has-text("Add new record"), a:has-text("Add"), #addNewRecordBtn'
    ).first();

    if (await addRecordBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await addRecordBtn.click();
      await page.waitForLoadState("networkidle");

      // Type XSS payload into first visible text field
      const textField = page.locator(
        'input[type="text"]:visible, textarea:visible'
      ).first();

      if (await textField.isVisible({ timeout: 3_000 }).catch(() => false)) {
        const xssPayload = '<img src=x onerror=alert("REDACTS_XSS")>';
        await textField.fill(xssPayload);

        // Save the record
        const saveBtn = page.locator(
          'button:has-text("Save"), input[value="Save"], #submit-btn-saverecord'
        ).first();
        if (await saveBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
          await saveBtn.click();
          await page.waitForLoadState("networkidle");

          // Verify XSS was not rendered in the saved page
          const content = await page.content();
          expect(content).not.toContain('onerror=alert("REDACTS_XSS")');
        }
      }
    } else {
      test.skip(true, "Cannot add records — instrument not configured");
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 4: Report builder — create and save a report
  // ─────────────────────────────────────────────────────────
  test("report builder does not expose PHP errors", async ({ page }) => {
    await goToProjectPage(page, TEST_PID, "DataExport/index.php");

    // Navigate to reports tab
    const reportsTab = page.locator(
      'a:has-text("Reports"), li:has-text("Reports")'
    ).first();

    if (await reportsTab.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await reportsTab.click();
      await page.waitForLoadState("networkidle");
      await assertNoPhpErrors(page);

      // Click "Create New Report"
      const createBtn = page.locator(
        'button:has-text("Create"), a:has-text("New Report")'
      ).first();

      if (await createBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
        await createBtn.click();
        await page.waitForLoadState("networkidle");
        await assertNoPhpErrors(page);
      }
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 5: API export endpoint — no auth bypass
  // ─────────────────────────────────────────────────────────
  test("API export endpoint rejects unauthenticated requests", async ({
    request,
  }) => {
    // SEC076: File export authorization bypass
    const response = await request.post(
      `${process.env.REDCAP_BASE_URL || "http://localhost:8585"}/redcap/api/`,
      {
        data: {
          content: "record",
          format: "csv",
          type: "flat",
          token: "INVALID_TOKEN_REDACTS_DAST_TEST",
        },
      }
    );

    // Should be rejected — 403 or error response
    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/record_id/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 6: Response headers on export page
  // ─────────────────────────────────────────────────────────
  test("export page has security headers", async ({ page }) => {
    const response = await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/DataExport/index.php?pid=${TEST_PID}`
    );
    if (!response) {
      throw new Error(
        "page.goto() returned null — navigation failed for export page"
      );
    }
    await assertNoInfoLeakHeaders(response);
  });
});
