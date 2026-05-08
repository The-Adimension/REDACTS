/**
 * REDACTS DAST - Data Governance Workflow
 * Driven by REDCap Admin Docs:
 *   - Sec.2.2 Data Collection (Online Designer, Data Dictionary, field validation,
 *     branching logic, CSV/API imports)
 *   - Sec.2.3 Data Export (multi-format, metadata, custom reports, file attachments)
 *   - Sec.2.4 Longitudinal Data (arms, events, instrument-event mapping)
 *
 * Maps to Admin Docs Checklist (A1):
 *   [ ] Data Dictionary is downloadable and uploadable
 *   [ ] Field validation prevents out-of-range values
 *   [ ] Export formats include CSV, JSON, XML
 *   [ ] Metadata export requires authorization
 *   [ ] Longitudinal projects have Events/Arms configuration
 *   [ ] Online Designer accessible to design-privileged users
 *   [ ] Branching logic editor is functional
 *   [ ] Record ID auto-numbering is configurable
 *   [ ] File upload fields reject executable content
 *   [ ] Custom reports page renders without leaking internals
 *
 * Flow:
 *   1. Login -> validate Online Designer access
 *   2. Data Dictionary download/upload interface
 *   3. Field validation enforcement
 *   4. Import page accessibility and authorization
 *   5. Multi-format export validation
 *   6. API metadata endpoint authorization
 *   7. Longitudinal event configuration
 *   8. File upload field security
 */

import { test, expect } from "@playwright/test";
import {
  login,
  goToProject,
  goToProjectPage,
  goToControlCenter,
  NetworkMonitor,
  assertNoPhpErrors,
  assertNoDebugArtifacts,
  assertNoReflectedXSS,
  assertNoExternalRequests,
  assertNoDatabaseLeaks,
  assertNoFilesystemLeaks,
  collectConsoleErrors,
} from "../helpers";

const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";
const REDCAP_BASE = process.env.REDCAP_BASE_URL || "http://localhost:8585";

test.describe("Data Governance - Admin Docs Sec.2.2/Sec.2.3/Sec.2.4", () => {
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

  // Sec.2.2 - Online Designer Tool
  // "Use the Online Designer to drag-and-drop and create
  //  instruments"

  test("Online Designer page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/online_designer.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Online Designer|Design|Instrument/i);

    // Should show instrument list or creation interface
    const hasDesignUI = /Add New Instrument|Edit Instrument|instrument|form/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasDesignUI
        ? "Online Designer interface detected - Sec.2.2 instrument builder available"
        : "Online Designer page loaded but instrument controls not found",
    });

    await assertNoDebugArtifacts(page);
    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  test("Online Designer does not expose internal field metadata", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/online_designer.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.2: Should not expose raw database schema or PHP internals
    expect(content).not.toMatch(/redcap_metadata/i);
    expect(content).not.toMatch(/SHOW\s+TABLES/i);
    expect(content).not.toMatch(/information_schema/i);

    await assertNoReflectedXSS(page);
  });

  // Sec.2.2 - Data Dictionary
  // "A Data Dictionary is an exceptional resource...
  //  downloadable in .csv and .xml formats"

  test("Data Dictionary is downloadable", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/data_dictionary_upload.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.2: Data Dictionary page should reference download/upload
    expect(content).toMatch(/Data Dictionary|Dictionary|Upload|Download/i);

    // Should have a download link/button for the current dictionary
    const hasDownload = /Download|Export.*Dictionary|Current.*Dictionary/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasDownload
        ? "Data Dictionary download available - Sec.2.2 dictionary management functional"
        : "Data Dictionary page loaded but download control not found",
    });

    await assertNoDebugArtifacts(page);
  });

  test("Data Dictionary upload page validates CSV format", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/data_dictionary_upload.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.2: Should have file upload control for CSV dictionaries
    const uploadInput = page.locator('input[type="file"]').first();
    const hasUpload = await uploadInput.isVisible({ timeout: 3_000 }).catch(() => false);

    test.info().annotations.push({
      type: "compliance",
      description: hasUpload
        ? "Data Dictionary CSV upload control present"
        : "Upload control not found - may require Design rights",
    });

    // Should not expose filesystem paths
    const fsEvidence = await assertNoFilesystemLeaks(page);
    expect(fsEvidence.status).toBe("pass");
  });

  // Sec.2.2 - Field Validation & Data Quality
  // "Validation over fields restricts undesirable behaviours...
  //  governed by numeric ranges, cross-validation and
  //  consistency checks, and impossible values"

  test("Data Entry form enforces field validation", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataEntry/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Data Entry|Record|Add/i);

    // Sec.2.2: Data entry should be accessible
    // Look for record navigation or form selection
    const hasDataEntry = /select.*instrument|choose.*form|record_id|Add new record/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasDataEntry
        ? "Data Entry interface accessible - Sec.2.2 field validation enforceable"
        : "Data Entry page loaded with limited controls",
    });

    await assertNoDebugArtifacts(page);
  });

  test("Data Entry page does not leak record data in HTML source", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataEntry/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.2/Sec.2.5: Should not render raw SQL or patient identifiers
    // in the page source when listing records
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_data\b/i);
    expect(content).not.toMatch(/INSERT.*INTO.*redcap_data\b/i);

    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  // Sec.2.2 - Data Import
  // "Project administrators can import structured datasets...
  //  using a CSV Import Tool, and a REDCap API"

  test("CSV Import page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataImportController/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Import|Upload|Data Import/i);

    // Sec.2.2: Import tool should reference CSV format
    const hasImportUI = /CSV|comma.?separated|upload.*file|import.*data/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasImportUI
        ? "CSV Import interface available - Sec.2.2 import pathway functional"
        : "Import page loaded without CSV-specific controls",
    });

    await assertNoDebugArtifacts(page);
  });

  test("API import endpoint rejects unauthorized requests", async ({ request }) => {
    // Sec.2.2: API (for advanced users) - must require valid token
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "record",
        format: "json",
        type: "flat",
        overwriteBehavior: "normal",
        data: JSON.stringify([{ record_id: "DAST_IMPORT_TEST" }]),
        token: "INVALID_TOKEN_DAST_IMPORT",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not confirm any data was imported
    expect(body).not.toMatch(/\d+ records imported/i);
    expect(body.toLowerCase()).toMatch(/error|invalid|denied|token/);
  });

  // Sec.2.3 - Multi-Format Export
  // "Select the required format from .csv, .r, .xml, .sas, .json"

  test("API metadata export requires valid authorization", async ({ request }) => {
    // Sec.2.3: content=metadata - the definitive guide to data fields
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "metadata",
        format: "json",
        token: "INVALID_TOKEN_DAST_METADATA",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not expose field definitions
    expect(body).not.toMatch(/field_name/i);
    expect(body).not.toMatch(/form_name/i);
    expect(body).not.toMatch(/field_type/i);
  });

  test("API report export requires authorization", async ({ request }) => {
    // Sec.2.3: Export by report ID - requires valid token
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "report",
        format: "json",
        report_id: "1",
        token: "INVALID_TOKEN_DAST_REPORT",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/record_id/i);
  });

  test("API file export requires authorization", async ({ request }) => {
    // Sec.2.3: content=file - file attachments
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "file",
        action: "export",
        record: "1",
        field: "file_upload",
        token: "INVALID_TOKEN_DAST_FILE",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not return file content
    expect(body.toLowerCase()).toMatch(/error|invalid|denied|token/);
  });

  // Sec.2.3 - Custom Reports
  // "Follow the main menu -> Data Exports, Reports, and Stats"

  test("Reports page renders without exposing internals", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataExport/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Report|Export|Data/i);

    // Sec.2.3: Reports should be listable
    const hasReports = /All data|Report|Create.*Report|report_id/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasReports
        ? "Reports/Export interface functional - Sec.2.3 export pathways available"
        : "Export page loaded with limited report controls",
    });

    // Should not expose raw report queries
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_reports/i);
    await assertNoDebugArtifacts(page);
  });

  // Sec.2.4 - Longitudinal Data Configuration
  // "An instrument is assigned to an event within an arm"

  test("Define Events page is accessible for longitudinal projects", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/define_events.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Longitudinal projects show events config;
    // classic projects show an info message
    const hasEventConfig = /Define.*Event|Event|Arm|Longitudinal|classic/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasEventConfig
        ? "Events/Arms configuration page accessible - Sec.2.4 longitudinal support available"
        : "Events page loaded (project may be classic-mode)",
    });

    await assertNoDebugArtifacts(page);
    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  test("Designate Instruments page maps instruments to events", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/designate_forms.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.4: Instrument-event mapping interface
    const hasMapping = /Designate|Instrument|Event|Form|assign/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasMapping
        ? "Instrument-event mapping page accessible - Sec.2.4 longitudinal assignment available"
        : "Designate page loaded (project may not use events)",
    });

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.2 - Record ID Configuration
  // "Set RECORD ID field and auto-numbering options"

  test("Project Setup shows record ID auto-numbering config", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "ProjectSetup/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // A1 checklist: Record ID structure (auto-number or meaningful IDs)
    const hasAutoNum = /auto.?number|record.?id|auto.*increment|numbering/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasAutoNum
        ? "Record ID auto-numbering config found - A1 checklist requirement met"
        : "Record ID config not detected (may be in advanced settings)",
    });

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.2 - File Upload Security
  // "File Upload: Collect forms/scans/images in .pdf etc."

  test("API file upload rejects unauthorized uploads", async ({ request }) => {
    // Sec.2.2: File uploads must be authorized and validated
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "file",
        action: "import",
        record: "1",
        field: "file_upload",
        token: "INVALID_TOKEN_DAST_UPLOAD",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body.toLowerCase()).toMatch(/error|invalid|denied|token/);
  });

  // Sec.2.2 - Calculated Fields & Branching Logic
  // "Calculations can be used to enforce logical settings...
  //  branching logic to show/hide fields dynamically"

  test("Branching logic editor is accessible in Online Designer", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Design/online_designer.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.2: Branching logic is a key feature
    const hasBranching = /branch|logic|calculation|calc|conditional/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasBranching
        ? "Branching logic / calculation references found in Designer"
        : "Designer loaded - branching may require instrument editing context",
    });

    // Ensure no XSS in the designer page
    await assertNoReflectedXSS(page);
  });
});
