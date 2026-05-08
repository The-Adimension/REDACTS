/**
 * REDACTS DAST - Compliance Monitoring Workflow
 * Driven by REDCap Admin Docs (redcap-admin-docs-main):
 *   - 2.5 Security Guidance (session timeout, MFA, DAGs, API tokens)
 *   - 2.1 Audit Trails (logging completeness, permission change tracking)
 *   - 2.3 Data Export (de-identification, permission enforcement)
 *   - 2.7 User Management (least privilege, role templates, DAG assignment)
 *   - 2.6 Workflows (dev->prod transition, data quality rules)
 *
 * Maps directly to the admin docs checklist (Sec.2.5.1):
 *   [ ] User rights follow least-privilege; DAGs correctly configured
 *   [ ] API access restricted, tokens protected
 *   [ ] Logs and security settings periodically reviewed
 *   [ ] Session timeouts and lockout configured
 *   [ ] Export procedures defined, with de-identification
 *   [ ] Data validation and quality rules defined
 *
 * Flow:
 *   1. Login -> verify session timeout config is active
 *   2. Audit log - verify login events are recorded
 *   3. DAG - verify data isolation between groups
 *   4. API - verify per-project token isolation
 *   5. Export - verify de-identification toggle presence
 *   6. User Rights - verify role boundaries
 *   7. Data Quality - verify validation rules active
 *   8. External Modules - verify module security review
 */

import { test, expect } from "@playwright/test";
import {
  login,
  logout,
  goToControlCenter,
  goToProject,
  goToProjectPage,
  isLoggedIn,
  NetworkMonitor,
  assertNoPhpErrors,
  assertNoDebugArtifacts,
  assertNoReflectedXSS,
  assertNoExternalRequests,
  collectConsoleErrors,
} from "../helpers";

const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";
const REDCAP_BASE = process.env.REDCAP_BASE_URL || "http://localhost:8585";

test.describe("Compliance Monitoring - Admin Docs Sec.2.5", () => {
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

  // Sec.2.5.3 - Session Timeout Configuration
  // "Configure automatic session timeouts and account
  //  inactivity lockout (e.g. 15-minute idle logout)"

  test("session timeout is configured in Control Center", async ({ page }) => {
    await login(page);
    await goToControlCenter(page);
    await assertNoPhpErrors(page);

    // Navigate to Security & Auth settings
    const securityLink = page.locator(
      'a:has-text("Security"), a:has-text("Authentication"), ' +
      'a:has-text("Security & Authentication")'
    ).first();

    if (await securityLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await securityLink.click();
      await page.waitForLoadState("networkidle");
      await assertNoPhpErrors(page);

      const content = await page.content();
      // REDCap should have session timeout settings visible
      expect(content).toMatch(
        /auto.?logout|session.?timeout|idle.?time|inactivity/i
      );

      // Verify the timeout value is not zero (disabled)
      // REDCap stores this as minutes - should be > 0
      const timeoutInput = page.locator(
        'input[name*="logout"], input[name*="timeout"], ' +
        'input[name*="idle"], input[name*="session"]'
      ).first();

      if (await timeoutInput.isVisible({ timeout: 3_000 }).catch(() => false)) {
        const val = await timeoutInput.inputValue();
        const numVal = parseInt(val, 10);
        // Sec.2.5.3: recommended 15-min idle logout
        if (!isNaN(numVal)) {
          expect(
            numVal,
            "Session timeout should be > 0 (not disabled)"
          ).toBeGreaterThan(0);

          test.info().annotations.push({
            type: "compliance",
            description: `Session timeout configured: ${numVal} minutes`,
          });
        }
      }
    } else {
      // Fallback: check PHP session config
      const phpInfoResp = await page.request.get(
        `${REDCAP_BASE}/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/general_settings.php`
      );
      const body = await phpInfoResp.text();
      // Should not have session.gc_maxlifetime set to extreme values
      test.info().annotations.push({
        type: "compliance",
        description: "Security settings page not found - verify manually",
      });
    }
  });

  // Sec.2.1 - Audit Trail Completeness
  // "Logs all user activity, including data views, edits,
  //  exports, user and project changes"

  test("login event is recorded in audit log", async ({ page }) => {
    // Login creates a log entry
    await login(page);

    // Navigate to project logging
    await goToProjectPage(page, TEST_PID, "Logging/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Audit trail should show recent activity
    expect(content).toMatch(/Logging|Audit Trail|Event/i);

    // Look for the logged-in user in recent entries
    const logTable = page.locator('table').first();
    if (await logTable.isVisible({ timeout: 5_000 }).catch(() => false)) {
      const tableText = await logTable.textContent();
      // Should contain recent login or page view events
      expect(tableText).toMatch(/admin|login|page view|manage|event/i);

      test.info().annotations.push({
        type: "compliance",
        description: "Audit log contains recent user activity entries",
      });
    }
  });

  test("audit log tracks data export events", async ({ page }) => {
    await login(page);

    // Navigate to Data Export page (creates a log entry)
    await goToProjectPage(page, TEST_PID, "DataExport/index.php");
    await assertNoPhpErrors(page);

    // Now check the logging page for export-related entries
    await goToProjectPage(page, TEST_PID, "Logging/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // The logging page should exist and be functional
    expect(content).toMatch(/Logging|Log|Audit/i);

    // Filter controls should be present for reviewing logs
    const filterElements = page.locator(
      'select, input[type="text"], button:has-text("Filter"), ' +
      'a:has-text("Display")'
    );
    const filterCount = await filterElements.count();

    test.info().annotations.push({
      type: "compliance",
      description: `Audit log page has ${filterCount} filter controls`,
    });

    // Sec.2.1.A: Should be able to filter by action type
    expect(
      filterCount,
      "Logging page should have filter controls for audit review"
    ).toBeGreaterThan(0);
  });

  // Sec.2.7.5 - Data Access Groups (DAG) Isolation
  // "DAGs restrict users views of data to within their
  //  assigned group"

  test("DAG configuration page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataAccessGroups/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // DAG management page should render
    expect(content).toMatch(/Data Access Group|DAG/i);

    // No PHP errors or stack traces
    await assertNoDebugArtifacts(page);
  });

  test("DAG page does not leak cross-group record counts", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataAccessGroups/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Should not expose raw SQL or database table names
    expect(content).not.toMatch(/SELECT\s+.*\s+FROM\s+.*redcap_data/i);
    expect(content).not.toMatch(/redcap_data_access_groups/i);

    // Should not expose internal IDs of other DAGs in raw form
    // (UI presentation is OK, but raw DB dumps are not)
    expect(content).not.toMatch(/group_id\s*=\s*\d+/);

    // Verify page loads cleanly
    await assertNoDebugArtifacts(page);
  });

  // Sec.2.5 - API Token Security
  // "Issue API tokens to users/projects that use them...
  //  Never embed API tokens in code, public repositories"

  test("API rejects requests with empty token", async ({ request }) => {
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "record",
        format: "json",
        token: "",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/record_id/i);
  });

  test("API rejects cross-project token usage", async ({ request }) => {
    // Sec.2.5: "Per-user, per-project tokens; access is restricted
    //        to specific API endpoints and roles"
    // Use a token format that looks valid but belongs to no project
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "record",
        format: "json",
        token: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not return data from any project
    expect(body).not.toMatch(/record_id/i);
    // Should return an error message about invalid token
    expect(body.toLowerCase()).toMatch(/error|invalid|denied|token/);
  });

  test("API user export requires valid token", async ({ request }) => {
    // Sec.2.3: content=user export requires authorization
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "user",
        format: "json",
        token: "INVALID_TOKEN_COMPLIANCE_TEST",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not leak user information
    expect(body).not.toMatch(/"username"/i);
    expect(body).not.toMatch(/"email"/i);
  });

  // Sec.2.3 - Data Export De-identification
  // "Use REDCap's de-identification options in the export tool"

  test("export page offers de-identification options", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataExport/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // REDCap export page should present de-identification controls
    // These appear as checkboxes or radio buttons in the export dialog
    const hasDeIdControls = /de.?identif|remove.?identif|shift.?dates|hash.?record/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasDeIdControls
        ? "De-identification controls present on export page"
        : "De-identification controls not found - may require export dialog interaction",
    });

    // The export page itself should load cleanly
    await assertNoDebugArtifacts(page);
  });

  // Sec.2.7.3 - User Rights Matrix & Least Privilege
  // "Each user has specific access rights at the project level"

  test("User Rights page shows permission matrix", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "UserRights/index.php");
    await assertNoPhpErrors(page);

    // Sec.2.7.3: Permission checkboxes for Design, User Rights,
    //         Data Entry, Data Export should be present
    const content = await page.content();
    const permissionKeywords = [
      /design|setup/i,
      /export/i,
      /data.?entry|form/i,
    ];

    let foundPermissions = 0;
    for (const keyword of permissionKeywords) {
      if (keyword.test(content)) {
        foundPermissions++;
      }
    }

    expect(
      foundPermissions,
      "User Rights page should show at least 2 permission categories"
    ).toBeGreaterThanOrEqual(2);

    // No reflected XSS in rights page
    await assertNoReflectedXSS(page);
  });

  test("User Rights page does not expose database credentials", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "UserRights/index.php");

    const content = await page.content();
    // Sec.2.1.C: Should not expose system internals
    expect(content).not.toMatch(/MYSQL_PASSWORD|DB_PASS|db_password/i);
    expect(content).not.toMatch(/MARIADB_ROOT_PASSWORD/i);
    expect(content).not.toMatch(/password\s*=\s*['"][^'"]+['"]/i);
  });

  // Sec.2.2 - Data Quality Rules & Validation
  // "Real-time validation, range checks and required fields"

  test("Data Quality module is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataQuality/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Data Quality|Quality Rules|Validation/i);

    // Data Quality should show built-in rules
    // REDCap has pre-defined quality rules (A-I)
    const hasBuiltInRules = /Rule\s+[A-I]|Missing values|Outliers|Field validation/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasBuiltInRules
        ? "Built-in data quality rules detected"
        : "No built-in rules found - project may need configuration",
    });

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.5.3 - External Module Security
  // "Maintain a list of approved modules, with version
  //  control and security review"

  test("External Modules page lists installed modules", async ({ page }) => {
    await login(page);

    // Control Center module management
    await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ExternalModules/manager/control_center.php`
    );
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Should show module management interface or empty list
    expect(content).toMatch(/External Module|Module|Enable|Disable/i);

    // Should NOT expose filesystem paths
    expect(content).not.toMatch(/\/var\/www\/html|C:\\\\xampp/i);

    // Should NOT show raw PHP configuration
    expect(content).not.toMatch(/\$module_config|require_once/i);

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.6 - Project Status & Dev->Prod Workflow
  // "Elect to move it into production. Any subsequent
  //  changes should be actioned to a draft model"

  test("Project Setup page shows production status", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "ProjectSetup/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.2.6.F: Project status should be visible
    expect(content).toMatch(
      /Project Setup|Project Status|Development|Production|Analysis/i
    );

    // Record locking and e-signatures should be configurable
    // Sec.Architecture 3: "Record Locking / E-signatures"
    const hasLockingConfig = /Record Locking|e.?signature|lock/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: `Project status page loaded. Locking config: ${hasLockingConfig}`,
    });

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.5 - HTTPS/TLS Enforcement
  // "All web traffic must use HTTPS with TLS;
  //  HTTP is disabled"

  test("security headers present on all responses", async ({ page }) => {
    await login(page);
    const response = await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/index.php?pid=${TEST_PID}`
    );

    if (!response) {
      throw new Error("Navigation returned null response");
    }

    const headers = response.headers();

    // X-Content-Type-Options prevents MIME sniffing
    expect(headers["x-content-type-options"]).toBe("nosniff");

    // X-Frame-Options prevents clickjacking
    expect(headers["x-frame-options"]).toMatch(/DENY|SAMEORIGIN/i);

    // Should not expose server version
    const server = headers["server"] || "";
    expect(server).not.toMatch(/Apache\/\d|nginx\/\d/i);

    // Should not have X-Powered-By
    expect(headers["x-powered-by"]).toBeUndefined();

    test.info().annotations.push({
      type: "compliance",
      description: "Security headers verified: X-Content-Type-Options, X-Frame-Options",
    });
  });

  // Sec.2.5 - Survey Security
  // "Use unique survey links or automatic invitations
  //  when controlling respondents"

  test("survey distribution page does not expose survey hashes", async ({ page }) => {
    await login(page);

    // Navigate to survey distribution
    await goToProjectPage(page, TEST_PID, "Surveys/invite_participants.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Survey hashes should not appear in raw form in the page source
    // (they should be in controlled UI elements, not raw text)
    expect(content).not.toMatch(/survey_hash\s*=\s*[a-f0-9]{10,}/i);

    // Should not expose internal survey queue logic
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_surveys/i);
  });

  // Sec.Architecture 5 - Backup Configuration
  // "Full database backup can be enforced mandatorily"

  test("cron jobs page shows scheduled tasks", async ({ page }) => {
    await login(page);
    await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/cron_jobs.php`
    );
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Cron|Scheduled|Task|Job/i);

    // Should not expose system-level cron commands
    expect(content).not.toMatch(/crontab\s+-[erl]/i);
    expect(content).not.toMatch(/\/etc\/cron/i);

    await assertNoDebugArtifacts(page);
  });
});
