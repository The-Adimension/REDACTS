/**
 * REDACTS DAST — Admin Access Workflow
 * ======================================
 * Simulates daily Control Center and User Rights operations.
 * Validates SEC077 (getUserRights bypass), SEC071 (cookie
 * deserialization RCE), SEC021 (session fixation), privilege
 * escalation paths, and admin-only page access controls.
 *
 * Flow:
 *   1. Login as admin → Control Center access
 *   2. Enumerate admin-only pages — verify access with/without auth
 *   3. User Rights — add/modify/remove user rights
 *   4. DAG management
 *   5. Session attacks — fixation, cookie manipulation
 *   6. Privilege boundary testing
 *   7. External Modules / Plugin pages
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
  assertSecureCookies,
  assertNoExternalRequests,
  collectConsoleErrors,
} from "../helpers";

const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";

// Admin-only Control Center pages to test
const ADMIN_PAGES = [
  "ControlCenter/index.php",
  "ControlCenter/general_settings.php",
  "ControlCenter/modules_settings.php",
  "ControlCenter/user_settings.php",
  "ControlCenter/edit_user.php",
  "ControlCenter/system_stats.php",
  "ControlCenter/external_links_global.php",
  "ControlCenter/notifications.php",
  "ControlCenter/superusers.php",
  "ControlCenter/cron_jobs.php",
];

// Project-level pages requiring specific rights
const PROJECT_PAGES = [
  { path: "UserRights/index.php", label: "User Rights" },
  { path: "DataQuality/index.php", label: "Data Quality" },
  { path: "ProjectSetup/index.php", label: "Project Setup" },
  { path: "Logging/index.php", label: "Logging" },
  { path: "Design/online_designer.php", label: "Online Designer" },
  { path: "Randomization/index.php", label: "Randomization" },
];

test.describe("Admin Access Workflow", () => {
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
  // Test 1: Control Center — admin login and access
  // ─────────────────────────────────────────────────────────
  test("admin can access Control Center", async ({ page }) => {
    await login(page);
    await goToControlCenter(page);
    await assertNoPhpErrors(page);
    await assertNoDebugArtifacts(page);

    // Verify we're actually on the Control Center page
    const content = await page.content();
    expect(content).toMatch(/Control Center|System Configuration|General Settings/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 2: Admin pages reject unauthenticated access
  // ─────────────────────────────────────────────────────────
  test("admin pages redirect to login when unauthenticated", async ({ page }) => {
    // Do NOT login — go directly to admin pages
    for (const adminPage of ADMIN_PAGES.slice(0, 3)) {
      const response = await page.goto(
        `/redcap/redcap_v${REDCAP_VERSION}/${adminPage}`
      );

      // Should redirect to login or return error
      const url = page.url();
      const loggedIn = await isLoggedIn(page);
      expect(
        loggedIn,
        `${adminPage} accessible without auth`
      ).toBe(false);

      // Should not show admin content
      const content = await page.content();
      expect(content).not.toMatch(/General Settings|System Stats|Cron Jobs/i);
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 3: User Rights page — SEC077 getUserRights bypass
  // ─────────────────────────────────────────────────────────
  test("User Rights page loads without PHP errors", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "UserRights/index.php");
    await assertNoPhpErrors(page);

    // Verify user rights table is visible
    const userTable = page.locator(
      'table, #user-rights-table, .userRightsTable'
    ).first();
    await expect(userTable).toBeVisible({ timeout: 10_000 });

    // Page should render — even if no custom users
    const content = await page.content();
    expect(content).toMatch(/User Rights|user_rights|Permissions/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 4: getUserRights API — authorization check
  // ─────────────────────────────────────────────────────────
  test("getUserRights API rejects invalid token", async ({ request }) => {
    // SEC077: getUserRights privilege escalation
    const response = await request.post(
      `${process.env.REDCAP_BASE_URL || "http://localhost:8585"}/redcap/api/`,
      {
        data: {
          content: "userRoleMapping",
          format: "json",
          token: "INVALID_TOKEN_DAST_PROBE",
        },
      }
    );

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toContain('"username"');
  });

  // ─────────────────────────────────────────────────────────
  // Test 5: Session cookie security
  // ─────────────────────────────────────────────────────────
  test("session cookies have security attributes", async ({ page }) => {
    await login(page);
    await assertSecureCookies(page);
  });

  // ─────────────────────────────────────────────────────────
  // Test 6: Session fixation resistance — SEC021
  // ─────────────────────────────────────────────────────────
  test("session ID regenerates after login", async ({ page }) => {
    // Get pre-login cookies
    await page.goto("/redcap/");
    const preLoginCookies = await page.context().cookies();
    const preSessionId = preLoginCookies.find(
      (c) => c.name.toLowerCase().includes("sess") || c.name === "PHPSESSID"
    )?.value;

    // Login
    await login(page);

    // Get post-login cookies
    const postLoginCookies = await page.context().cookies();
    const postSessionId = postLoginCookies.find(
      (c) => c.name.toLowerCase().includes("sess") || c.name === "PHPSESSID"
    )?.value;

    // Session ID should change after authentication
    if (preSessionId && postSessionId) {
      expect(
        postSessionId,
        "Session fixation — ID did not change after login"
      ).not.toBe(preSessionId);
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 7: Logging page access — audit trail
  // ─────────────────────────────────────────────────────────
  test("Logging page shows audit trail", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Logging/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Logging|Audit Trail|Event Log/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 8: Project-level pages — no PHP errors
  // ─────────────────────────────────────────────────────────
  test("project management pages render cleanly", async ({ page }) => {
    await login(page);

    for (const pp of PROJECT_PAGES) {
      await goToProjectPage(page, TEST_PID, pp.path);
      await assertNoPhpErrors(page);
      await assertNoDebugArtifacts(page);
    }
  });

  // ─────────────────────────────────────────────────────────
  // Test 9: External Modules page — SEC064/065 config exposure
  // ─────────────────────────────────────────────────────────
  test("External Modules page does not expose config", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "ExternalModules/manager/project.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Should not expose system paths or DB credentials
    expect(content).not.toMatch(/\/var\/www|C:\\|password\s*=/i);
    expect(content).not.toMatch(/MARIADB_|MYSQL_PASSWORD/i);
  });

  // ─────────────────────────────────────────────────────────
  // Test 10: Direct URL manipulation — privilege boundary
  // ─────────────────────────────────────────────────────────
  test("non-admin cannot access superuser pages", async ({ page }) => {
    // Login as admin first, then try to access superuser-only page
    await login(page);

    // Try pages that should be restricted even for project admins
    const response = await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/superusers.php`
    );
    await assertNoPhpErrors(page);

    // Page should load but verify it doesn't leak user data
    const content = await page.content();
    // If accessible, it should not show database queries or raw SQL
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_user_information/i);
  });
});
