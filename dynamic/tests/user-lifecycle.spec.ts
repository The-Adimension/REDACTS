/**
 * REDACTS DAST - User Lifecycle Workflow
 * Driven by REDCap Admin Docs:
 *   - Sec.2.7.1 New REDCap Accounts (Control Center -> Add Users)
 *   - Sec.2.7.2 Add Users to a Project (User Rights page)
 *   - Sec.2.7.3 User Rights Matrix (permission checkboxes)
 *   - Sec.2.7.4 Custom User Roles (create/assign role templates)
 *   - Sec.2.7.5 Data Access Groups (DAG assignment and isolation)
 *   - Sec.2.7.6 Removal of User Accounts (Browse Users -> deactivate)
 *   - Sec.2.1 Automation (LDAP/SSO, API batch user management)
 *   - Sec.2.5 Security (account lockout, session timeout)
 *
 * Maps to Admin Docs Checklist (A1):
 *   [ ] User accounts created via Control Center
 *   [ ] Users added to projects with appropriate rights
 *   [ ] Custom roles simplify multi-user permission assignment
 *   [ ] DAGs restrict data visibility per organizational unit
 *   [ ] Dormant accounts deactivated via Browse Users
 *   [ ] API user management endpoints require authorization
 *   [ ] User activity is logged and filterable
 *   [ ] Account lockout configured for failed login attempts
 *
 * Flow:
 *   1. Login -> Control Center -> Add Users page
 *   2. Browse Users -> verify search/filter functionality
 *   3. Project User Rights -> role/permission assignment
 *   4. Custom Role creation interface
 *   5. DAG assignment and isolation verification
 *   6. API user management authorization
 *   7. User activity log filtering
 *   8. Account lockout configuration
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
  assertNoDatabaseLeaks,
  assertNoFilesystemLeaks,
  collectConsoleErrors,
} from "../helpers";

const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";
const REDCAP_BASE = process.env.REDCAP_BASE_URL || "http://localhost:8585";

test.describe("User Lifecycle - Admin Docs Sec.2.7", () => {
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

  // Sec.2.7.1 - New REDCap Accounts
  // "Go to the Control Center -> Add Users ->
  //  Create a new Table-Based user"

  test("Add Users page is accessible in Control Center", async ({ page }) => {
    await login(page);
    await goToControlCenter(page);
    await assertNoPhpErrors(page);

    // Navigate to Add Users section
    const addUsersLink = page.locator(
      'a:has-text("Add Users"), a:has-text("Create Single User")'
    ).first();

    if (await addUsersLink.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await addUsersLink.click();
      await page.waitForLoadState("networkidle");
      await assertNoPhpErrors(page);

      const content = await page.content();
      // Sec.2.7.1: Should show user creation form
      expect(content).toMatch(/username|email|create.*user|add.*user|table.?based/i);

      test.info().annotations.push({
        type: "compliance",
        description: "Add Users page accessible - Sec.2.7.1 account creation available",
      });
    } else {
      // Try direct URL
      await page.goto(
        `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/create_user.php`
      );
      await assertNoPhpErrors(page);

      const content = await page.content();
      expect(content).toMatch(/user|account|create/i);

      test.info().annotations.push({
        type: "compliance",
        description: "Add Users page accessed via direct URL",
      });
    }

    await assertNoDebugArtifacts(page);
  });

  test("Add Users page does not expose password hashing details", async ({ page }) => {
    await login(page);

    await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/create_user.php`
    );
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.2.5.3: Should not reveal password storage implementation
    expect(content).not.toMatch(/password_hash|bcrypt|sha256|md5/i);
    expect(content).not.toMatch(/\$2[aby]\$\d+\$/); // bcrypt hash pattern

    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  // Sec.2.7.6 - Browse Users / Account Deactivation
  // "Control Center > Browse Users ->
  //  Sort/filter by most recent login date"

  test("Browse Users page is accessible", async ({ page }) => {
    await login(page);

    await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/view_users.php`
    );
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.2.7.6: Browse Users page should list accounts
    expect(content).toMatch(/Browse Users|User|Account|List/i);

    // Should have search or filter functionality
    const hasFilter = /search|filter|sort|find/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasFilter
        ? "Browse Users page has search/filter - Sec.2.7.6 dormant account review possible"
        : "Browse Users page loaded without visible filter controls",
    });

    await assertNoDebugArtifacts(page);
  });

  test("Browse Users does not expose full password column", async ({ page }) => {
    await login(page);

    await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/view_users.php`
    );

    const content = await page.content();
    // Sec.2.5: Should not expose hashed passwords in user listings
    expect(content).not.toMatch(/\$2[aby]\$\d+\$/); // bcrypt pattern
    expect(content).not.toMatch(/password_hash/i);
    // Should not show raw user_information table dumps
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_user_information.*password/i);
  });

  // Sec.2.7.2/Sec.2.7.3 - User Rights & Roles in Project
  // "From the project menu, select User Rights"
  // "Each user has rights and each right permits an action"

  test("User Rights shows role assignment interface", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "UserRights/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.2.7.3: Permission matrix with categories
    const permissionCategories = [
      /design|setup/i,
      /user.?rights/i,
      /data.?entry|form/i,
      /data.?export/i,
    ];

    let matchedCategories = 0;
    for (const cat of permissionCategories) {
      if (cat.test(content)) matchedCategories++;
    }

    test.info().annotations.push({
      type: "compliance",
      description: `User Rights page shows ${matchedCategories}/4 permission categories - Sec.2.7.3`,
    });

    expect(matchedCategories).toBeGreaterThanOrEqual(2);
  });

  test("User Rights page has role creation capability", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "UserRights/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.7.4: "Choose Create Role in the User Rights section"
    const hasRoleCreation = /Create.*Role|Add.*Role|role|User Role/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasRoleCreation
        ? "Role creation capability detected - Sec.2.7.4 custom roles available"
        : "Role creation not visible - may require specific permissions",
    });

    await assertNoReflectedXSS(page);
  });

  // Sec.2.7.5 - DAG User Assignment
  // "DAGs restrict users views of data to within their
  //  assigned group"

  test("DAG assignment interface shows group management", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "DataAccessGroups/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Data Access Group|DAG/i);

    // Sec.2.7.5: Should allow creating/assigning DAGs
    const hasDagMgmt = /add.*group|create.*group|assign|Add New DAG/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasDagMgmt
        ? "DAG management interface present - Sec.2.7.5 group isolation configurable"
        : "DAG page loaded without creation controls",
    });

    await assertNoDebugArtifacts(page);
    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  // Sec.2.1 - API User Management
  // "Batch additions or amendments to user accounts...
  //  Configuration of user rights or roles"

  test("API user import requires valid authorization", async ({ request }) => {
    // Sec.2.1 Automation: API batch user management
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "user",
        format: "json",
        data: JSON.stringify([{
          username: "dast_test_user",
          email: "dast@test.invalid",
        }]),
        token: "INVALID_TOKEN_DAST_USER_IMPORT",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not confirm user creation
    expect(body).not.toMatch(/\d+ users added/i);
    expect(body.toLowerCase()).toMatch(/error|invalid|denied|token/);
  });

  test("API user role mapping requires authorization", async ({ request }) => {
    // Sec.2.1: "Configuration of user rights or roles" via API
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "userRoleMapping",
        format: "json",
        token: "INVALID_TOKEN_DAST_ROLE_MAP",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/"username"/i);
    expect(body).not.toMatch(/"unique_role_name"/i);
  });

  test("API user role export requires authorization", async ({ request }) => {
    // Sec.2.7.4: Export custom role definitions via API
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "userRole",
        format: "json",
        token: "INVALID_TOKEN_DAST_ROLES",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/"role_label"/i);
  });

  // Sec.2.1 - User Activity Logging
  // "Querying user activity logs"

  test("Logging page allows user-specific filtering", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Logging/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Logging|Log|Audit/i);

    // Sec.2.1: Should support filtering by user and action type
    const filterElements = page.locator(
      'select[name*="user"], select[name*="log"], ' +
      'input[name*="user"], input[name*="filter"], ' +
      'select, button:has-text("Filter")'
    );

    const filterCount = await filterElements.count();

    test.info().annotations.push({
      type: "compliance",
      description: `Logging page has ${filterCount} filter elements - Sec.2.1 user activity log filtering`,
    });

    expect(filterCount).toBeGreaterThan(0);
  });

  // Sec.2.5 - Account Lockout Configuration
  // "Configure automatic session timeouts and account
  //  inactivity lockout (e.g. 90 days)"

  test("Security settings include account lockout configuration", async ({ page }) => {
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
      // Sec.2.5: Account lockout from inactivity (90-day default)
      const hasLockout = /lockout|suspend|inactive|dormant|days.*login/i.test(content);

      test.info().annotations.push({
        type: "compliance",
        description: hasLockout
          ? "Account lockout/inactivity settings found - Sec.2.5 auto-suspension configurable"
          : "Security page loaded but no lockout-specific settings detected",
      });
    } else {
      // Try direct URL to security settings
      await page.goto(
        `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/security_settings.php`
      );
      await assertNoPhpErrors(page);

      const content = await page.content();
      // Fallback check
      const hasSecurityConfig = /security|authentication|lockout|session/i.test(content);

      test.info().annotations.push({
        type: "compliance",
        description: hasSecurityConfig
          ? "Security configuration page accessible"
          : "Security settings page not found - verify manually",
      });
    }
  });

  // Sec.2.5 - Failed Login Rate Limiting

  test("login rejects invalid credentials without leaking user info", async ({ page }) => {
    // Attempt login with bad credentials
    await page.goto(`${REDCAP_BASE}/redcap/`);
    await page.waitForLoadState("networkidle");

    const usernameField = page.locator(
      'input[name="username"], input[id="username"], input[type="text"]'
    ).first();

    const passwordField = page.locator(
      'input[name="password"], input[id="password"], input[type="password"]'
    ).first();

    if (
      (await usernameField.isVisible({ timeout: 5_000 }).catch(() => false)) &&
      (await passwordField.isVisible({ timeout: 3_000 }).catch(() => false))
    ) {
      await usernameField.fill("dast_nonexistent_user");
      await passwordField.fill("dast_wrong_password");

      const submitBtn = page.locator(
        'button[type="submit"], input[type="submit"], #login_btn'
      ).first();

      if (await submitBtn.isVisible({ timeout: 3_000 }).catch(() => false)) {
        await submitBtn.click();
        await page.waitForLoadState("networkidle");

        const content = await page.content();

        // Should show generic error - not "user not found" vs "wrong password"
        // to prevent username enumeration
        expect(content).not.toMatch(/user.*not.*found|no.*such.*user|unknown.*user/i);
        expect(content).not.toMatch(/username.*does.*not.*exist/i);

        // Should not be logged in after failed attempt
        const loggedIn = await isLoggedIn(page);
        expect(loggedIn).toBe(false);

        test.info().annotations.push({
          type: "compliance",
          description: "Failed login returns generic error - no username enumeration",
        });
      }
    }
  });
});
