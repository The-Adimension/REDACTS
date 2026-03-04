/**
 * REDACTS DAST — Authentication Helper
 * =====================================
 * Handles REDCap login, session management, and admin escalation.
 * Designed for REDCap 15.x–16.x login flow.
 */

import { Page, expect, BrowserContext } from "@playwright/test";

/**
 * REDCap version — derived from REDCAP_VERSION env var.
 * Must be set for version-specific URL routing to work.
 */
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";

export interface RedcapCredentials {
  username: string;
  password: string;
}

/**
 * Log in to REDCap via the standard login form.
 * Handles the initial login page, password change prompts,
 * and the "My Projects" landing page verification.
 */
export async function login(
  page: Page,
  creds?: RedcapCredentials
): Promise<void> {
  const username = creds?.username || process.env.REDCAP_ADMIN_USER || "admin";
  const password = creds?.password || process.env.REDCAP_ADMIN_PASS || "password123";

  await page.goto("/redcap/");

  // REDCap login form — field names vary by version
  const usernameField = page.locator(
    'input[name="username"], input[name="app_username"], input#username'
  ).first();
  const passwordField = page.locator(
    'input[name="password"], input[name="app_password"], input#password'
  ).first();

  await usernameField.fill(username);
  await passwordField.fill(password);

  // Submit — could be button or input[type=submit]
  const submitBtn = page.locator(
    'button[type="submit"], input[type="submit"], button#login_btn, #login-btn'
  ).first();

  await submitBtn.click();

  // Wait for post-login page — My Projects or Control Center
  await page.waitForURL(/\/(index\.php|Home\/|ControlCenter)/, {
    timeout: 30_000,
  });
}

/**
 * Navigate to the Control Center (admin area).
 */
export async function goToControlCenter(page: Page): Promise<void> {
  await page.goto(`/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/index.php`);
  await page.waitForLoadState("networkidle");
}

/**
 * Navigate to a specific project by PID.
 */
export async function goToProject(page: Page, pid: number): Promise<void> {
  await page.goto(`/redcap/redcap_v${REDCAP_VERSION}/index.php?pid=${pid}`);
  await page.waitForLoadState("networkidle");
}

/**
 * Navigate to a specific REDCap module page within a project.
 */
export async function goToProjectPage(
  page: Page,
  pid: number,
  pagePath: string
): Promise<void> {
  const url = `/redcap/redcap_v${REDCAP_VERSION}/${pagePath}${pagePath.includes("?") ? "&" : "?"}pid=${pid}`;
  await page.goto(url);
  await page.waitForLoadState("networkidle");
}

/**
 * Check if we're currently logged in.
 * Throws on unexpected errors — only returns false if
 * the logout link is genuinely absent.
 */
export async function isLoggedIn(page: Page): Promise<boolean> {
  // Look for logout link — present when authenticated
  const logoutLink = page.locator('a[href*="logout"], a:has-text("Log out")');
  return (await logoutLink.count()) > 0;
}

/**
 * Log out from REDCap.
 * Throws if the logout link exists but clicking it fails.
 */
export async function logout(page: Page): Promise<void> {
  const logoutLink = page.locator('a[href*="logout"], a:has-text("Log out")').first();
  const linkCount = await logoutLink.count();
  if (linkCount === 0) {
    throw new Error(
      "logout() called but no logout link found on page — " +
      "the session may already be expired or the page did not load correctly. " +
      `Current URL: ${page.url()}`
    );
  }
  await logoutLink.click();
  await page.waitForLoadState("networkidle");
}

/**
 * Store and reuse auth state to avoid re-login per test.
 */
export async function saveAuthState(
  context: BrowserContext,
  path: string = "/tmp/redcap-auth.json"
): Promise<void> {
  await context.storageState({ path });
}
