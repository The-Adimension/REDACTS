/**
 * REDACTS DAST — Security Assertions
 * ====================================
 * Reusable Playwright assertions that map directly to REDACTS
 * SEC rules, validating dynamic behaviour matches static findings.
 */

import { Page, Response, expect } from "@playwright/test";

/**
 * Assert no sensitive data leaks in HTTP response headers.
 * Maps to: SEC031 (information disclosure headers)
 */
export async function assertNoInfoLeakHeaders(response: Response): Promise<void> {
  const headers = response.headers();

  // Server version should be suppressed
  const server = headers["server"] || "";
  expect(server).not.toMatch(/Apache\/\d|PHP\/\d|nginx\/\d/i);

  // X-Powered-By should not exist
  expect(headers["x-powered-by"]).toBeUndefined();

  // Security headers should be present
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["x-frame-options"]).toMatch(/DENY|SAMEORIGIN/i);
}

/**
 * Assert a page does not reflect user input unsanitized (XSS check).
 * Maps to: SEC010, SEC073 (Messenger XSS), SEC074 (Design XSS)
 */
export async function assertNoReflectedXSS(
  page: Page,
  payload: string = '<script>alert("REDACTS")</script>'
): Promise<void> {
  const bodyContent = await page.content();
  // The payload should NOT appear unescaped in the DOM
  expect(bodyContent).not.toContain(payload);
  // Check that it was properly encoded
  const encoded = payload
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  // Either absent or encoded — both are safe
}

/**
 * Assert PHP errors are not displayed to the user.
 * Maps to: SEC022 (error display in production)
 */
export async function assertNoPhpErrors(page: Page): Promise<void> {
  const content = await page.content();
  const errorPatterns = [
    /Fatal error:/i,
    /Parse error:/i,
    /Warning:.*on line \d+/i,
    /Notice:.*on line \d+/i,
    /Stack trace:/i,
    /Uncaught Exception/i,
    /<b>Warning<\/b>:/i,
    /Deprecated:.*on line/i,
  ];

  for (const pattern of errorPatterns) {
    expect(content).not.toMatch(pattern);
  }
}

/**
 * Assert no debug/development artifacts visible.
 * Maps to: SEC030, SEC063 (debug tool detection)
 */
export async function assertNoDebugArtifacts(page: Page): Promise<void> {
  const content = await page.content();
  const debugPatterns = [
    /phpinfo\(\)/i,
    /var_dump\(/i,
    /print_r\(/i,
    /debug_backtrace/i,
    /xdebug/i,
    /Adminer/i,
    /phpMyAdmin/i,
  ];

  for (const pattern of debugPatterns) {
    expect(content).not.toMatch(pattern);
  }
}

/**
 * Assert that a file download has expected content type and
 * does not contain injected code.
 * Maps to: SEC076 (file export bypass), SEC074 (PDF injection)
 */
export async function assertCleanDownload(
  response: Response,
  expectedMime: string
): Promise<void> {
  const ct = response.headers()["content-type"] || "";
  expect(ct).toContain(expectedMime);

  const body = await response.body();
  const text = body.toString("utf-8");

  // Check for code injection in non-PHP downloads
  if (!expectedMime.includes("php")) {
    expect(text).not.toMatch(/eval\s*\(/);
    expect(text).not.toMatch(/base64_decode\s*\(/);
    expect(text).not.toMatch(/<\?php/i);
  }
}

/**
 * Assert session cookie security attributes.
 * Maps to: SEC021 (session fixation), SEC071 (cookie deserialization)
 */
export async function assertSecureCookies(page: Page): Promise<void> {
  const cookies = await page.context().cookies();

  for (const cookie of cookies) {
    if (cookie.name.toLowerCase().includes("sess")) {
      // Session cookies must be HttpOnly
      expect(cookie.httpOnly).toBe(true);
      // SameSite should be Lax or Strict
      expect(["Lax", "Strict"]).toContain(cookie.sameSite);
    }
  }
}

/**
 * Assert that a network request did not go to an external/unexpected host.
 * Detects C2 callbacks and data exfiltration.
 * Maps to: SEC060-062 (INFINITERED IoCs)
 */
export function assertNoExternalRequests(
  requests: { url: string }[],
  allowedHosts: string[] = ["redcap-dast-app", "localhost"]
): string[] {
  const violations: string[] = [];

  for (const req of requests) {
    try {
      const url = new URL(req.url);
      if (!allowedHosts.includes(url.hostname)) {
        violations.push(req.url);
      }
    } catch {
      // Malformed URL — NOT safe to ignore.
      // Could be a C2 callback or injection artifact.
      violations.push(`MALFORMED_URL: ${req.url}`);
    }
  }

  return violations;
}

/**
 * Monitor console for suspicious JavaScript execution.
 * Maps to: SEC040 (nested encoding backdoor)
 */
export function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      errors.push(msg.text());
    }
  });
  return errors;
}
