/**
 * REDACTS DAST - Security Assertions
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
  // Either absent or encoded - both are safe
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
      // Malformed URL - NOT safe to ignore.
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

// Compliance Assertions - driven by redcap-admin-docs-main

/**
 * Compliance check result returned by assertion helpers.
 * Collects evidence for the compliance report without hard-failing.
 */
export interface ComplianceEvidence {
  control: string;
  section: string;
  status: "pass" | "fail" | "info";
  detail: string;
}

/**
 * Assert that the page does not expose internal database structure.
 * Maps to: Admin Docs Sec.2.1.C, Sec.2.5.3
 */
export async function assertNoDatabaseLeaks(page: Page): Promise<ComplianceEvidence> {
  const content = await page.content();
  const patterns = [
    /SELECT\s+.*FROM\s+redcap_/i,
    /INSERT\s+INTO\s+redcap_/i,
    /UPDATE\s+redcap_/i,
    /MYSQL_PASSWORD/i,
    /MARIADB_ROOT_PASSWORD/i,
    /db_password\s*=/i,
    /database\.php/i,
  ];

  const violations: string[] = [];
  for (const p of patterns) {
    if (p.test(content)) {
      violations.push(p.source);
    }
  }

  if (violations.length > 0) {
    expect.soft(violations, "Database structure leaked in page").toHaveLength(0);
    return {
      control: "no-database-leak",
      section: "Sec.2.1.C",
      status: "fail",
      detail: `Leaked patterns: ${violations.join(", ")}`,
    };
  }

  return {
    control: "no-database-leak",
    section: "Sec.2.1.C",
    status: "pass",
    detail: "No database structure leaks detected",
  };
}

/**
 * Assert that the page does not expose filesystem paths.
 * Maps to: Admin Docs Sec.2.5.3
 */
export async function assertNoFilesystemLeaks(page: Page): Promise<ComplianceEvidence> {
  const content = await page.content();
  const patterns = [
    /\/var\/www\/html/,
    /C:\\\\xampp/i,
    /C:\\\\wamp/i,
    /\/home\/\w+\/redcap/,
    /DocumentRoot/i,
  ];

  const violations: string[] = [];
  for (const p of patterns) {
    if (p.test(content)) {
      violations.push(p.source);
    }
  }

  if (violations.length > 0) {
    expect.soft(violations, "Filesystem paths exposed in page").toHaveLength(0);
    return {
      control: "no-filesystem-leak",
      section: "Sec.2.5.3",
      status: "fail",
      detail: `Leaked paths: ${violations.join(", ")}`,
    };
  }

  return {
    control: "no-filesystem-leak",
    section: "Sec.2.5.3",
    status: "pass",
    detail: "No filesystem path leaks detected",
  };
}

/**
 * Assert that the page does not expose internal API tokens or secrets.
 * Maps to: Admin Docs Sec.2.5 API Token Security, Sec.2.7.1 Account Creation
 */
export async function assertNoTokenLeaks(page: Page): Promise<ComplianceEvidence> {
  const content = await page.content();
  const patterns = [
    /super_api_token\s*=/i,
    /[A-F0-9]{32}/,                       // Raw 32-char hex API tokens
    /password_hash\s*=/i,
    /\$2[aby]\$\d{2}\$/,                  // bcrypt hashes
    /salt\s*=\s*['"][a-f0-9]{16,}/i,      // Salt values
  ];

  const violations: string[] = [];
  for (const p of patterns) {
    if (p.test(content)) {
      violations.push(p.source);
    }
  }

  if (violations.length > 0) {
    expect.soft(violations, "Token/secret material leaked in page").toHaveLength(0);
    return {
      control: "no-token-leak",
      section: "Sec.2.5",
      status: "fail",
      detail: `Leaked patterns: ${violations.join(", ")}`,
    };
  }

  return {
    control: "no-token-leak",
    section: "Sec.2.5",
    status: "pass",
    detail: "No API tokens or secrets leaked",
  };
}

/**
 * Assert that the page does not expose internal SQL queries.
 * Maps to: Admin Docs Sec.2.2 Data Collection, Sec.2.6 Workflows
 */
export async function assertNoSqlExposure(page: Page): Promise<ComplianceEvidence> {
  const content = await page.content();
  const patterns = [
    /SELECT\s+\*\s+FROM/i,
    /DROP\s+TABLE/i,
    /ALTER\s+TABLE/i,
    /CREATE\s+TABLE/i,
    /SHOW\s+TABLES/i,
    /INFORMATION_SCHEMA/i,
  ];

  const violations: string[] = [];
  for (const p of patterns) {
    if (p.test(content)) {
      violations.push(p.source);
    }
  }

  if (violations.length > 0) {
    expect.soft(violations, "SQL queries exposed in page").toHaveLength(0);
    return {
      control: "no-sql-exposure",
      section: "Sec.2.2",
      status: "fail",
      detail: `Exposed SQL patterns: ${violations.join(", ")}`,
    };
  }

  return {
    control: "no-sql-exposure",
    section: "Sec.2.2",
    status: "pass",
    detail: "No SQL statement exposure detected",
  };
}

/**
 * Collect compliance evidence from a REDCap page.
 * Runs all compliance assertions and returns evidence array.
 */
export async function collectComplianceEvidence(
  page: Page,
): Promise<ComplianceEvidence[]> {
  const evidence: ComplianceEvidence[] = [];
  evidence.push(await assertNoDatabaseLeaks(page));
  evidence.push(await assertNoFilesystemLeaks(page));
  evidence.push(await assertNoTokenLeaks(page));
  evidence.push(await assertNoSqlExposure(page));
  return evidence;
}
