import { defineConfig, devices } from "@playwright/test";

/**
 * REDACTS DAST — Playwright Configuration
 *
 * Headless Chromium against a live REDCap instance.
 * All tests run sequentially (--workers=1) because REDCap
 * has shared server-side state (sessions, DB rows).
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,             // 2 min per test — upgrades are slow
  expect: { timeout: 15_000 },

  reporter: [
    ["list"],
    ["json", { outputFile: process.env.DAST_RESULTS_DIR
      ? `${process.env.DAST_RESULTS_DIR}/dast-results.json`
      : "results/dast-results.json" }],
    ["html", { outputFolder: process.env.DAST_RESULTS_DIR
      ? `${process.env.DAST_RESULTS_DIR}/html-report`
      : "results/html-report",
      open: "never" }],
  ],

  use: {
    baseURL: process.env.REDCAP_BASE_URL || "http://localhost:8585",
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure",
    // Extra HTTP headers for fingerprinting
    extraHTTPHeaders: {
      "X-REDACTS-DAST": "1.0.0",
    },
  },

  projects: [
    {
      name: "dast-chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
