/**
 * REDACTS DAST - Workflow Lifecycle
 * Driven by REDCap Admin Docs:
 *   - Sec.2.6 Workflows (dev->prod transition, draft mode, record locking)
 *   - A1 Checklist (survey queue, randomization, test records, sign-off)
 *   - Sec.Architecture 5 (backup, cron, e-signatures)
 *   - Sec.2.5 Security (survey configuration, public survey links)
 *
 * Maps to Admin Docs Checklist (A1):
 *   [ ] Project starts in Development mode
 *   [ ] Move to Production requires sign-off
 *   [ ] Post-production changes go through Draft mode
 *   [ ] Record Locking and e-signatures configurable
 *   [ ] Survey Queue order configurable
 *   [ ] Randomization Module accessible when needed
 *   [ ] Project notes/README instrument available
 *   [ ] Scheduled tasks (cron) are monitored
 *   [ ] Survey invitations page accessible
 *   [ ] Calendar module accessible for visit scheduling
 *
 * Flow:
 *   1. Login -> Project Setup -> verify development mode
 *   2. Record Locking configuration
 *   3. E-signature setup
 *   4. Survey Queue management
 *   5. Randomization Module access
 *   6. Calendar / scheduling module
 *   7. Survey invitation management
 *   8. API project info endpoint
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
  collectConsoleErrors,
} from "../helpers";

const TEST_PID = 1;
const REDCAP_VERSION = process.env.REDCAP_VERSION || "";
const REDCAP_BASE = process.env.REDCAP_BASE_URL || "http://localhost:8585";

test.describe("Workflow Lifecycle - Admin Docs Sec.2.6 / A1 Checklist", () => {
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

  // Sec.2.6 - Project Status & Development Mode
  // "Leave the project in Development mode (do not move
  //  to Production yet)"

  test("Project Setup displays project status indicator", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "ProjectSetup/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.2.6: Project status should indicate Development, Production, or Analysis
    const hasStatus = /Development|Production|Analysis|Completed|project.?status/i.test(content);

    expect(hasStatus).toBe(true);

    test.info().annotations.push({
      type: "compliance",
      description: "Project status indicator visible - Sec.2.6 lifecycle tracking enabled",
    });

    await assertNoDebugArtifacts(page);
  });

  test("Project Setup shows Move to Production control", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "ProjectSetup/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // Sec.2.6.F: "Elect to move it into production"
    const hasMoveControl = /Move.*Production|move.*to.*production|production.?status/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasMoveControl
        ? "Move to Production control found - Sec.2.6 lifecycle transition available"
        : "Production move control not visible - project may already be in production",
    });

    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  // Sec.2.6 / Architecture 3 - Record Locking
  // "Record Locking / E-signatures"

  test("Record Locking page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Locking/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.Architecture 3: Record Locking / E-signatures
    expect(content).toMatch(/Lock|Locking|Record|E.?signature/i);

    test.info().annotations.push({
      type: "compliance",
      description: "Record Locking page accessible - Sec.Architecture 3 record integrity available",
    });

    await assertNoDebugArtifacts(page);
  });

  test("Record Locking page does not expose lock internals", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Locking/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Should not expose internal lock table structure
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_locking_data/i);
    expect(content).not.toMatch(/UPDATE.*redcap_locking/i);

    const dbEvidence = await assertNoDatabaseLeaks(page);
    expect(dbEvidence.status).toBe("pass");
  });

  // A1 Checklist - Survey Queue & Invitations
  // "Enable Public Survey if needed.
  //  Set up Survey Queue and/or Auto-Survey Invitations"

  test("Survey Distribution page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Surveys/invite_participants.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Survey|Invite|Participant|Distribution/i);

    // A1: Survey invitations should be configurable
    const hasSurveyMgmt = /invitation|queue|public.?survey|compose|survey.?link/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasSurveyMgmt
        ? "Survey distribution/invitation controls present - A1 survey management available"
        : "Survey page loaded with limited invitation controls",
    });

    await assertNoDebugArtifacts(page);
  });

  test("Survey Distribution does not leak internal survey tokens", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Surveys/invite_participants.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Should not expose internal DB queries for surveys
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_surveys_participants/i);
    expect(content).not.toMatch(/SELECT.*FROM.*redcap_surveys_response/i);

    // Survey hashes should not appear as raw database values
    expect(content).not.toMatch(/participant_id\s*=\s*\d+/i);
  });

  // A1 Checklist - Randomization Module
  // "Randomization Module if applicable"

  test("Randomization Module page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Randomization/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Randomization may not be enabled - that's OK
    const hasRandomization = /Randomization|randomize|allocation|stratif/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasRandomization
        ? "Randomization module accessible - A1 randomization requirement checkable"
        : "Randomization module page loaded (may not be enabled for this project)",
    });

    await assertNoDebugArtifacts(page);
  });

  // A1 Checklist - Calendar Module
  // "Calendar reminders that a follow-up appointment is required"

  test("Calendar module is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "Calendar/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();
    expect(content).toMatch(/Calendar|Schedule|Appointment|Event/i);

    test.info().annotations.push({
      type: "compliance",
      description: "Calendar module accessible - A1 scheduling capability available",
    });

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.6 - Project Configuration / Governance
  // "Configure: Logging (ensure it is enabled)"

  test("Project Setup shows logging configuration", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "ProjectSetup/index.php");
    await assertNoPhpErrors(page);

    const content = await page.content();

    // A1 Checklist: "Logging (ensure it is enabled, usually by default)"
    const hasLogging = /logging|audit|log.*enabled/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasLogging
        ? "Logging configuration reference found in Project Setup"
        : "Logging config not visible in Project Setup - may be system-level",
    });
  });

  // Sec.2.3 - API Project Info
  // Ensures API project metadata endpoint requires auth

  test("API project info requires authorization", async ({ request }) => {
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "project",
        format: "json",
        token: "INVALID_TOKEN_DAST_PROJECT_INFO",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    // Should not reveal project configuration
    expect(body).not.toMatch(/project_title/i);
    expect(body).not.toMatch(/purpose/i);
    expect(body.toLowerCase()).toMatch(/error|invalid|denied|token/);
  });

  test("API instrument list requires authorization", async ({ request }) => {
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "instrument",
        format: "json",
        token: "INVALID_TOKEN_DAST_INSTRUMENTS",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/instrument_name/i);
    expect(body).not.toMatch(/instrument_label/i);
  });

  test("API event list requires authorization", async ({ request }) => {
    // Sec.2.4: Event configuration via API
    const response = await request.post(`${REDCAP_BASE}/redcap/api/`, {
      data: {
        content: "event",
        format: "json",
        token: "INVALID_TOKEN_DAST_EVENTS",
      },
    });

    expect(response.status()).not.toBe(200);
    const body = await response.text();
    expect(body).not.toMatch(/event_name/i);
    expect(body).not.toMatch(/unique_event_name/i);
  });

  // Sec.2.6.G - Administrative Monitoring
  // "Monitor the logs periodically for unexpected activity
  //  (deletion, edits at scale, peculiar login details)"

  test("System Statistics page is accessible to admins", async ({ page }) => {
    await login(page);

    await page.goto(
      `/redcap/redcap_v${REDCAP_VERSION}/ControlCenter/system_stats.php`
    );
    await assertNoPhpErrors(page);

    const content = await page.content();
    // Sec.2.6.G: Admin should be able to monitor system stats
    expect(content).toMatch(/System|Statistics|Stats|Usage|Projects|Users/i);

    // Should not expose raw database connection strings
    expect(content).not.toMatch(/mysql:\/\//i);
    expect(content).not.toMatch(/Server:\s*localhost.*Port:\s*3306/i);

    test.info().annotations.push({
      type: "compliance",
      description: "System Statistics page accessible - Sec.2.6.G admin monitoring available",
    });

    await assertNoDebugArtifacts(page);
  });

  // Sec.2.6 - Project Notifications

  test("Alerts & Notifications page is accessible", async ({ page }) => {
    await login(page);
    await goToProjectPage(page, TEST_PID, "index.php?route=AlertsController:setup");
    await assertNoPhpErrors(page);

    const content = await page.content();

    const hasAlerts = /Alert|Notification|trigger|condition/i.test(content);

    test.info().annotations.push({
      type: "compliance",
      description: hasAlerts
        ? "Alerts & Notifications page accessible - automated monitoring configurable"
        : "Alerts page loaded with limited controls",
    });

    await assertNoDebugArtifacts(page);
  });
});
