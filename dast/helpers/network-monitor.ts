/**
 * REDACTS DAST — Network Monitor
 * ================================
 * Intercepts and logs all HTTP requests during tests.
 * Captures request/response pairs for post-test analysis.
 */

import { Page, Request, Response } from "@playwright/test";

export interface CapturedRequest {
  url: string;
  method: string;
  resourceType: string;
  postData?: string | null;
  timestamp: number;
  status?: number;
  responseHeaders?: Record<string, string>;
  responseSize?: number;
}

export class NetworkMonitor {
  private requests: CapturedRequest[] = [];
  private page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  /** Start capturing all network traffic. */
  start(): void {
    this.requests = [];

    this.page.on("requestfinished", async (request: Request) => {
      try {
        const response = await request.response();
        this.requests.push({
          url: request.url(),
          method: request.method(),
          resourceType: request.resourceType(),
          postData: request.postData(),
          timestamp: Date.now(),
          status: response?.status(),
          responseHeaders: response?.headers(),
          responseSize: (await response?.body())?.length,
        });
      } catch (err) {
        // Response disposed — record with explicit marker so
        // downstream analysis knows the capture is incomplete.
        this.requests.push({
          url: request.url(),
          method: request.method(),
          resourceType: request.resourceType(),
          postData: request.postData(),
          timestamp: Date.now(),
          status: -1,  // sentinel: response was not available
          responseHeaders: {
            "x-redacts-capture-error": String(err),
          },
        });
      }
    });
  }

  /** Get all captured requests. */
  getAll(): CapturedRequest[] {
    return [...this.requests];
  }

  /** Get requests matching a URL pattern. */
  filter(pattern: RegExp): CapturedRequest[] {
    return this.requests.filter((r) => pattern.test(r.url));
  }

  /** Get all POST requests (mutation operations). */
  getPosts(): CapturedRequest[] {
    return this.requests.filter((r) => r.method === "POST");
  }

  /** Get requests to external hosts. */
  getExternal(internalHost: string = "redcap-dast-app"): CapturedRequest[] {
    return this.requests.filter((r) => {
      try {
        return !new URL(r.url).hostname.includes(internalHost);
      } catch {
        // Malformed URL — treat as external (suspicious)
        return true;
      }
    });
  }

  /** Get requests that returned server errors. */
  getErrors(): CapturedRequest[] {
    return this.requests.filter(
      (r) => r.status && r.status >= 500
    );
  }

  /** Summary for reporting. */
  summary(): Record<string, number> {
    return {
      total: this.requests.length,
      posts: this.getPosts().length,
      external: this.getExternal().length,
      errors: this.getErrors().length,
    };
  }

  /** Clear captured data. */
  clear(): void {
    this.requests = [];
  }
}
