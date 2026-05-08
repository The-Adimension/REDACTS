"""
REDACTS DAST - pytest fixtures for Playwright tests.

Provides async browser, context, and page fixtures for all DAST tests.
Replaces playwright.config.ts configuration.
"""

from __future__ import annotations

import os
import shlex

import pytest
import pytest_asyncio
from playwright.async_api import async_playwright, Browser, BrowserContext, Page


REDCAP_BASE_URL = os.environ.get("REDCAP_BASE_URL", "http://localhost:8585")
CHROMIUM_EXECUTABLE = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE", "").strip()
CHROMIUM_ARGS = shlex.split(os.environ.get("PLAYWRIGHT_CHROMIUM_ARGS", ""))


@pytest_asyncio.fixture
async def browser():
    """Launch a Chromium browser for the test."""
    launch_options: dict[str, object] = {"headless": True}
    if CHROMIUM_EXECUTABLE:
        launch_options["executable_path"] = CHROMIUM_EXECUTABLE
    if CHROMIUM_ARGS:
        launch_options["args"] = CHROMIUM_ARGS
    pw = await async_playwright().start()
    b = await pw.chromium.launch(**launch_options)
    yield b
    await b.close()
    await pw.stop()


@pytest_asyncio.fixture
async def context(browser: Browser):
    """Create a fresh browser context per test."""
    ctx = await browser.new_context(
        base_url=REDCAP_BASE_URL,
        extra_http_headers={"X-REDACTS-DAST": "1.0.0"},
        ignore_https_errors=True,
    )
    yield ctx
    await ctx.close()


@pytest_asyncio.fixture
async def page(context: BrowserContext):
    """Create a fresh page per test."""
    pg = await context.new_page()
    yield pg
    await pg.close()
