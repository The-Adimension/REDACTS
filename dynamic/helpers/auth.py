"""
REDACTS DAST - Authentication Helper
Handles REDCap login, session management, and admin escalation.
Designed for REDCap 15.x-16.x login flow.
"""

from __future__ import annotations

from playwright.async_api import BrowserContext, Page, expect

from ._runtime_env import snapshot as _env_snapshot

_ENV = _env_snapshot()

# Import compatibility for callers that use the module-level constant.
REDCAP_VERSION = _ENV.redcap_version


async def login(
    page: Page,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """Log in to REDCap via the standard login form.

    Handles the initial login page, password change prompts,
    and the 'My Projects' landing page verification.
    """
    username = username or _ENV.admin_user
    password = password or _ENV.admin_password
    if not password:
        raise RuntimeError(
            "REDCap admin password unavailable: pass `password=` or ensure "
            "the orchestrator injects REDCAP_ADMIN_PASS into the Playwright "
            "runtime (sourced from the contract via dynamic.credentials)."
        )

    await page.goto("/redcap/")

    # REDCap login form - field names vary by version
    username_field = page.locator(
        'input[name="username"], input[name="app_username"], input#username'
    ).first
    password_field = page.locator(
        'input[name="password"], input[name="app_password"], input#password'
    ).first

    await username_field.fill(username)
    await password_field.fill(password)

    # Submit - could be button or input[type=submit]
    submit_btn = page.locator(
        'button[type="submit"], input[type="submit"], button#login_btn, #login-btn'
    ).first

    await submit_btn.click()

    # Wait for post-login state - look for logout link or My Projects page
    await page.wait_for_load_state("networkidle")
    post_login = page.locator(
        'a[href*="logout"], a:has-text("Log out"), a:has-text("My Projects")'
    ).first
    await post_login.wait_for(state="visible", timeout=30_000)


async def go_to_control_center(page: Page) -> None:
    """Navigate to the Control Center (admin area)."""
    await page.goto(f"/redcap/redcap_v{REDCAP_VERSION}/ControlCenter/index.php")
    await page.wait_for_load_state("networkidle")


async def go_to_project(page: Page, pid: int) -> None:
    """Navigate to a specific project by PID."""
    await page.goto(f"/redcap/redcap_v{REDCAP_VERSION}/index.php?pid={pid}")
    await page.wait_for_load_state("networkidle")


async def go_to_project_page(page: Page, pid: int, page_path: str) -> None:
    """Navigate to a specific REDCap module page within a project."""
    sep = "&" if "?" in page_path else "?"
    url = f"/redcap/redcap_v{REDCAP_VERSION}/{page_path}{sep}pid={pid}"
    await page.goto(url)
    await page.wait_for_load_state("networkidle")


async def is_logged_in(page: Page) -> bool:
    """Check if we're currently logged in."""
    logout_link = page.locator('a[href*="logout"], a:has-text("Log out")')
    return await logout_link.count() > 0


async def logout(page: Page) -> None:
    """Log out from REDCap.

    Raises if the logout link exists but clicking it fails.
    """
    logout_link = page.locator(
        'a[href*="logout"], a:has-text("Log out")'
    ).first
    link_count = await page.locator(
        'a[href*="logout"], a:has-text("Log out")'
    ).count()
    if link_count == 0:
        raise RuntimeError(
            "logout() called but no logout link found on page - "
            "the session may already be expired or the page did not load correctly. "
            f"Current URL: {page.url}"
        )
    await logout_link.click()
    await page.wait_for_load_state("networkidle")


async def save_auth_state(
    context: BrowserContext,
    path: str = "/tmp/redcap-auth.json",
) -> None:
    """Store and reuse auth state to avoid re-login per test."""
    await context.storage_state(path=path)
