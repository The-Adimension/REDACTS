"""
REDACTS DAST - Security Assertions
Reusable Playwright assertions that map directly to REDACTS
SEC rules, validating dynamic behaviour matches static findings.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from playwright.async_api import Page, Response

from ._runtime_env import snapshot as _env_snapshot

_ENV = _env_snapshot()


async def assert_no_info_leak_headers(response: Response) -> None:
    """Assert no sensitive data leaks in HTTP response headers.

    Maps to: SEC031 (information disclosure headers)
    """
    headers = await response.all_headers()

    server = headers.get("server", "")
    assert not re.search(
        r"Apache/\d|PHP/\d|nginx/\d", server, re.IGNORECASE
    ), f"Server header leaks version: {server}"

    assert "x-powered-by" not in headers, (
        f"X-Powered-By header present: {headers.get('x-powered-by')}"
    )

    assert headers.get("x-content-type-options") == "nosniff", (
        "Missing X-Content-Type-Options: nosniff"
    )

    xfo = headers.get("x-frame-options", "")
    assert re.search(r"DENY|SAMEORIGIN", xfo, re.IGNORECASE), (
        f"X-Frame-Options missing or invalid: {xfo}"
    )


async def assert_no_reflected_xss(
    page: Page,
    payload: str = '<script>alert("REDACTS")</script>',
) -> None:
    """Assert a page does not reflect user input unsanitized (XSS check).

    Maps to: SEC010, SEC073 (Messenger XSS), SEC074 (Design XSS)
    """
    body_content = await page.content()
    assert payload not in body_content, (
        f"Reflected XSS: payload found unescaped in DOM"
    )


async def assert_no_php_errors(page: Page) -> None:
    """Assert PHP errors are not displayed to the user.

    Maps to: SEC022 (error display in production)
    """
    content = await page.content()
    error_patterns = [
        r"Fatal error:",
        r"Parse error:",
        r"Warning:.*on line \d+",
        r"Notice:.*on line \d+",
        r"Stack trace:",
        r"Uncaught Exception",
        r"<b>Warning</b>:",
        r"Deprecated:.*on line",
    ]
    for pattern in error_patterns:
        assert not re.search(pattern, content, re.IGNORECASE), (
            f"PHP error detected: pattern '{pattern}' found in page content"
        )


async def assert_no_debug_artifacts(page: Page) -> None:
    """Assert no debug/development artifacts visible.

    Maps to: SEC030, SEC063 (debug tool detection)
    """
    content = await page.content()
    debug_patterns = [
        r"phpinfo\(\)",
        r"var_dump\(",
        r"print_r\(",
        r"debug_backtrace",
        r"xdebug",
        r"Adminer",
        r"phpMyAdmin",
    ]
    for pattern in debug_patterns:
        assert not re.search(pattern, content, re.IGNORECASE), (
            f"Debug artifact detected: pattern '{pattern}' found in page content"
        )


async def assert_clean_download(
    response: Response,
    expected_mime: str,
) -> None:
    """Assert that a file download has expected content type and
    does not contain injected code.

    Maps to: SEC076 (file export bypass), SEC074 (PDF injection)
    """
    headers = await response.all_headers()
    ct = headers.get("content-type", "")
    assert expected_mime in ct, (
        f"Expected content-type containing '{expected_mime}', got '{ct}'"
    )

    body = await response.body()
    text = body.decode("utf-8", errors="replace")

    # Check for code injection in non-PHP downloads
    if "php" not in expected_mime:
        assert not re.search(r"eval\s*\(", text), "eval() found in download"
        assert not re.search(r"base64_decode\s*\(", text), "base64_decode() found in download"
        assert not re.search(r"<\?php", text, re.IGNORECASE), "PHP tag found in download"


async def assert_secure_cookies(page: Page) -> None:
    """Assert session cookie security attributes.

    Maps to: SEC021 (session fixation), SEC071 (cookie deserialization)
    """
    cookies = await page.context.cookies()

    for cookie in cookies:
        if "sess" in cookie["name"].lower():
            assert cookie.get("httpOnly") is True, (
                f"Session cookie '{cookie['name']}' missing HttpOnly"
            )
            assert cookie.get("sameSite") in ("Lax", "Strict"), (
                f"Session cookie '{cookie['name']}' SameSite={cookie.get('sameSite')}"
            )


def assert_no_external_requests(
    requests: list[dict[str, str] | object],
    allowed_hosts: list[str] | None = None,
) -> list[str]:
    """Assert that requests did not go to an external/unexpected host.

    Detects C2 callbacks and data exfiltration.
    Maps to: SEC060-062 (INFINITERED IoCs)
    """
    env_hosts = list(_ENV.internal_hosts)
    base_url_host = urlparse(_ENV.base_url).hostname

    if allowed_hosts is None:
        allowed_hosts = ["redcap-dast-app", "localhost", "127.0.0.1", "::1"]

    normalized_hosts = {
        *allowed_hosts,
        *env_hosts,
    }
    if base_url_host:
        normalized_hosts.add(base_url_host)

    violations: list[str] = []

    for req in requests:
        url = req.url if hasattr(req, "url") else req.get("url", "")  # type: ignore[union-attr]
        try:
            hostname = urlparse(url).hostname or ""
            if hostname not in normalized_hosts:
                violations.append(url)
        except Exception:
            # Malformed URL - NOT safe to ignore.
            violations.append(f"MALFORMED_URL: {url}")

    return violations


def collect_console_errors(page: Page) -> list[str]:
    """Monitor console for suspicious JavaScript execution.

    Maps to: SEC040 (nested encoding backdoor)
    """
    errors: list[str] = []

    def _on_console(msg: object) -> None:
        if hasattr(msg, "type") and msg.type == "error":  # type: ignore[union-attr]
            errors.append(msg.text)  # type: ignore[union-attr]

    page.on("console", _on_console)
    return errors
