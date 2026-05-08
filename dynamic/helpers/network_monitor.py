"""
REDACTS DAST - Network Monitor
Intercepts and logs all HTTP requests during tests.
Captures request/response pairs for post-test analysis.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

from playwright.async_api import Page, Request


@dataclass
class CapturedRequest:
    url: str
    method: str
    resource_type: str
    post_data: str | None = None
    timestamp: float = 0.0
    status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_size: int | None = None


class NetworkMonitor:
    """Captures all HTTP requests during Playwright tests."""

    def __init__(self, page: Page) -> None:
        self._page = page
        self._requests: list[CapturedRequest] = []

    def start(self) -> None:
        """Start capturing all network traffic."""
        self._requests = []

        async def _on_request_finished(request: Request) -> None:
            try:
                response = await request.response()
                body_bytes = await response.body() if response else None
                self._requests.append(CapturedRequest(
                    url=request.url,
                    method=request.method,
                    resource_type=request.resource_type,
                    post_data=request.post_data,
                    timestamp=time.time(),
                    status=response.status if response else None,
                    response_headers=await response.all_headers() if response else {},
                    response_size=len(body_bytes) if body_bytes else None,
                ))
            except Exception as exc:
                # Response disposed - record with explicit marker so
                # downstream analysis knows the capture is incomplete.
                self._requests.append(CapturedRequest(
                    url=request.url,
                    method=request.method,
                    resource_type=request.resource_type,
                    post_data=request.post_data,
                    timestamp=time.time(),
                    status=-1,  # sentinel: response was not available
                    response_headers={
                        "x-redacts-capture-error": str(exc),
                    },
                ))

        self._page.on("requestfinished", _on_request_finished)

    def get_all(self) -> list[CapturedRequest]:
        """Get all captured requests."""
        return list(self._requests)

    def filter(self, pattern: re.Pattern[str]) -> list[CapturedRequest]:
        """Get requests matching a URL pattern."""
        return [r for r in self._requests if pattern.search(r.url)]

    def get_posts(self) -> list[CapturedRequest]:
        """Get all POST requests (mutation operations)."""
        return [r for r in self._requests if r.method == "POST"]

    def get_external(self, internal_host: str = "redcap-dast-app") -> list[CapturedRequest]:
        """Get requests to external hosts."""
        results: list[CapturedRequest] = []
        for r in self._requests:
            try:
                hostname = urlparse(r.url).hostname or ""
                if internal_host not in hostname:
                    results.append(r)
            except Exception:
                # Malformed URL - treat as external (suspicious)
                results.append(r)
        return results

    def get_errors(self) -> list[CapturedRequest]:
        """Get requests that returned server errors."""
        return [r for r in self._requests if r.status and r.status >= 500]

    def summary(self) -> dict[str, int]:
        """Summary for reporting."""
        return {
            "total": len(self._requests),
            "posts": len(self.get_posts()),
            "external": len(self.get_external()),
            "errors": len(self.get_errors()),
        }

    def clear(self) -> None:
        """Clear captured data."""
        self._requests = []
