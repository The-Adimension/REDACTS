"""
Shared network-security primitives — SSRF protection.

Centralises DNS-resolution-based internal-IP rejection so every outbound
HTTP request in REDACTS benefits from the same hardened check.

Used by:
    - loaders.http_loader
    - investigation.yara_adapter
"""

from __future__ import annotations

import ipaddress
import logging
import socket

logger = logging.getLogger(__name__)

# Allowlisted domains for community rule downloads (yara_adapter).
ALLOWED_DOWNLOAD_HOSTS: frozenset[str] = frozenset({
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
})


def reject_ssrf_target(hostname: str) -> None:
    """Block requests whose resolved IP is internal/reserved.

    Raises ``ValueError`` when *hostname*:
    - is empty,
    - resolves to a private, loopback, link-local, reserved, multicast,
      or unspecified IP, or
    - cannot be resolved at all (**fail-closed**).
    """
    if not hostname:
        raise ValueError("Empty hostname in URL")

    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC):
            addr = info[4][0]
            ip = ipaddress.ip_address(addr)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
                # AWS / GCP / Azure metadata endpoint
                or str(ip) == "169.254.169.254"
            ):
                raise ValueError(
                    f"SSRF blocked: {hostname} resolves to internal address {ip}"
                )
    except socket.gaierror as exc:
        # Fail closed — unresolvable hosts must not be trusted
        raise ValueError(
            f"SSRF blocked: cannot resolve hostname {hostname!r} ({exc})"
        ) from exc


def enforce_https(url: str) -> None:
    """Raise ``ValueError`` unless *url* uses the ``https`` scheme."""
    from urllib.parse import urlparse

    if urlparse(url).scheme != "https":
        raise ValueError(f"Only HTTPS URLs are allowed (got {url!r})")


def check_domain_allowlist(
    hostname: str,
    allowed: frozenset[str] = ALLOWED_DOWNLOAD_HOSTS,
) -> None:
    """Raise ``ValueError`` if *hostname* is not in *allowed*."""
    if hostname not in allowed:
        raise ValueError(
            f"Domain {hostname!r} is not in the allow-list: {sorted(allowed)}"
        )
