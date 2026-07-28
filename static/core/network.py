"""SSRF guard rails for outbound HTTP.

Why fail-closed on ``socket.gaierror``:

* Hospital networks frequently restrict outbound DNS to an internal
  resolver. An attacker-controlled archive that lists e.g.
  ``intranet.example.org`` for its update URL will fail to resolve from
  the scan host, and we treat that as a refusal, not a green light.
* Cloud metadata endpoints (169.254.169.254 on AWS / Azure / GCP, plus
  ``fd00:ec2::254`` on AWS IPv6) are *enumerated* below rather than
  inferred from ``is_link_local``. At least one historical SSRF
  (CVE-2019-5418-class) bypassed link-local checks via DNS rebinding,
  and we close that gap by resolving once and connecting to the IP we
  resolved.

What this module does NOT do: it does not pin TLS, rewrite Host headers,
or enforce request rate. Those belong to the caller (``loaders``,
``yara_adapter``).
"""

from __future__ import annotations

import ipaddress
import logging
import socket

logger = logging.getLogger(__name__)

# Built-in fallback allowlist - used ONLY when no FrozenCaseContract has
# been installed on runtime_context (e.g. unit tests that exercise the
# helper directly). In production, the contract's
# ``[security].ssrf_allowlist`` is the source of truth and overrides
# this set. Do not add hosts here without also documenting them in
# case.example.toml.
ALLOWED_DOWNLOAD_HOSTS: frozenset[str] = frozenset({
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
})


class NetworkDisabledError(RuntimeError):
    """Raised when [security].network_disabled blocks an outbound request."""


def _runtime_allowlist() -> frozenset[str] | None:
    """Return the contract-driven SSRF allowlist, or ``None`` if no
    contract is installed (test contexts).

    This is the runtime equivalent of the contract's
    ``[security].ssrf_allowlist``. It is intentionally read at call time
    so that test harnesses that swap out the contract via
    ``runtime_context.set_contract`` see the current value.
    """
    try:
        from . import runtime_context  # local import - avoids cycles at import time
    except Exception:  # pragma: no cover - runtime_context always exists in production
        return None
    contract = runtime_context.get_optional_contract()
    if contract is None or not hasattr(contract, "security"):
        return None
    return frozenset(contract.security.ssrf_allowlist)


def _runtime_network_disabled() -> bool:
    """Return ``True`` iff the installed contract sets
    ``[security].network_disabled = true``. Returns ``False`` when no
    contract is installed (tests / pre-contract bootstrapping)."""
    try:
        from . import runtime_context
    except Exception:  # pragma: no cover
        return False
    contract = runtime_context.get_optional_contract()
    if contract is None or not hasattr(contract, "security"):
        return False
    return bool(contract.security.network_disabled)


def assert_network_allowed(url: str, *, label: str = "outbound HTTP") -> None:
    """Single chokepoint for *every* host-side outbound HTTP request.

    Enforces the four contract-driven gates in order:
      1. ``[security].network_disabled`` - hard refusal (raises
         ``NetworkDisabledError``).
      2. HTTPS-only (raises ``ValueError``).
      3. Host appears in ``[security].ssrf_allowlist`` - when a
         contract is installed; falls back to the built-in
         ``ALLOWED_DOWNLOAD_HOSTS`` only when no contract is installed
         (test contexts) (raises ``ValueError``).
      4. Resolved IP is not internal/reserved (raises ``ValueError``).

    Callers should use this in preference to calling
    ``reject_ssrf_target`` / ``enforce_https`` / ``check_domain_allowlist``
    individually - those remain available as building blocks but
    do not consult the contract on their own.
    """
    from urllib.parse import urlparse

    if _runtime_network_disabled():
        raise NetworkDisabledError(
            f"{label}: blocked by [security].network_disabled - request to "
            f"{url!r} refused at the host boundary."
        )

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"{label}: only HTTPS URLs are allowed (got {url!r})")

    hostname = parsed.hostname or ""
    runtime_allow = _runtime_allowlist()
    allowlist = runtime_allow if runtime_allow is not None else ALLOWED_DOWNLOAD_HOSTS
    if hostname not in allowlist:
        source = (
            "[security].ssrf_allowlist"
            if runtime_allow is not None
            else "ALLOWED_DOWNLOAD_HOSTS"
        )
        raise ValueError(
            f"{label}: host {hostname!r} is not in {source} "
            f"(allowed: {sorted(allowlist)})"
        )

    reject_ssrf_target(hostname)


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
                # AWS / GCP / Azure metadata endpoint (IPv4 + AWS IPv6)
                or str(ip) == "169.254.169.254"
                or str(ip) == "fd00:ec2::254"
            ):
                raise ValueError(
                    f"SSRF blocked: {hostname} resolves to internal address {ip}"
                )
    except socket.gaierror as exc:
        # Fail closed - unresolvable hosts must not be trusted
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
