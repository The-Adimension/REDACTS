"""
REDACTS Dependency Auto-Installer
Auto-installs missing Python packages and system tool binaries.

Python packages are installed via pip.  System tools (Trivy, YARA)
are downloaded as platform-specific binaries into ``~/.redacts/tools/``.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import urljoin

from .dependencies import DependencyReport
from ..core.paths import tools_dir as _resolve_tools_dir, inject_tools_on_path

logger = logging.getLogger(__name__)


def network_disabled() -> bool:
    """Return True when the active case contract forbids host networking.

    Public alias of :func:`_network_disabled` so external callers (and
    tests) do not depend on a private name.  Both names point at the
    same single contract read; there is no second policy source.
    """
    return _network_disabled()


def _network_disabled() -> bool:
    """Return True when the active case contract forbids host networking."""
    try:
        from ..core import runtime_context
    except Exception:  # pragma: no cover
        return False
    contract = runtime_context.get_optional_contract()
    return bool(contract is not None and contract.security.network_disabled)


def auto_install_python(report: DependencyReport) -> list[str]:
    """Auto-install missing Python packages via pip.

    Returns list of successfully installed package names.
    """
    missing = report.missing_python
    if not missing:
        return []

    if _network_disabled():
        for dep in missing:
            dep.error = "Auto-install skipped: [security].network_disabled = true"
        print("  Skipping Python auto-install: [security].network_disabled = true")
        return []

    installed: list[str] = []
    for dep in missing:
        pip_spec = dep.install_cmd.replace("pip install ", "") if dep.install_cmd else dep.name
        print(f"  Installing {pip_spec}...")

        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_spec, "--quiet"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                installed.append(dep.name)
                dep.available = True
                dep.error = ""
                print(f"    OK {dep.name}")
            else:
                dep.error = proc.stderr.strip()[:200]
                print(f"    FAILED: {dep.error}")
        except subprocess.TimeoutExpired:
            dep.error = "Timed out after 120s"
            print(f"    TIMEOUT: {dep.name}")
        except Exception as exc:
            dep.error = str(exc)
            print(f"    ERROR: {dep.name} - {exc}")

    return installed


def _post_install_hooks(installed: list[str]) -> None:
    """Run post-install hooks for packages that need extra setup."""
    if "playwright" in installed:
        if _network_disabled():
            print(
                "  Skipping Playwright Chromium install: "
                "[security].network_disabled = true"
            )
            return
        print("  Installing Playwright Chromium browser...")
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if proc.returncode == 0:
                print("    OK playwright chromium")
            else:
                msg = proc.stderr.strip()[:200]
                print(f"    WARNING: playwright install chromium failed: {msg}")
        except subprocess.TimeoutExpired:
            print("    WARNING: playwright install chromium timed out")
        except Exception as exc:
            print(f"    WARNING: playwright install chromium error: {exc}")


# Bootstrap fallback versions used only when no FrozenCaseContract is
# available (e.g. unit tests or early CLI startup). When the contract is
# loaded, ``[tools.trivy].version`` / ``[tools.yara].version`` from
# case.toml override these via ``_resolve_tool_spec``.
_TRIVY_VERSION = "0.58.2"
_YARA_VERSION = "4.5.2"


def _normalize_expected_sha256(value: str) -> str | None:
    """Return a usable SHA-256 digest, or None for missing/placeholders."""
    expected = (value or "").strip().lower()
    if len(expected) != 64 or not all(c in "0123456789abcdef" for c in expected):
        return None
    if expected == "0" * 64 or expected == "deadbeef" * 8:
        return None
    return expected


def _download_and_extract_zip(
    url: str,
    dest_dir: Path,
    label: str,
    *,
    expected_sha256: str = "",
) -> bool:
    """Download a ZIP from *url*, verify paths, and extract into *dest_dir*.

    Args:
        url: HTTPS URL to download (validated through ``assert_network_allowed``).
        dest_dir: Directory to extract into (created if missing).
        label: Human-readable label for logs / progress messages.
        expected_sha256: required 64-character hex digest from
            ``[tools.<name>].sha256_table``. Placeholders and missing
            values are rejected before any network request is made.
    """
    import hashlib
    import tempfile

    import requests

    # Normalize the expected digest - sha256_table values arrive as
    # contract strings, so be tolerant of whitespace and case. Refuse to
    # download when the operator has not pinned a real digest; an
    # unverified scanner binary is worse than a loud BLOCK.
    expected = _normalize_expected_sha256(expected_sha256)
    if expected is None:
        logger.error(
            "Refusing to download %s: sha256_table value is missing or a "
            "placeholder (%r)",
            label, expected_sha256,
        )
        print(
            f"    REJECTED ({label}): pin a real 64-hex SHA-256 in "
            "case.toml [tools.*].sha256_table before auto-install"
        )
        return False

    dest_dir.mkdir(parents=True, exist_ok=True)
    print(f"    Downloading {label}...")
    logger.info("Downloading %s from %s", label, url)

    # Single chokepoint: enforces [security].network_disabled, HTTPS-only,
    # contract ssrf_allowlist, and SSRF (internal-IP) rejection in one call.
    from ..core.network import (
        assert_network_allowed as _assert_net,
        NetworkDisabledError as _NetDisabled,
    )

    def _get_with_verified_redirects(start_url: str):
        current_url = start_url
        for _redirect_count in range(6):
            try:
                _assert_net(current_url, label=f"auto_install:{label}")
            except _NetDisabled as exc:
                logger.error(
                    "Network disabled - refusing to download %s: %s", label, exc
                )
                print(f"    BLOCKED ({label}): {exc}")
                raise
            except ValueError as exc:
                logger.error("Outbound check failed for %s: %s", label, exc)
                print(f"    BLOCKED: {label} - {exc}")
                raise

            response = requests.get(
                current_url,
                stream=True,
                timeout=120,
                allow_redirects=False,
            )
            if 300 <= response.status_code < 400:
                location = response.headers.get("Location", "")
                response.close()
                if not location:
                    raise ValueError(
                        f"{label}: redirect from {current_url!r} had no Location"
                    )
                next_url = urljoin(current_url, location)
                logger.info("Redirect for %s: %s -> %s", label, current_url, next_url)
                current_url = next_url
                continue
            return response
        raise requests.exceptions.TooManyRedirects(
            f"{label}: too many redirects while downloading {start_url!r}"
        )

    tmp_path: Path | None = None
    try:
        # Stream to a temp file instead of loading entire ZIP into memory.
        # NamedTemporaryFile owns the file handle and we close() it BEFORE
        # any other I/O. Using mkstemp + os.fdopen here leaks the raw fd
        # whenever requests.get() raises before the body-write block is
        # entered (e.g. on HTTP 4xx); the subsequent unlink() then
        # crashes on Windows with `WinError 32 (file in use)`, masking
        # the original error with an unhandled traceback.
        tmp_file = tempfile.NamedTemporaryFile(
            suffix=".zip", prefix="redacts_dep_", delete=False
        )
        tmp_path = Path(tmp_file.name)
        try:
            sha256 = hashlib.sha256()
            with _get_with_verified_redirects(url) as resp:
                resp.raise_for_status()
                for chunk in resp.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                    sha256.update(chunk)
        finally:
            # Always release the OS handle before any unlink/extract step.
            tmp_file.close()

        logger.info(
            "Downloaded %s - SHA-256: %s", label, sha256.hexdigest()
        )

        # Verify the downloaded archive against the
        # contract-pinned digest BEFORE extraction. Refuse to extract
        # - and refuse to leave the temp file around - when the digest
        # disagrees. ``constant-time`` comparison is unnecessary here
        # (no secret material), but matching against a single known
        # value is the cheapest defence against a tampered mirror.
        actual = sha256.hexdigest().lower()
        if actual != expected:
            logger.error(
                "SHA-256 mismatch for %s - expected %s, got %s",
                label, expected, actual,
            )
            print(
                f"    REJECTED ({label}): SHA-256 mismatch - "
                f"expected {expected[:12]}..., got {actual[:12]}..."
            )
            return False
        logger.info("SHA-256 verified for %s (%s)", label, actual[:16] + "...")

        resolved_dest = dest_dir.resolve()
        with zipfile.ZipFile(tmp_path) as zf:
            # Zip Slip protection: reject entries that escape dest_dir
            for member in zf.namelist():
                member_path = (dest_dir / member).resolve()
                if not str(member_path).startswith(str(resolved_dest)):
                    raise zipfile.BadZipFile(
                        f"Zip Slip detected: {member!r} escapes {dest_dir}"
                    )
            zf.extractall(dest_dir)
        return True
    except requests.exceptions.HTTPError as exc:
        logger.error("HTTP error downloading %s: %s", label, exc)
        print(f"    FAILED to download {label} (HTTP error): {exc}")
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("Network error downloading %s: %s", label, exc)
        print(f"    FAILED to download {label} (network error): {exc}")
        return False
    except (_NetDisabled, ValueError):
        return False
    except zipfile.BadZipFile as exc:
        logger.error("Invalid ZIP file downloaded for %s: %s", label, exc)
        print(f"    FAILED to extract {label} (invalid ZIP): {exc}")
        return False
    except Exception as exc:
        logger.error("Failed to download %s: %s", label, exc)
        print(f"    FAILED to download {label}: {exc}")
        return False
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError as exc:
                # Best-effort cleanup - never let temp-file removal mask the
                # real download outcome (this used to crash the whole CLI).
                logger.warning(
                    "Could not delete temp file %s: %s", tmp_path, exc
                )


def _platform_tokens() -> tuple[str, str, str]:
    """Return ``(os_token, arch_token, platform_key)`` for URL template
    substitution and sha256_table lookup.

    `os_token`/`arch_token` are the values substituted into
    ``[tools.<name>].url_template``; `platform_key` (e.g. ``windows-64bit``,
    ``linux-64bit``, ``darwin-arm64``, ``win64``) is the key used to look
    up an expected SHA-256 in ``[tools.<name>].sha256_table``.

    The Trivy and YARA release archives use different OS/arch slugs, so
    we return *generic* tokens here and let each installer adapt them.
    Returning more than is needed is the lesser evil compared to two
    near-identical helpers.
    """
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch_map = {
        "x86_64": "64bit",
        "amd64": "64bit",
        "arm64": "ARM64",
        "aarch64": "ARM64",
    }
    arch = arch_map.get(machine, "64bit")
    if system == "windows":
        return "windows", arch, f"windows-{arch}"
    if system == "darwin":
        return "macOS", arch, f"darwin-{arch}"
    return "Linux", arch, f"linux-{arch}"


def _resolve_tool_spec(name: str):
    """Return ``contract.tools.<name>`` (a ``ToolSpec``) if a contract is
    installed, else ``None``. Callers fall back to module constants when
    no contract is available (e.g. during ``main.py --case``-less
    invocations)."""
    try:
        from ..core import runtime_context
    except Exception:  # pragma: no cover
        return None
    contract = runtime_context.get_optional_contract()
    if contract is None:
        return None
    return getattr(contract.tools, name, None)


def _install_trivy(dest_dir: Path) -> bool:
    """Download the Trivy binary for the current platform.

    Reads ``[tools.trivy]`` from the active FrozenCaseContract when one is
    installed; falls back to the module-level ``_TRIVY_VERSION`` and the
    upstream URL template only when no contract is loaded (early
    bootstrap, unit tests).
    """
    spec = _resolve_tool_spec("trivy")
    os_token, arch_token, platform_key = _platform_tokens()

    if spec is not None:
        version = spec.version
        url = spec.url_template.format(
            version=version, os=os_token, arch=arch_token
        )
        expected_sha = spec.sha256_table.get(platform_key, "")
    else:
        version = _TRIVY_VERSION
        if os_token == "windows":
            slug = f"trivy_{version}_windows-{arch_token}.zip"
        elif os_token == "macOS":
            slug = f"trivy_{version}_macOS-{arch_token}.zip"
        else:
            slug = f"trivy_{version}_Linux-{arch_token}.zip"
        url = (
            f"https://github.com/aquasecurity/trivy/releases/download/"
            f"v{version}/{slug}"
        )
        expected_sha = ""

    ok = _download_and_extract_zip(
        url, dest_dir, f"Trivy v{version}", expected_sha256=expected_sha,
    )
    if ok and expected_sha:
        # Verification happens inside
        # ``_download_and_extract_zip`` before extraction. This
        # informational log is retained so operators can correlate
        # the version they ran against the digest they pinned.
        logger.info(
            "Trivy v%s installed (sha256_table[%s]=%s)",
            version, platform_key, expected_sha,
        )
    return ok


def _install_yara(dest_dir: Path) -> bool:
    """Download the YARA binary for the current platform.

    Reads ``[tools.yara]`` from the active FrozenCaseContract when one is
    installed; falls back to the module-level ``_YARA_VERSION`` only when
    no contract is loaded.
    """
    system = platform.system().lower()
    spec = _resolve_tool_spec("yara")
    version = spec.version if spec is not None else _YARA_VERSION

    if system == "windows":
        if spec is not None:
            # Windows release uses os=win64 in the canonical URL template.
            url = spec.url_template.format(
                version=version, os="win64", arch="win64"
            )
            # B.1: pull the platform-keyed digest off the contract.
            expected_sha = spec.sha256_table.get("win64", "") or \
                spec.sha256_table.get("windows-64bit", "")
        else:
            url = (
                f"https://github.com/VirusTotal/yara/releases/download/"
                f"v{version}/yara-v{version}-2326-win64.zip"
            )
            expected_sha = ""
        ok = _download_and_extract_zip(
            url, dest_dir, f"YARA v{version}",
            expected_sha256=expected_sha,
        )
        if ok:
            # Release ships yara64.exe - create yara.exe alias so PATH lookup works
            src = dest_dir / "yara64.exe"
            dst = dest_dir / "yara.exe"
            if src.is_file() and not dst.is_file():
                shutil.copy2(src, dst)
                logger.info("Created %s -> %s", src.name, dst.name)
        return ok
    elif system == "darwin":
        # macOS - try Homebrew first, then binary download
        try:
            proc = subprocess.run(
                ["brew", "install", "yara"],
                capture_output=True, text=True, timeout=180,
            )
            if proc.returncode == 0:
                print("    Installed YARA via Homebrew")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        print("    YARA auto-install not available for macOS without Homebrew")
        print("    Install manually: brew install yara")
        return False
    else:
        # Linux - try apt/yum, fall back to guidance
        for pkg_mgr, args in [
            ("apt-get", ["sudo", "apt-get", "install", "-y", "yara"]),
            ("yum", ["sudo", "yum", "install", "-y", "yara"]),
        ]:
            if shutil.which(pkg_mgr):
                try:
                    proc = subprocess.run(
                        args, capture_output=True, text=True, timeout=180,
                    )
                    if proc.returncode == 0:
                        print(f"    Installed YARA via {pkg_mgr}")
                        return True
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue
        print("    YARA auto-install not available - install manually")
        return False


def auto_install_system_tools(report: DependencyReport) -> list[str]:
    """Auto-download missing system tool binaries.

    Downloads into ``~/.redacts/tools/`` and adds to PATH.
    Returns list of successfully installed tool names.
    """
    missing = [
        c for c in report.checks
        if not c.available and c.category == "system"
    ]
    if not missing:
        return []

    tools_dir = _resolve_tools_dir()
    tools_dir.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []

    # Make tools_dir discoverable to shutil.which / subprocess via the
    # single permitted PATH chokepoint.
    inject_tools_on_path()

    installers = {
        "trivy": _install_trivy,
        "yara": _install_yara,
    }

    for dep in missing:
        installer = installers.get(dep.name)
        if not installer:
            continue

        print(f"  Auto-installing {dep.name}...")
        if installer(tools_dir):
            # Verify it actually works now
            binary = dep.name + (".exe" if sys.platform == "win32" else "")
            if (tools_dir / binary).is_file() or shutil.which(dep.name):
                dep.available = True
                dep.error = ""
                installed.append(dep.name)
                print(f"    OK - {dep.name} installed to {tools_dir}")
            else:
                dep.error = f"Downloaded but binary not found in {tools_dir}"
                print(f"    WARNING: {dep.error}")
        else:
            dep.error = f"Auto-install failed - install manually: {dep.install_url}"
            print(f"    FAILED: {dep.error}")

    return installed
