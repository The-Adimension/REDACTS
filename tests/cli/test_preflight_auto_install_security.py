"""Regression tests for preflight and auto-install security gates."""

from __future__ import annotations

import hashlib
import io
import socket
import subprocess
import zipfile
from pathlib import Path

import pytest

from static.cli import auto_install, preflight
from static.cli.dependencies import DependencyReport, DependencyStatus
from static.core import runtime_context
from static.core.contract import load_and_freeze


@pytest.fixture(autouse=True)
def _reset_contract():
    runtime_context.reset_contract()
    yield
    runtime_context.reset_contract()


def _install_disabled_contract(valid_case_factory) -> None:
    contract = load_and_freeze(valid_case_factory())
    assert contract.security.network_disabled is True
    runtime_context.set_contract(contract)


def _zip_bytes(filename: str = "tool.exe", content: bytes = b"binary") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(filename, content)
    return buffer.getvalue()


class _FakeResponse:
    def __init__(
        self,
        body: bytes = b"",
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self.closed = True

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int):
        for index in range(0, len(self.body), chunk_size):
            yield self.body[index:index + chunk_size]


def test_auto_install_python_skips_pip_when_network_disabled(
    valid_case_factory,
    monkeypatch,
) -> None:
    _install_disabled_contract(valid_case_factory)
    report = DependencyReport(checks=[
        DependencyStatus(
            name="missing-package",
            available=False,
            required=True,
            install_cmd="pip install missing-package>=1.0",
            category="python",
        ),
    ])

    def _forbidden_run(*args, **kwargs):
        raise AssertionError("pip must not run while network_disabled=true")

    monkeypatch.setattr(subprocess, "run", _forbidden_run)

    assert auto_install.auto_install_python(report) == []
    assert "network_disabled" in report.checks[0].error


def test_post_install_hooks_skip_playwright_when_network_disabled(
    valid_case_factory,
    monkeypatch,
) -> None:
    _install_disabled_contract(valid_case_factory)

    def _forbidden_run(*args, **kwargs):
        raise AssertionError("playwright browser install must not run")

    monkeypatch.setattr(subprocess, "run", _forbidden_run)
    auto_install._post_install_hooks(["playwright"])


def test_network_status_does_not_open_socket_when_network_disabled(
    valid_case_factory,
    monkeypatch,
) -> None:
    _install_disabled_contract(valid_case_factory)

    def _forbidden_connect(*args, **kwargs):
        raise AssertionError("preflight network probe must not open a socket")

    monkeypatch.setattr(socket, "create_connection", _forbidden_connect)

    check = preflight._check_network_status()
    assert check.passed is False
    assert check.tier == "WARN"
    assert "network_disabled" in check.message


def test_step_preflight_skips_all_auto_install_when_network_disabled(
    valid_case_factory,
    monkeypatch,
) -> None:
    _install_disabled_contract(valid_case_factory)
    blocked = preflight.PreflightResult(checks=[
        preflight.PreflightCheck(
            layer=2,
            name="missing-package",
            passed=False,
            tier="BLOCK",
            message="missing",
        ),
    ])

    monkeypatch.setattr(preflight, "run_preflight", lambda **kwargs: blocked)
    monkeypatch.setattr(
        preflight,
        "_display_preflight_table",
        lambda console, result: None,
    )
    monkeypatch.setattr(
        "static.cli.dependencies.check_dependencies",
        lambda **kwargs: DependencyReport(),
    )

    def _forbidden(*args, **kwargs):
        raise AssertionError("auto-install must be skipped while network is disabled")

    monkeypatch.setattr("static.cli.auto_install.auto_install_python", _forbidden)
    monkeypatch.setattr("static.cli.auto_install._post_install_hooks", _forbidden)
    monkeypatch.setattr("static.cli.auto_install.auto_install_system_tools", _forbidden)

    passed, _, _ = preflight.step_preflight(console=None)
    assert passed is False


def test_download_rejects_placeholder_hash_before_network(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def _forbidden_get(*args, **kwargs):
        raise AssertionError("download must not start with a placeholder hash")

    monkeypatch.setattr("requests.get", _forbidden_get)

    ok = auto_install._download_and_extract_zip(
        "https://github.com/example/tool.zip",
        tmp_path,
        "tool",
        expected_sha256="deadbeef",
    )
    assert ok is False


def test_download_extracts_only_when_sha256_matches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    body = _zip_bytes("trivy.exe", b"ok")
    digest = hashlib.sha256(body).hexdigest()
    checked_urls: list[str] = []

    monkeypatch.setattr(
        "static.core.network.assert_network_allowed",
        lambda url, *, label: checked_urls.append(url),
    )
    monkeypatch.setattr(
        "requests.get",
        lambda *args, **kwargs: _FakeResponse(body),
    )

    ok = auto_install._download_and_extract_zip(
        "https://github.com/example/tool.zip",
        tmp_path,
        "tool",
        expected_sha256=digest,
    )
    assert ok is True
    assert checked_urls == ["https://github.com/example/tool.zip"]
    assert (tmp_path / "trivy.exe").read_bytes() == b"ok"


def test_download_rejects_sha256_mismatch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    body = _zip_bytes("trivy.exe", b"ok")
    monkeypatch.setattr(
        "static.core.network.assert_network_allowed",
        lambda url, *, label: None,
    )
    monkeypatch.setattr(
        "requests.get",
        lambda *args, **kwargs: _FakeResponse(body),
    )

    ok = auto_install._download_and_extract_zip(
        "https://github.com/example/tool.zip",
        tmp_path,
        "tool",
        expected_sha256="1" * 64,
    )
    assert ok is False
    assert not (tmp_path / "trivy.exe").exists()


def test_download_validates_redirect_target_before_following(
    tmp_path: Path,
    monkeypatch,
) -> None:
    body = _zip_bytes("trivy.exe", b"ok")
    digest = hashlib.sha256(body).hexdigest()
    calls: list[str] = []

    def _assert_allowed(url: str, *, label: str) -> None:
        calls.append(url)
        if "evil.example" in url:
            raise ValueError("blocked final host")

    def _fake_get(url: str, **kwargs):
        if url == "https://github.com/example/tool.zip":
            return _FakeResponse(
                status_code=302,
                headers={"Location": "https://evil.example/tool.zip"},
            )
        raise AssertionError("blocked redirect target must not be requested")

    monkeypatch.setattr("static.core.network.assert_network_allowed", _assert_allowed)
    monkeypatch.setattr("requests.get", _fake_get)

    ok = auto_install._download_and_extract_zip(
        "https://github.com/example/tool.zip",
        tmp_path,
        "tool",
        expected_sha256=digest,
    )
    assert ok is False
    assert calls == [
        "https://github.com/example/tool.zip",
        "https://evil.example/tool.zip",
    ]


def test_download_allows_verified_redirect_chain(
    tmp_path: Path,
    monkeypatch,
) -> None:
    body = _zip_bytes("trivy.exe", b"ok")
    digest = hashlib.sha256(body).hexdigest()
    checked_urls: list[str] = []
    requested_urls: list[str] = []

    def _assert_allowed(url: str, *, label: str) -> None:
        checked_urls.append(url)

    def _fake_get(url: str, **kwargs):
        requested_urls.append(url)
        if url == "https://github.com/example/tool.zip":
            return _FakeResponse(
                status_code=302,
                headers={"Location": "https://objects.githubusercontent.com/tool.zip"},
            )
        return _FakeResponse(body)

    monkeypatch.setattr("static.core.network.assert_network_allowed", _assert_allowed)
    monkeypatch.setattr("requests.get", _fake_get)

    ok = auto_install._download_and_extract_zip(
        "https://github.com/example/tool.zip",
        tmp_path,
        "tool",
        expected_sha256=digest,
    )
    assert ok is True
    assert checked_urls == [
        "https://github.com/example/tool.zip",
        "https://objects.githubusercontent.com/tool.zip",
    ]
    assert requested_urls == checked_urls
    assert (tmp_path / "trivy.exe").is_file()