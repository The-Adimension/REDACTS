"""Tests for the dependency checker (cli/dependencies.py)."""

from __future__ import annotations

from static.cli.dependencies import (
    DependencyReport,
    DependencyStatus,
    check_dependencies,
    _check_python_package,
    _check_system_tool,
)


class TestCheckPythonPackage:
    def test_importable_package(self):
        """json is always available in CPython."""
        status = _check_python_package("json", "json", True, "", "stdlib")
        assert status.available is True
        assert status.required is True

    def test_missing_package(self):
        status = _check_python_package(
            "nonexistent_pkg_xyz", "nonexistent_pkg_xyz", False, "", "test"
        )
        assert status.available is False
        assert "Not installed" in status.error

    def test_required_missing_is_not_ok(self):
        status = _check_python_package(
            "nonexistent_pkg_xyz", "nonexistent_pkg_xyz", True, "", "test"
        )
        assert status.ok is False

    def test_optional_missing_is_ok(self):
        status = _check_python_package(
            "nonexistent_pkg_xyz", "nonexistent_pkg_xyz", False, "", "test"
        )
        assert status.ok is True


class TestCheckExternalTool:
    def test_python_in_path(self):
        """Python itself should always be in PATH during tests."""
        tool = {"name": "python", "binary": "python", "required": True,
                "description": "test", "install_cmd": "", "install_url": ""}
        status = _check_system_tool(tool)
        # On some CI the command might be 'python3' only
        if not status.available:
            tool["binary"] = "python3"
            status = _check_system_tool(tool)
        assert status.available is True

    def test_missing_tool(self):
        tool = {"name": "this_tool_does_not_exist_redacts",
                "binary": "this_tool_does_not_exist_redacts",
                "required": False, "description": "test",
                "install_cmd": "", "install_url": ""}
        status = _check_system_tool(tool)
        assert status.available is False
        assert "not found" in status.error.lower()


class TestDependencyReport:
    def test_all_ok(self):
        report = DependencyReport(checks=[
            DependencyStatus("a", True, True),
            DependencyStatus("b", True, False),
        ])
        assert report.all_required_ok is True
        assert len(report.missing_required) == 0

    def test_missing_required(self):
        report = DependencyReport(checks=[
            DependencyStatus("a", False, True, error="missing"),
        ])
        assert report.all_required_ok is False
        assert len(report.missing_required) == 1

    def test_summary_readable(self):
        report = DependencyReport(checks=[
            DependencyStatus("good", True, True),
            DependencyStatus("bad", False, True, error="gone"),
        ])
        txt = report.summary()
        assert "1/2 available" in txt
        assert "bad" in txt


class TestCheckDependencies:
    def test_runs_without_crash(self):
        """Integration test: check_dependencies should not crash."""
        report = check_dependencies(
            include_optional_tools=False,
            fail_on_missing=False,
        )
        assert isinstance(report, DependencyReport)
        assert len(report.checks) > 0

    def test_required_packages_checked(self):
        """All required packages should appear in the report."""
        report = check_dependencies(
            include_optional_tools=False,
            fail_on_missing=False,
        )
        names = [c.name for c in report.checks]
        for pkg in ("chardet", "magika", "paramiko", "requests"):
            assert pkg in names, f"{pkg} missing from dependency report"


class TestSystemToolsAndHints:
    def test_system_tools_includes_required_binaries(self):
        from static.cli.dependencies import SYSTEM_TOOLS
        names = {t["name"] for t in SYSTEM_TOOLS}
        for tool in ("semgrep", "trivy", "yara"):
            assert tool in names, f"{tool} missing from SYSTEM_TOOLS"

    def test_node_repomix_are_not_external_system_tools(self):
        """Repomix is a Python package now; node/npx are no longer host tools."""
        from static.cli.dependencies import SYSTEM_TOOLS, PYTHON_PACKAGES

        names = {t["name"] for t in SYSTEM_TOOLS}
        assert "repomix" not in names
        assert "node" not in names
        assert "npx" not in names

        # ...and repomix is declared as a Python dependency instead.
        py_imports = {import_name for import_name, *_ in PYTHON_PACKAGES}
        assert "repomix" in py_imports

    def test_docker_is_marked_dast_only(self):
        from static.cli.dependencies import SYSTEM_TOOLS

        docker = next(t for t in SYSTEM_TOOLS if t["name"] == "docker")
        assert docker.get("dast_only") is True

    def test_fix_hint_for_tool_os_aware(self, monkeypatch):
        import sys
        from static.cli.dependencies import fix_hint_for_tool

        tool = {
            "name": "npx",
            "binary": "npx",
            "required": True,
            "install_cmd_win": "Install Node.js from https://nodejs.org or winget install OpenJS.NodeJS",
            "install_cmd_posix": "Install Node.js via brew install node or apt install nodejs",
        }

        monkeypatch.setattr(sys, "platform", "win32")
        win_hint = fix_hint_for_tool(tool)
        assert "winget" in win_hint or "https://nodejs.org" in win_hint

        monkeypatch.setattr(sys, "platform", "linux")
        posix_hint = fix_hint_for_tool(tool)
        assert "brew" in posix_hint or "apt" in posix_hint

