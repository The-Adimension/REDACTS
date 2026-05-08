"""REDACTS DAST - Helper barrel exports."""

from .auth import (
    go_to_control_center,
    go_to_project,
    go_to_project_page,
    is_logged_in,
    login,
    logout,
    save_auth_state,
)
from .filesystem_snapshot import (
    FileEntry,
    SnapshotDiff,
    SuspiciousFile,
    diff_snapshots,
    save_diff_report,
    take_snapshot,
)
from .network_monitor import CapturedRequest, NetworkMonitor
from .security_assertions import (
    assert_clean_download,
    assert_no_debug_artifacts,
    assert_no_external_requests,
    assert_no_info_leak_headers,
    assert_no_php_errors,
    assert_no_reflected_xss,
    assert_secure_cookies,
    collect_console_errors,
)

__all__ = [
    # auth
    "login",
    "logout",
    "go_to_control_center",
    "go_to_project",
    "go_to_project_page",
    "is_logged_in",
    "save_auth_state",
    # filesystem
    "take_snapshot",
    "diff_snapshots",
    "save_diff_report",
    "FileEntry",
    "SnapshotDiff",
    "SuspiciousFile",
    # network
    "NetworkMonitor",
    "CapturedRequest",
    # security assertions
    "assert_no_info_leak_headers",
    "assert_no_reflected_xss",
    "assert_no_php_errors",
    "assert_no_debug_artifacts",
    "assert_clean_download",
    "assert_secure_cookies",
    "assert_no_external_requests",
    "collect_console_errors",
]
