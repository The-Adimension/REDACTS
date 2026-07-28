"""Semgrep must not report a silent no-op as success.

On unsupported runtimes (notably Python 3.14) the Semgrep engine installs but
does not run: the binary exits cleanly yet emits no SARIF. A functional Semgrep
with ``--sarif`` *always* emits a SARIF document, even with zero findings, so
empty output on a clean exit means no PHP coverage was obtained. Reporting that
as ``success`` would give false assurance that the code was scanned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from static.scanners.semgrep_adapter import SemgrepAdapter


def _adapter(monkeypatch, *, out: str, err: str = "", rc: int = 0) -> SemgrepAdapter:
    a = SemgrepAdapter()
    monkeypatch.setattr(a, "is_available", lambda: True)
    monkeypatch.setattr(a, "_resolve_invocation", lambda: ["semgrep"])
    monkeypatch.setattr(a, "get_version", lambda: "1.100.0")
    monkeypatch.setattr(a, "_run_subprocess", lambda *args, **kwargs: (out, err, rc))
    return a


_EMPTY_SARIF = json.dumps(
    {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}]}
)


def test_clean_exit_with_no_output_is_a_failure(monkeypatch, tmp_path: Path) -> None:
    """The 3.14 silent no-op: exit 0, empty stdout -> success must be False."""
    a = _adapter(monkeypatch, out="", rc=0)
    res = a.run(tmp_path)
    assert res.success is False
    assert any("no SARIF output" in e or "did not run" in e for e in res.errors)


def test_valid_empty_sarif_is_success(monkeypatch, tmp_path: Path) -> None:
    """A real run with zero findings still emits SARIF -> success True."""
    a = _adapter(monkeypatch, out=_EMPTY_SARIF, rc=0)
    res = a.run(tmp_path)
    assert res.success is True
    assert res.parsed_data["results_count"] == 0


def test_valid_sarif_with_findings_is_success(monkeypatch, tmp_path: Path) -> None:
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": []}},
                "results": [
                    {
                        "ruleId": "php.lang.security.eval",
                        "level": "error",
                        "message": {"text": "eval on user input"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "x.php"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    a = _adapter(monkeypatch, out=json.dumps(sarif), rc=1)
    res = a.run(tmp_path)
    assert res.success is True
    assert res.parsed_data["results_count"] == 1


def test_whitespace_only_output_is_a_failure(monkeypatch, tmp_path: Path) -> None:
    a = _adapter(monkeypatch, out="   \n  ", rc=0)
    res = a.run(tmp_path)
    assert res.success is False
