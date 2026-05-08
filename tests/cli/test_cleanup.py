"""Regression tests for forensic cleanup invariants (DATA_LIFECYCLE R1).

The contract enforced here:

* Extracted reference and target source trees (``_ref_extract`` /
  ``_tgt_extract``) under the per-scan output directory MUST be removed
  on every exit path --- normal completion, uncaught exception, and
  SIGINT / SIGTERM --- so that PHI extracted from a REDCap installation
  never outlives the analyst process.

These tests exercise the building blocks (``_phase_cleanup`` and
``_register_cleanup``) directly rather than spinning up a full scan;
the full-pipeline contract is implicitly covered because both
mechanisms are wired into ``step_run_scan``.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path

import pytest


def _make_scan_layout(root: Path) -> tuple[Path, Path]:
    audit = root / "audit"
    ref = audit / "_ref_extract"
    tgt = audit / "_tgt_extract"
    for d in (ref, tgt):
        d.mkdir(parents=True)
        (d / "redcap.php").write_text("<?php // pretend PHI lives here ?>")
    return ref, tgt


def test_phase_cleanup_removes_extracted_trees(tmp_path: Path) -> None:
    from static.cli.workflow import _phase_cleanup

    ref, tgt = _make_scan_layout(tmp_path)
    assert ref.is_dir() and tgt.is_dir()

    _phase_cleanup(None, tmp_path)

    assert not ref.exists(), "reference extract tree must be removed"
    assert not tgt.exists(), "target extract tree must be removed"


def test_phase_cleanup_warns_on_residue(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If shutil.rmtree fails, the operator must be warned, not silenced."""
    import static.cli.workflow as wf

    _make_scan_layout(tmp_path)

    def _boom(_path: object) -> None:
        raise OSError("simulated EBUSY")

    monkeypatch.setattr(wf.shutil, "rmtree", _boom)

    with caplog.at_level(logging.WARNING, logger=wf.logger.name):
        wf._phase_cleanup(None, tmp_path)

    assert any("Residue not removed" in r.getMessage() for r in caplog.records)


def test_register_cleanup_uses_atexit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_register_cleanup`` must register via ``atexit.register``.

    We capture the handler at registration time rather than poking
    atexit's CPython internals. Invoking the captured handler must
    remove the residue trees.
    """
    import atexit

    import static.cli.workflow as wf

    captured: list[object] = []
    original_register = atexit.register

    def _capture(fn, *args, **kwargs):  # type: ignore[no-untyped-def]
        captured.append(fn)
        return original_register(fn, *args, **kwargs)

    monkeypatch.setattr(atexit, "register", _capture)

    ref, tgt = _make_scan_layout(tmp_path)
    wf._register_cleanup(tmp_path)

    assert captured, "expected _register_cleanup to call atexit.register"
    captured[-1]()  # type: ignore[operator]

    assert not ref.exists()
    assert not tgt.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT semantics differ on Windows")
def test_register_cleanup_handles_sigint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SIGINT delivered to the process must trigger residue removal.

    We replace ``os.kill`` (used inside the handler to re-raise the
    signal with default disposition) so the handler does not actually
    terminate the test process.
    """
    import static.cli.workflow as wf

    ref, tgt = _make_scan_layout(tmp_path)

    kills: list[int] = []
    monkeypatch.setattr(wf._os, "kill", lambda pid, sig: kills.append(sig))

    original_handler = signal.getsignal(signal.SIGINT)
    try:
        wf._register_cleanup(tmp_path)
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)  # allow signal delivery
    finally:
        signal.signal(signal.SIGINT, original_handler)

    assert not ref.exists()
    assert not tgt.exists()
    assert signal.SIGINT in kills
