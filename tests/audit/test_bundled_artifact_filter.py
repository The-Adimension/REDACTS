"""Bundled-source artifacts must not flood content scanning.

A ``repomix-output.*`` file concatenates an entire codebase into a single file.
Content-scanning it re-detects every pattern in the bundled source, producing
hundreds of non-distinct findings. Such files are excluded from the delta set
that feeds deep content scanning, but remain in ``files_added`` (so the
structural anomaly is still reported) and are still Magika-typed elsewhere.
"""

from __future__ import annotations

import pytest

from static.audit.baseline import StructuralDiffResult, _is_bundled_artifact


@pytest.mark.parametrize(
    "path",
    [
        "ControlCenter/repomix-output.xml",
        "repomix-output.txt",
        "repomix-output.md",
        "repomix-output.json",
        "a/b/c/repomix-output.xml",
        "REPOMIX-OUTPUT.XML",  # case-insensitive
    ],
)
def test_recognises_repomix_bundles(path: str) -> None:
    assert _is_bundled_artifact(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "ControlCenter/error_log",
        "index.php",
        "config/database.php",
        "my-repomix-output-notes.txt",  # not the bundle filename
        "repomix.php",
    ],
)
def test_ordinary_files_are_not_artifacts(path: str) -> None:
    assert _is_bundled_artifact(path) is False


def test_delta_files_excludes_bundle_but_added_keeps_it() -> None:
    diff = StructuralDiffResult()
    diff.files_added = ["ControlCenter/error_log", "ControlCenter/repomix-output.xml"]
    diff.files_modified = ["index.php"]

    # Excluded from deep content scanning...
    assert "ControlCenter/repomix-output.xml" not in diff.delta_files
    # ...but still present as a structural addition (the anomaly is reported).
    assert "ControlCenter/repomix-output.xml" in diff.files_added
    # Everything else still scanned.
    assert diff.delta_files == {"ControlCenter/error_log", "index.php"}


def test_modified_bundle_is_also_excluded_from_delta() -> None:
    diff = StructuralDiffResult()
    diff.files_modified = ["repomix-output.xml", "app.php"]
    assert diff.delta_files == {"app.php"}


def test_repomix_runner_excludes_prior_bundles_by_default() -> None:
    from static.collect.repomix import RepomixRunner

    excludes = RepomixRunner().exclude
    assert any("repomix-output" in pat for pat in excludes)
