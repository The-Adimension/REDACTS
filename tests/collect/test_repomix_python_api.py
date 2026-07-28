"""RepomixRunner integration over the ``repomix`` Python package.

The Node ``repomix``/``npx`` CLI was replaced by the in-process Python API,
removing the Node host dependency and the Windows ``.cmd``-shim subprocess
path. These tests exercise the runner end-to-end (no subprocess, no network)
and pin the failure-is-non-fatal contract the collection step relies on.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from static.collect.repomix import RepomixResult, RepomixRunner


def _make_tree(root: Path) -> Path:
    src = root / "src"
    (src / "sub").mkdir(parents=True)
    (src / "index.php").write_text("<?php echo 'redcap'; ?>\n", encoding="utf-8")
    (src / "sub" / "util.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    # Junk that the default excludes should drop.
    (src / "node_modules").mkdir()
    (src / "node_modules" / "bundle.min.js").write_text("x" * 4000, encoding="utf-8")
    return src


def test_run_packs_tree_and_reports_counts(tmp_path: Path) -> None:
    src = _make_tree(tmp_path)
    out = tmp_path / "out" / "repomix_target.txt"

    result = RepomixRunner().run(source_dir=src, output_file=out, label="target")

    assert result.success is True
    assert out.is_file()
    assert result.output_file == str(out)
    assert result.total_files >= 2  # index.php + util.py, junk excluded
    assert result.total_chars > 0
    assert result.output_size_bytes == out.stat().st_size


def test_run_excludes_default_junk(tmp_path: Path) -> None:
    src = _make_tree(tmp_path)
    out = tmp_path / "repomix.txt"

    RepomixRunner().run(source_dir=src, output_file=out)
    packed = out.read_text(encoding="utf-8", errors="replace")

    assert "bundle.min.js" not in packed
    assert "index.php" in packed


def test_output_hash_matches_file(tmp_path: Path) -> None:
    src = _make_tree(tmp_path)
    out = tmp_path / "repomix.txt"

    result = RepomixRunner().run(source_dir=src, output_file=out)

    expected = hashlib.sha256(out.read_bytes()).hexdigest()
    assert result.output_hash == expected


def test_missing_package_is_non_fatal(tmp_path: Path, monkeypatch) -> None:
    """If the package is absent, run() returns a failed result, not an exception."""
    import builtins

    real_import = builtins.__import__

    def _blocked(name, *args, **kwargs):
        if name == "repomix" or name.startswith("repomix."):
            raise ImportError("simulated missing repomix")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _blocked)

    result = RepomixRunner().run(
        source_dir=tmp_path, output_file=tmp_path / "o.txt"
    )

    assert isinstance(result, RepomixResult)
    assert result.success is False
    assert result.error and "repomix" in result.error.lower()


def test_processing_error_is_non_fatal(tmp_path: Path) -> None:
    """A nonexistent source directory must yield a failed result, not raise."""
    result = RepomixRunner().run(
        source_dir=tmp_path / "does_not_exist",
        output_file=tmp_path / "o.txt",
    )

    assert result.success is False
    assert result.error


def test_is_available_reflects_import(tmp_path: Path) -> None:
    # repomix is a declared dependency, so it must be importable in the test env.
    assert RepomixRunner().is_available() is True


def test_no_subprocess_module_imported() -> None:
    """The rewrite is in-process: repomix.py must not import subprocess."""
    import static.collect.repomix as mod

    assert not hasattr(mod, "subprocess")
