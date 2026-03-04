"""
Shared fixtures for the REDACTS test suite.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def tmp_dir(tmp_path: Path) -> Path:
    """Re-export pytest's tmp_path for convenience."""
    return tmp_path


@pytest.fixture
def fake_redcap(tmp_path: Path) -> Path:
    """Create a minimal fake REDCap directory tree.

    Contains the markers that ``detect_redcap_root`` looks for.
    """
    root = tmp_path / "redcap"
    root.mkdir()
    (root / "redcap_connect.php").write_text("<?php // REDCap connect\n")
    (root / "index.php").write_text("<?php // entry\n")
    classes = root / "Classes"
    classes.mkdir()
    (classes / "Dummy.php").write_text("<?php class Dummy {}\n")
    return root


@pytest.fixture
def clean_env(monkeypatch):
    """Remove all REDACTS_* environment variables for a clean test."""
    for key in list(os.environ):
        if key.startswith("REDACTS_"):
            monkeypatch.delenv(key, raising=False)
