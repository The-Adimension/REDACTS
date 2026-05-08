"""
Shared fixtures for the REDACTS test suite.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

# Re-export the case-contract factory so fixtures defined under
# ``tests/core/conftest.py`` are visible to every test directory
# (knowledge, scanners, etc.) without duplicating the wiring.
from tests.core.conftest import valid_case_factory  # noqa: F401


@pytest.fixture
def clean_env(monkeypatch):
    """Remove all REDACTS_* environment variables for a clean test."""
    for key in list(os.environ):
        if key.startswith("REDACTS_"):
            monkeypatch.delenv(key, raising=False)
