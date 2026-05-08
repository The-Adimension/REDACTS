"""CI gate: forbid ``yaml.load`` outside of tests.

``yaml.load`` without a ``SafeLoader`` is RCE-equivalent on untrusted
input; ``yaml.safe_load`` is the only acceptable form for loading the
threat-base YAML files (which, although shipped with REDACTS, are
checksummed and could in principle be swapped in transit by a hostile
mirror). Every introduction of bare ``yaml.load(`` therefore fails CI.

A test under ``tests/`` is permitted to import ``yaml.load`` for
negative-case construction; that exception is encoded by skipping the
``tests`` directory in the walk.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKIP_PARTS = {"tests", ".venv", "venv", "__pycache__", "node_modules", "build", "dist"}
PATTERN = re.compile(r"\byaml\.load\s*\(")


def test_no_unsafe_yaml_load() -> None:
    offenders: list[str] = []
    for py in ROOT.rglob("*.py"):
        if any(part in SKIP_PARTS for part in py.parts):
            continue
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        if PATTERN.search(text):
            offenders.append(str(py.relative_to(ROOT)))
    assert not offenders, (
        f"yaml.load found in: {offenders}. "
        "Use yaml.safe_load - yaml.load is RCE-equivalent on untrusted input."
    )
