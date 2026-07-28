"""``select_scanners`` - the contract's [static].scanners list is the source of truth.

For a long time the scanner selection in ``case.toml`` was parsed, written by
``init``, and shown to the operator, but never actually consumed: what ran was
decided solely by "is the tool installed". This mirrored the same bug that had
already been fixed for ``[static].severity_gate``. ``select_scanners`` closes it:
a tool-backed scanner runs iff it is BOTH selected AND installed, with a
transparent notice for every conflict.
"""

from __future__ import annotations

import pytest

from static.cli.workflow import KNOWN_SCANNERS, select_scanners


def _installed(*names: str):
    present = set(names)
    return lambda n: n in present


ALL = _installed("regex", "yara", "trivy", "semgrep")


# --- selection is honored --


def test_excluded_scanner_does_not_run_even_if_installed() -> None:
    enables, _ = select_scanners(("regex", "yara", "trivy"), ALL)
    assert enables["semgrep"] is False
    assert enables["trivy"] is True
    assert enables["yara"] is True
    assert enables["regex"] is True


def test_selected_and_installed_runs() -> None:
    enables, _ = select_scanners(("regex", "semgrep"), ALL)
    assert enables["semgrep"] is True
    assert enables["regex"] is True
    # Not selected -> off, even though installed.
    assert enables["trivy"] is False
    assert enables["yara"] is False


def test_regex_needs_only_selection_no_tool() -> None:
    # regex has no backing binary: selection alone decides it.
    enables, _ = select_scanners(("yara",), _installed("yara"))
    assert enables["regex"] is False
    enables, _ = select_scanners(("regex",), _installed())
    assert enables["regex"] is True


def test_case_insensitive_selection() -> None:
    enables, _ = select_scanners(("Regex", "SEMGREP"), ALL)
    assert enables["semgrep"] is True
    assert enables["regex"] is True


# --- conflict notices --


def test_selected_but_missing_is_a_gap() -> None:
    enables, notices = select_scanners(("semgrep",), _installed("regex", "yara"))
    assert enables["semgrep"] is False
    gaps = [m for m, is_gap in notices if is_gap]
    assert any("selected in [static].scanners but not installed" in m for m in gaps)
    assert any("semgrep" in m for m in gaps)


def test_installed_but_not_selected_is_informational_not_a_gap() -> None:
    _, notices = select_scanners(("regex",), ALL)
    for message, is_gap in notices:
        if "skipped by choice" in message:
            assert is_gap is False


def test_unknown_scanner_name_is_a_gap() -> None:
    _, notices = select_scanners(("regex", "smgrep"), ALL)  # typo
    gaps = [m for m, is_gap in notices if is_gap]
    assert any("unknown scanner 'smgrep'" in m for m in gaps)


def test_no_conflict_no_notices() -> None:
    # Everything selected is installed and vice versa.
    _, notices = select_scanners(("regex", "yara", "trivy", "semgrep"), ALL)
    assert notices == []


# --- back-compat: no contract --


def test_none_selection_runs_whatever_is_installed() -> None:
    enables, notices = select_scanners(None, _installed("regex", "trivy"))
    assert enables == {
        "semgrep": False,
        "trivy": True,
        "yara": False,
        "regex": True,
    }
    assert notices == []


# --- invariants --


def test_known_scanners_are_exactly_the_gateable_set() -> None:
    assert KNOWN_SCANNERS == {"regex", "yara", "trivy", "semgrep"}


@pytest.mark.parametrize("name", sorted(KNOWN_SCANNERS))
def test_every_known_scanner_has_an_enable_key(name: str) -> None:
    enables, _ = select_scanners((name,), ALL)
    assert name in enables
