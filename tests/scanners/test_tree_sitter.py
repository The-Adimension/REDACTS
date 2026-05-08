"""tree-sitter PHP analyser tests.

These tests assert two things --- both are forensic invariants, not
optimisations:

1. Every PHP fixture under ``tests/data/php/positive/`` produces at
   least one entry in ``PHPFileAST.security_patterns``.  Each fixture
   is a minimal reproduction of one rule the analyser is meant to
   catch (eval, exec/system, unserialize, INFINITERED-style layered
   obfuscation, deprecated mysql_* API).
2. Every PHP fixture under ``tests/data/php/negative/`` produces zero
   ``security_patterns`` entries.  These are deliberately benign
   REDCap-style snippets; matching against them would be a false
   positive and is treated as a regression.

Limits: tree-sitter's grammar tolerates malformed PHP and reports
parse errors as a flag rather than an exception.  We therefore do not
exercise the parser against adversarial input here --- only the
analyser's pattern extraction layer on top of well-formed input.

If ``tree_sitter`` or ``tree_sitter_php`` is not importable in the
test environment the whole module skips: the analyser is an optional
dependency for environments without a C toolchain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

tree_sitter = pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_php")

from static.scanners.tree_sitter_adapter import TreeSitterAnalyzer  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "data" / "php"
POSITIVE = sorted((FIXTURES / "positive").glob("*.php"))
NEGATIVE = sorted((FIXTURES / "negative").glob("*.php"))


@pytest.fixture(scope="module")
def analyzer() -> TreeSitterAnalyzer:
    return TreeSitterAnalyzer()


def test_positive_fixture_set_is_complete() -> None:
    """Sanity: at least the five positive fixtures the audit roadmap requires."""
    assert len(POSITIVE) >= 5, f"Need >=5 positive PHP fixtures, found {len(POSITIVE)}"


def test_negative_fixture_set_is_complete() -> None:
    assert len(NEGATIVE) >= 5, f"Need >=5 negative PHP fixtures, found {len(NEGATIVE)}"


@pytest.mark.parametrize("fixture", POSITIVE, ids=lambda p: p.name)
def test_positive_fixture_produces_security_finding(
    analyzer: TreeSitterAnalyzer, fixture: Path
) -> None:
    ast = analyzer.parse_file(fixture, fixture.parent)
    assert ast.error is None, f"unexpected read/parse error: {ast.error}"
    assert ast.security_patterns, (
        f"{fixture.name} produced no security_patterns; "
        "tree-sitter analyser failed to flag a known-bad construct"
    )


@pytest.mark.parametrize("fixture", NEGATIVE, ids=lambda p: p.name)
def test_negative_fixture_is_clean(
    analyzer: TreeSitterAnalyzer, fixture: Path
) -> None:
    ast = analyzer.parse_file(fixture, fixture.parent)
    assert ast.error is None, f"unexpected read/parse error: {ast.error}"
    assert not ast.security_patterns, (
        f"{fixture.name} produced false-positive findings: {ast.security_patterns!r}"
    )


def test_parser_does_not_crash_on_empty_file(
    analyzer: TreeSitterAnalyzer, tmp_path: Path
) -> None:
    empty = tmp_path / "empty.php"
    empty.write_text("")
    ast = analyzer.parse_file(empty, tmp_path)
    assert ast.error is None
    assert ast.security_patterns == []


def test_parser_does_not_crash_on_malformed_input(
    analyzer: TreeSitterAnalyzer, tmp_path: Path
) -> None:
    """tree-sitter is error-tolerant; the analyser must not raise."""
    bad = tmp_path / "broken.php"
    bad.write_text("<?php function {{{ }")
    ast = analyzer.parse_file(bad, tmp_path)
    # We don't care what it returns --- only that it didn't raise.
    assert ast.path.endswith("broken.php")
