"""The init wizard must not produce a contract that misrepresents the evidence.

Two ways it could:

* **Fabricating inputs.** ``[inputs.*].path`` must exist and, for files, carry a
  matching SHA-256 - so the wizard used to ``touch()`` a placeholder when the
  named path was absent. That seals a contract whose recorded digest is the
  digest of an empty file; the scan then reports a pristine result for evidence
  that was never supplied.
* **Unescaped TOML.** Every field is interpolated into a hand-written template.
  A quote or backslash in an analyst name, case ID, or Windows path produces a
  file that either fails to parse or parses into something other than what was
  entered.
"""

from __future__ import annotations

import argparse
import hashlib
import tomllib
from pathlib import Path

import pytest

from static.cli.init_wizard import generate_case_toml, run_init_wizard, toml_escape


def _args(tmp_path: Path, **overrides) -> argparse.Namespace:
    base = dict(
        target=None,
        reference=None,
        case_id="CASE-INTEGRITY-001",
        analyst="Analyst",
        organization="Org",
        output=tmp_path / "case.toml",
        yes=True,
        non_interactive=True,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# --- missing evidence is refused, never invented --


def test_missing_target_is_refused(tmp_path: Path) -> None:
    reference = tmp_path / "reference.zip"
    reference.write_bytes(b"reference payload")

    rc = run_init_wizard(
        _args(tmp_path, target=tmp_path / "absent.zip", reference=reference)
    )

    assert rc == 2


def test_missing_reference_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "target.zip"
    target.write_bytes(b"target payload")

    rc = run_init_wizard(
        _args(tmp_path, target=target, reference=tmp_path / "absent.zip")
    )

    assert rc == 2


def test_refusal_creates_no_placeholder_files(tmp_path: Path) -> None:
    """The whole point: nothing is written where the evidence should be."""
    reference = tmp_path / "reference.zip"
    reference.write_bytes(b"reference payload")
    absent = tmp_path / "nested" / "absent.zip"

    run_init_wizard(_args(tmp_path, target=absent, reference=reference))

    assert not absent.exists()
    assert not absent.parent.exists()


def test_refusal_writes_no_case_toml(tmp_path: Path) -> None:
    """Refuse before emitting a contract, not after."""
    out = tmp_path / "case.toml"
    reference = tmp_path / "reference.zip"
    reference.write_bytes(b"reference payload")

    run_init_wizard(
        _args(tmp_path, target=tmp_path / "absent.zip", reference=reference, output=out)
    )

    assert not out.exists()


def test_empty_file_digest_never_reaches_a_contract(tmp_path: Path) -> None:
    """Guard the specific failure: sha256 of b'' recorded as the evidence digest."""
    out = tmp_path / "case.toml"
    reference = tmp_path / "reference.zip"
    reference.write_bytes(b"reference payload")

    run_init_wizard(
        _args(tmp_path, target=tmp_path / "absent.zip", reference=reference, output=out)
    )

    empty_digest = hashlib.sha256(b"").hexdigest()
    assert not out.exists() or empty_digest not in out.read_text(encoding="utf-8")


def test_existing_directory_inputs_are_accepted(tmp_path: Path) -> None:
    """A directory is legitimate evidence and carries no file digest."""
    target = tmp_path / "target_dir"
    reference = tmp_path / "reference_dir"
    target.mkdir()
    reference.mkdir()

    rc = run_init_wizard(_args(tmp_path, target=target, reference=reference))

    assert rc == 0


# --- TOML escaping --


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('say "hi"', 'say \\"hi\\"'),
        ("back\\slash", "back\\\\slash"),
        ("tab\there", "tab\\there"),
        ("new\nline", "new\\nline"),
        ("plain", "plain"),
    ],
)
def test_toml_escape_basic_cases(raw: str, expected: str) -> None:
    assert toml_escape(raw) == expected


def test_toml_escape_encodes_control_characters() -> None:
    assert toml_escape("\x00\x1f") == "\\u0000\\u001F"


@pytest.mark.parametrize(
    "hostile",
    [
        'Bob "The Analyst" O\'Brien',
        "C:\\Cases\\Q3\\target.zip",
        'x" \ninjected = "yes',
        "line1\nline2",
        "tab\tseparated",
    ],
)
def test_generated_toml_survives_hostile_field_values(hostile: str) -> None:
    """Whatever was entered must round-trip through the parser unchanged."""
    text = generate_case_toml(
        case_id=hostile,
        analyst=hostile,
        organization=hostile,
        target_path="inputs/target.zip",
        target_sha256="0" * 64,
        reference_path="inputs/reference.zip",
        reference_sha256="0" * 64,
        scanners=["regex"],
    )

    parsed = tomllib.loads(text)

    assert parsed["case"]["id"] == hostile
    assert parsed["case"]["analyst"] == hostile
    assert parsed["case"]["organization"] == hostile


def test_injected_key_does_not_appear_as_toml_structure() -> None:
    """A crafted value must stay a value - it must not become a new key."""
    text = generate_case_toml(
        case_id='x"\nnetwork_disabled = false\njunk = "y',
        analyst="A",
        organization="O",
        target_path="inputs/target.zip",
        target_sha256="0" * 64,
        reference_path="inputs/reference.zip",
        reference_sha256="0" * 64,
        scanners=["regex"],
    )

    parsed = tomllib.loads(text)

    assert "junk" not in parsed["case"]
    assert "network_disabled" not in parsed["case"]
    assert parsed["security"]["network_disabled"] is False


def test_windows_path_with_quote_round_trips() -> None:
    text = generate_case_toml(
        case_id="CASE-1",
        analyst="A",
        organization="O",
        target_path='C:\\cases\\od"d\\target.zip',
        target_sha256="0" * 64,
        reference_path="inputs/reference.zip",
        reference_sha256="0" * 64,
        scanners=["regex"],
    )

    parsed = tomllib.loads(text)

    assert parsed["inputs"]["target"]["path"] == 'C:/cases/od"d/target.zip'
