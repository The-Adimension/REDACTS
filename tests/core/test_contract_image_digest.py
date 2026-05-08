"""Digest required on every dynamic image."""

from __future__ import annotations

import pytest

from static.core.contract import CaseConfigError, load_and_freeze


def _swap_digest(text: str, image_section: str, new_digest_line: str) -> str:
    """Replace the ``digest = "..."`` line that follows the named section header."""
    lines = text.splitlines()
    out: list[str] = []
    in_section = False
    for line in lines:
        if line.strip() == image_section:
            in_section = True
            out.append(line)
            continue
        if in_section and line.startswith("digest"):
            out.append(new_digest_line)
            in_section = False
            continue
        # Leave the section block once the next section header appears.
        if in_section and line.startswith("[") and line != image_section:
            in_section = False
        out.append(line)
    return "\n".join(out) + "\n"


def test_tag_only_digest_refused(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = _swap_digest(text, "[dynamic.images.mariadb]", 'digest = "tag-only-no-sha"')
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError, match=r"digest.*sha256"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_short_digest_refused(valid_case_factory, isolated_search_paths):
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    text = _swap_digest(text, "[dynamic.images.php]", 'digest = "sha256:deadbeef"')
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError, match=r"digest"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)


def test_uppercase_digest_refused(valid_case_factory, isolated_search_paths):
    """Digest regex enforces lowercase hex (Docker's canonical form)."""
    case_path = valid_case_factory()
    text = case_path.read_text(encoding="utf-8")
    bad = "sha256:" + ("A" * 64)
    text = _swap_digest(text, "[dynamic.images.sandbox]", f'digest = "{bad}"')
    case_path.write_text(text, encoding="utf-8")
    with pytest.raises(CaseConfigError, match=r"digest"):
        load_and_freeze(case_path, env={}, dotenv_search_paths=isolated_search_paths)
