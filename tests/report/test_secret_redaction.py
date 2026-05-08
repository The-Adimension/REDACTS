"""Regression tests for credential redaction in evidence previews
(DATA_LIFECYCLE R2).

Forensic invariant: snippets of audited config files (``database.php``,
``.user.ini``, ``.htaccess``) embedded in a finding payload must not
leak the original credential. Whatever the analyst sees in the rendered
report must be the masked form ``***REDACTED***`` for any string that
looks credential-shaped.
"""

from __future__ import annotations

from threat_base.sensitive_data import redact_preview


def test_redact_preview_masks_php_password_assignment() -> None:
    snippet = (
        "<?php\n"
        "$conn = new mysqli('localhost', 'redcap', 'P@ssw0rd!2025', 'redcap_db');\n"
    )
    out = redact_preview(snippet)
    assert "P@ssw0rd!2025" not in out
    assert "***REDACTED***" in out


def test_redact_preview_masks_dotenv_style() -> None:
    snippet = "DB_PASSWORD=hunter2hunter2\nAPI_KEY: sk-live-1234567890abcdef"
    out = redact_preview(snippet)
    assert "hunter2hunter2" not in out
    assert "sk-live-1234567890abcdef" not in out


def test_redact_preview_preserves_short_innocuous_quoted_strings() -> None:
    # "abc" is below the 8-char heuristic threshold -> should pass through.
    snippet = "echo 'abc';"
    assert redact_preview(snippet) == snippet


def test_redact_preview_handles_empty_input() -> None:
    assert redact_preview("") == ""
    assert redact_preview(None) is None  # type: ignore[arg-type]


def test_user_ini_preview_is_redacted_in_steps_payload(tmp_path) -> None:
    """End-to-end check at the call site: ConfigFilesStep emits a
    redacted ``content_preview`` for ``.user.ini`` files.
    """
    import importlib

    steps = importlib.import_module("static.analyze.steps")

    # Build a minimal .user.ini that would otherwise leak a token-looking value.
    user_ini = tmp_path / ".user.ini"
    user_ini.write_text(
        "auto_prepend_file = /tmp/x.php\n"
        "session.save_path = '/var/lib/php/sessions'\n"
        "secret_token = 'abcdef1234567890'\n"
    )

    # _check_user_ini_files is a private method on ConfigFileAuditStep;
    # instantiate the class with whatever its no-arg constructor needs.
    cls = getattr(steps, "ConfigIntegrityStep", None)
    assert cls is not None, "ConfigIntegrityStep class not found in steps module"
    instance = cls.__new__(cls)  # avoid full __init__ wiring for this unit test
    results = cls._check_user_ini_files(instance, tmp_path)

    assert results, "expected at least one .user.ini result"
    preview = results[0].get("content_preview", "")
    assert "abcdef1234567890" not in preview
    assert "***REDACTED***" in preview
