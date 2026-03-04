"""Tests for REDACTS configuration system (core/__init__.py)."""

from __future__ import annotations

import json

import pytest

from REDACTS.core import REDACTSConfig


# ───────────────────────────────────────────────────────────
# Defaults
# ───────────────────────────────────────────────────────────


class TestDefaults:
    def test_default_config_creates_successfully(self):
        cfg = REDACTSConfig()
        assert cfg.log_level == "INFO"
        assert cfg.analysis.parallel_workers == 4
        assert cfg.sandbox.enabled is True

    def test_default_config_passes_validation(self):
        cfg = REDACTSConfig()
        cfg.validate()  # should not raise


# ───────────────────────────────────────────────────────────
# from_file
# ───────────────────────────────────────────────────────────


class TestFromFile:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            REDACTSConfig.from_file(tmp_path / "nonexistent.json")

    def test_valid_json(self, tmp_path):
        cfg_path = tmp_path / "redacts.json"
        cfg_path.write_text(json.dumps({
            "log_level": "DEBUG",
            "output_dir": "/tmp/out",
            "analysis": {"parallel_workers": 8},
        }))
        cfg = REDACTSConfig.from_file(cfg_path)
        assert cfg.log_level == "DEBUG"
        assert cfg.output_dir == "/tmp/out"
        assert cfg.analysis.parallel_workers == 8

    def test_invalid_json_raises(self, tmp_path):
        cfg_path = tmp_path / "bad.json"
        cfg_path.write_text("{not valid json}")
        with pytest.raises(Exception):
            REDACTSConfig.from_file(cfg_path)

    def test_invalid_values_fail_validation(self, tmp_path):
        cfg_path = tmp_path / "bad_vals.json"
        cfg_path.write_text(json.dumps({
            "analysis": {"parallel_workers": -1},
        }))
        with pytest.raises(ValueError, match="parallel_workers"):
            REDACTSConfig.from_file(cfg_path)


# ───────────────────────────────────────────────────────────
# from_env
# ───────────────────────────────────────────────────────────


class TestFromEnv:
    def test_workers_valid(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_WORKERS", "16")
        cfg = REDACTSConfig.from_env()
        assert cfg.analysis.parallel_workers == 16

    def test_workers_non_integer_raises(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_WORKERS", "abc")
        with pytest.raises(ValueError, match="positive integer"):
            REDACTSConfig.from_env()

    def test_workers_zero_raises(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_WORKERS", "0")
        with pytest.raises(ValueError, match=">= 1"):
            REDACTSConfig.from_env()

    def test_log_level_valid(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_LOG_LEVEL", "debug")
        cfg = REDACTSConfig.from_env()
        assert cfg.log_level == "DEBUG"

    def test_log_level_invalid_raises(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_LOG_LEVEL", "VERBOSE")
        with pytest.raises(ValueError, match="Invalid REDACTS_LOG_LEVEL"):
            REDACTSConfig.from_env()

    def test_dast_enabled(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_DAST_ENABLED", "true")
        cfg = REDACTSConfig.from_env()
        assert cfg.dast.enabled is True

    def test_dast_suites(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_DAST_SUITES", "export, admin")
        cfg = REDACTSConfig.from_env()
        assert cfg.dast.suites == ["export", "admin"]

    def test_sandbox_enabled(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_SANDBOX_ENABLED", "false")
        cfg = REDACTSConfig.from_env()
        assert cfg.sandbox.enabled is False

    def test_network_disabled(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_NETWORK_DISABLED", "false")
        cfg = REDACTSConfig.from_env()
        assert cfg.sandbox.network_disabled is False

    def test_output_dir(self, monkeypatch, clean_env):
        monkeypatch.setenv("REDACTS_OUTPUT_DIR", "/custom/output")
        cfg = REDACTSConfig.from_env()
        assert cfg.output_dir == "/custom/output"


# ───────────────────────────────────────────────────────────
# load (precedence: file > env > defaults)
# ───────────────────────────────────────────────────────────


class TestLoad:
    def test_env_overrides_file(self, tmp_path, monkeypatch, clean_env):
        cfg_path = tmp_path / ".redacts.json"
        cfg_path.write_text(json.dumps({"log_level": "WARNING"}))
        monkeypatch.setenv("REDACTS_LOG_LEVEL", "ERROR")
        cfg = REDACTSConfig.load(workspace=tmp_path)
        assert cfg.log_level == "ERROR"

    def test_all_env_vars_applied(self, tmp_path, monkeypatch, clean_env):
        cfg_path = tmp_path / ".redacts.json"
        cfg_path.write_text(json.dumps({}))
        monkeypatch.setenv("REDACTS_WORKERS", "2")
        monkeypatch.setenv("REDACTS_DAST_ENABLED", "true")
        monkeypatch.setenv("REDACTS_DAST_SUITES", "export")
        monkeypatch.setenv("REDACTS_NETWORK_DISABLED", "false")
        cfg = REDACTSConfig.load(workspace=tmp_path)
        assert cfg.analysis.parallel_workers == 2
        assert cfg.dast.enabled is True
        assert cfg.dast.suites == ["export"]
        assert cfg.sandbox.network_disabled is False


# ───────────────────────────────────────────────────────────
# validate
# ───────────────────────────────────────────────────────────


class TestValidation:
    def test_similarity_out_of_range(self):
        cfg = REDACTSConfig()
        cfg.comparison.similarity_threshold = 1.5
        with pytest.raises(ValueError, match="similarity_threshold"):
            cfg.validate()

    def test_invalid_report_format(self):
        cfg = REDACTSConfig()
        cfg.report.formats = ["pdf"]
        with pytest.raises(ValueError, match="Invalid report format"):
            cfg.validate()

    def test_negative_timeout(self):
        cfg = REDACTSConfig()
        cfg.sandbox.max_execution_time = 0
        with pytest.raises(ValueError, match="max_execution_time"):
            cfg.validate()
