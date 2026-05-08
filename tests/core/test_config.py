"""Tests for ``static.core.config``.

``REDACTSConfig`` is built either with built-in defaults (via
``REDACTSConfig()``) or from a :class:`FrozenCaseContract` (via
:meth:`REDACTSConfig.from_contract`). Environment-variable and
JSON-file overrides are not supported.
"""

from __future__ import annotations

import pytest

from static.core import REDACTSConfig
from static.core.contract import load_and_freeze


# --- Defaults ---


class TestDefaults:
    def test_default_config_creates_successfully(self):
        cfg = REDACTSConfig()
        assert cfg.log_level == "INFO"
        assert cfg.analysis.parallel_workers == 4
        assert cfg.sandbox.enabled is True

    def test_default_config_passes_validation(self):
        cfg = REDACTSConfig()
        cfg.validate()  # should not raise


# --- Validation -


class TestValidation:
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


# --- from_contract ----------------


class TestFromContract:
    """``REDACTSConfig.from_contract`` is the only contract-driven loader."""

    def test_paths_propagate_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.output_dir == str(contract.paths.output_root)
        assert cfg.temp_dir == str(contract.paths.temp_root)

    def test_logging_level_propagates(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.log_level == contract.logging.level.upper()

    def test_sandbox_image_pinned_from_contract(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.sandbox.docker_image == contract.dynamic.images.sandbox.full_ref

    def test_sandbox_security_hardening_propagates(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.sandbox.network_disabled is contract.security.network_disabled
        assert cfg.sandbox.no_new_privileges is contract.security.sandbox_no_new_priv
        assert cfg.sandbox.read_only_rootfs is contract.security.sandbox_read_only
        assert cfg.sandbox.drop_capabilities == list(contract.security.sandbox_drop_caps)

    def test_dast_propagates(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.dast.enabled is contract.dynamic.enabled
        assert cfg.dast.suites == list(contract.dynamic.suites)
        assert cfg.dast.port == contract.dynamic.port
        assert cfg.dast.timeout == contract.dynamic.suite_timeout
        assert cfg.dast.runtime == contract.dynamic.runtime

    def test_analysis_propagates(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.analysis.parallel_workers == contract.static.parallel_workers
        assert cfg.analysis.max_total_files == contract.static.max_total_files

    def test_report_formats_propagate(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.report.formats == list(contract.static.formats)

    def test_global_timeout_propagates(self, valid_case_factory):
        contract = load_and_freeze(valid_case_factory())
        cfg = REDACTSConfig.from_contract(contract)
        assert cfg.global_timeout_seconds == contract.static.global_timeout_seconds

    def test_validate_passes(self, valid_case_factory):
        # from_contract calls validate() internally; no raise = green.
        contract = load_and_freeze(valid_case_factory())
        REDACTSConfig.from_contract(contract)


# Removed API checks


class TestRemovedAPIs:
    """``REDACTSConfig`` does not expose env/file loaders."""

    def test_from_env_no_longer_exists(self):
        assert not hasattr(REDACTSConfig, "from_env")

    def test_from_file_no_longer_exists(self):
        assert not hasattr(REDACTSConfig, "from_file")

    def test_load_no_longer_exists(self):
        assert not hasattr(REDACTSConfig, "load")
