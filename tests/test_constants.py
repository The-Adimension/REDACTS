"""Tests for core.constants — shared constants registry.

Covers every public constant, every ``get_*`` accessor, every
``register_*`` mutator, and parity with the original scattered
definitions.
"""

from __future__ import annotations

import importlib
import types

import pytest

from REDACTS.core import constants


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _reload_constants() -> types.ModuleType:
    """Re-import constants to reset mutable registries."""
    return importlib.reload(constants)


# ═══════════════════════════════════════════════════════════════════════════
# 1. VERSION
# ═══════════════════════════════════════════════════════════════════════════


class TestVersion:
    """DUP-013: VERSION constant."""

    def test_version_is_string(self) -> None:
        assert isinstance(constants.VERSION, str)

    def test_version_matches_package(self) -> None:
        from REDACTS import __version__
        assert constants.VERSION == __version__

    def test_version_semver_format(self) -> None:
        parts = constants.VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


# ═══════════════════════════════════════════════════════════════════════════
# 2. LANGUAGE_MAP
# ═══════════════════════════════════════════════════════════════════════════


class TestLanguageMap:
    """DUP-003: Extension → language mapping."""

    def test_get_returns_dict(self) -> None:
        lm = constants.get_language_map()
        assert isinstance(lm, dict)
        assert len(lm) >= 23  # original 23 entries

    def test_get_returns_copy(self) -> None:
        """Mutation of the returned dict must NOT affect the registry."""
        lm = constants.get_language_map()
        lm[".zzz"] = "FakeLang"
        assert ".zzz" not in constants.get_language_map()

    def test_known_entries(self) -> None:
        lm = constants.get_language_map()
        assert lm[".php"] == "PHP"
        assert lm[".js"] == "JavaScript"
        assert lm[".py"] == "Python"
        assert lm[".htaccess"] == "Apache"
        assert lm[".inc"] == "PHP Include"
        assert lm[".module"] == "PHP Module"

    def test_register_new(self) -> None:
        mod = _reload_constants()
        mod.register_language(".ts", "TypeScript")
        assert mod.get_language_map()[".ts"] == "TypeScript"
        _reload_constants()  # cleanup

    def test_register_overwrite(self) -> None:
        mod = _reload_constants()
        mod.register_language(".php", "PHP 8")
        assert mod.get_language_map()[".php"] == "PHP 8"
        _reload_constants()

    def test_register_bad_extension(self) -> None:
        with pytest.raises(ValueError, match="must start with '.'"):
            constants.register_language("php", "PHP")

    def test_all_keys_start_with_dot(self) -> None:
        for ext in constants.get_language_map():
            assert ext.startswith("."), f"{ext!r} missing leading dot"


# ═══════════════════════════════════════════════════════════════════════════
# 3. CATEGORY_MAP
# ═══════════════════════════════════════════════════════════════════════════


class TestCategoryMap:
    """DUP-004: Category → extensions mapping."""

    def test_get_returns_frozen(self) -> None:
        cm = constants.get_category_map()
        assert isinstance(cm, dict)
        for v in cm.values():
            assert isinstance(v, frozenset)

    def test_get_returns_copy(self) -> None:
        cm = constants.get_category_map()
        cm["test_cat"] = frozenset({".zzz"})
        assert "test_cat" not in constants.get_category_map()

    def test_expected_categories(self) -> None:
        cm = constants.get_category_map()
        for cat in ("code", "markup", "style", "data", "config", "doc", "binary"):
            assert cat in cm, f"Missing category {cat!r}"

    def test_superset_data_has_sql(self) -> None:
        """File_analyzer's 'data' includes .sql — verify it survived."""
        assert ".sql" in constants.get_category_map()["data"]

    def test_superset_config_has_user_ini(self) -> None:
        """Manifest's 'config' includes .user.ini — verify it survived."""
        assert ".user.ini" in constants.get_category_map()["config"]

    def test_superset_doc_has_pdf(self) -> None:
        """File_analyzer's 'doc' includes .pdf — verify it survived."""
        assert ".pdf" in constants.get_category_map()["doc"]

    def test_binary_category_present(self) -> None:
        """Manifest's 'binary' category — verify it survived."""
        binary = constants.get_category_map()["binary"]
        assert ".png" in binary
        assert ".exe" in binary
        assert ".phar" in binary

    def test_register_extend_existing(self) -> None:
        mod = _reload_constants()
        mod.register_category_entries("code", [".rb", ".java"])
        cm = mod.get_category_map()
        assert ".rb" in cm["code"]
        assert ".java" in cm["code"]
        # original entries still present
        assert ".php" in cm["code"]
        _reload_constants()

    def test_register_new_category(self) -> None:
        mod = _reload_constants()
        mod.register_category_entries("test_new", [".test"])
        assert ".test" in mod.get_category_map()["test_new"]
        _reload_constants()

    def test_register_bad_extension(self) -> None:
        with pytest.raises(ValueError, match="must start with '.'"):
            constants.register_category_entries("code", ["js"])


# ═══════════════════════════════════════════════════════════════════════════
# 4. SEVERITY_CVSS
# ═══════════════════════════════════════════════════════════════════════════


class TestSeverityCvss:
    """DUP-009: Severity → CVSS score."""

    def test_all_levels_present(self) -> None:
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert level in constants.SEVERITY_CVSS

    def test_descending_order(self) -> None:
        assert constants.SEVERITY_CVSS["CRITICAL"] > constants.SEVERITY_CVSS["HIGH"]
        assert constants.SEVERITY_CVSS["HIGH"] > constants.SEVERITY_CVSS["MEDIUM"]
        assert constants.SEVERITY_CVSS["MEDIUM"] > constants.SEVERITY_CVSS["LOW"]
        assert constants.SEVERITY_CVSS["LOW"] > constants.SEVERITY_CVSS["INFO"]

    def test_info_is_zero(self) -> None:
        assert constants.SEVERITY_CVSS["INFO"] == 0.0

    def test_critical_representative(self) -> None:
        """Matches semgrep_adapter.py L329 inline dict."""
        assert constants.SEVERITY_CVSS["CRITICAL"] == 9.5


# ═══════════════════════════════════════════════════════════════════════════
# 5. SEVERITY_ORDER
# ═══════════════════════════════════════════════════════════════════════════


class TestSeverityOrder:
    """DUP-010: Severity → sort-rank."""

    def test_all_levels_present(self) -> None:
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert level in constants.SEVERITY_ORDER

    def test_critical_is_highest(self) -> None:
        assert constants.SEVERITY_ORDER["CRITICAL"] == max(
            constants.SEVERITY_ORDER.values()
        )

    def test_info_is_lowest(self) -> None:
        assert constants.SEVERITY_ORDER["INFO"] == min(
            constants.SEVERITY_ORDER.values()
        )

    def test_parity_forensic_report(self) -> None:
        """Values match reporting/forensic_report.py L46 _SEVERITY_ORDER."""
        expected = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        assert constants.SEVERITY_ORDER == expected

    def test_parity_investigator(self) -> None:
        """Values match investigation/investigator.py L46 _SEVERITY_ORDER."""
        expected = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        assert constants.SEVERITY_ORDER == expected


# ═══════════════════════════════════════════════════════════════════════════
# 6. SKIP_DIRS
# ═══════════════════════════════════════════════════════════════════════════


class TestSkipDirs:
    """DUP-011: Directory exclusion set."""

    def test_get_returns_frozenset(self) -> None:
        sd = constants.get_skip_dirs()
        assert isinstance(sd, frozenset)

    def test_core_entries_present(self) -> None:
        """The two entries present in ALL 13 original sites."""
        sd = constants.get_skip_dirs()
        assert ".git" in sd
        assert "node_modules" in sd

    def test_common_entries(self) -> None:
        sd = constants.get_skip_dirs()
        for d in ("__pycache__", "vendor", ".svn", ".tox", ".DS_Store"):
            assert d in sd, f"Missing {d!r}"

    def test_get_returns_frozen_copy(self) -> None:
        sd = constants.get_skip_dirs()
        with pytest.raises(AttributeError):
            sd.add("new_dir")  # type: ignore[attr-defined]

    def test_register_new(self) -> None:
        mod = _reload_constants()
        mod.register_skip_dirs(".mypy_cache", ".pytest_cache")
        sd = mod.get_skip_dirs()
        assert ".mypy_cache" in sd
        assert ".pytest_cache" in sd
        # originals still present
        assert ".git" in sd
        _reload_constants()

    def test_register_idempotent(self) -> None:
        mod = _reload_constants()
        orig_len = len(mod.get_skip_dirs())
        mod.register_skip_dirs(".git")  # already present
        assert len(mod.get_skip_dirs()) == orig_len
        _reload_constants()


# ═══════════════════════════════════════════════════════════════════════════
# 7. SCANNABLE_EXTENSIONS
# ═══════════════════════════════════════════════════════════════════════════


class TestScannableExtensions:
    """DUP-012: Extensions eligible for content scanning."""

    def test_get_returns_frozenset(self) -> None:
        se = constants.get_scannable_extensions()
        assert isinstance(se, frozenset)

    def test_minimum_count(self) -> None:
        assert len(constants.get_scannable_extensions()) >= 22

    def test_php_related(self) -> None:
        se = constants.get_scannable_extensions()
        for ext in (".php", ".inc", ".module"):
            assert ext in se, f"Missing {ext!r}"

    def test_config_files(self) -> None:
        se = constants.get_scannable_extensions()
        for ext in (".ini", ".conf", ".env", ".htaccess", ".user.ini"):
            assert ext in se, f"Missing {ext!r}"

    def test_register_new(self) -> None:
        mod = _reload_constants()
        mod.register_scannable_extensions(".ts", ".tsx")
        se = mod.get_scannable_extensions()
        assert ".ts" in se
        assert ".tsx" in se
        _reload_constants()

    def test_register_bad_extension(self) -> None:
        with pytest.raises(ValueError, match="must start with '.'"):
            constants.register_scannable_extensions("php")

    def test_get_returns_frozen_copy(self) -> None:
        se = constants.get_scannable_extensions()
        with pytest.raises(AttributeError):
            se.add(".zzz")  # type: ignore[attr-defined]


# ═══════════════════════════════════════════════════════════════════════════
# 8. SKIP_FILE_PATTERNS
# ═══════════════════════════════════════════════════════════════════════════


class TestSkipFilePatterns:
    """File-glob skip patterns from AnalysisConfig.ignore_patterns."""

    def test_is_frozenset(self) -> None:
        assert isinstance(constants.SKIP_FILE_PATTERNS, frozenset)

    def test_known_entries(self) -> None:
        for pat in ("*.pyc", "*.map", "*.min.js", "*.min.css", "Thumbs.db"):
            assert pat in constants.SKIP_FILE_PATTERNS, f"Missing {pat!r}"


# ═══════════════════════════════════════════════════════════════════════════
# 9. Threshold constants
# ═══════════════════════════════════════════════════════════════════════════


class TestThresholds:
    """HC-004 (entropy) and HC-014 (binary detection)."""

    def test_entropy_suspicious(self) -> None:
        assert constants.DEFAULT_ENTROPY_THRESHOLD == 7.5

    def test_entropy_elevated(self) -> None:
        assert constants.ELEVATED_ENTROPY_THRESHOLD == 6.0

    def test_entropy_ordering(self) -> None:
        assert constants.DEFAULT_ENTROPY_THRESHOLD > constants.ELEVATED_ENTROPY_THRESHOLD

    def test_binary_threshold(self) -> None:
        assert constants.BINARY_DETECTION_THRESHOLD == 0.30

    def test_binary_threshold_range(self) -> None:
        assert 0.0 < constants.BINARY_DETECTION_THRESHOLD < 1.0


# ═══════════════════════════════════════════════════════════════════════════
# 10. Legacy parity — verify canonical values match original sites
# ═══════════════════════════════════════════════════════════════════════════


class TestLegacyParity:
    """Ensure the canonical constants are exact supersets of every original."""

    def test_language_map_parity_file_analyzer(self) -> None:
        """All 23 entries from forensics/file_analyzer.py FileAnalyzer.LANGUAGE_MAP."""
        legacy = {
            ".php": "PHP", ".js": "JavaScript", ".css": "CSS",
            ".html": "HTML", ".htm": "HTML", ".xml": "XML",
            ".json": "JSON", ".sql": "SQL", ".py": "Python",
            ".sh": "Shell", ".bat": "Batch", ".yml": "YAML",
            ".yaml": "YAML", ".md": "Markdown", ".txt": "Text",
            ".csv": "CSV", ".ini": "INI", ".conf": "Config",
            ".htaccess": "Apache", ".twig": "Twig", ".tpl": "Template",
            ".inc": "PHP Include", ".module": "PHP Module",
        }
        canonical = constants.get_language_map()
        for ext, lang in legacy.items():
            assert canonical.get(ext) == lang, f"Mismatch for {ext!r}"

    def test_language_map_parity_manifest(self) -> None:
        """All 23 entries from evidence/manifest.py LANGUAGE_MAP."""
        # Identical to file_analyzer — just verify the same superset holds.
        legacy = {
            ".php": "PHP", ".js": "JavaScript", ".css": "CSS",
            ".html": "HTML", ".htm": "HTML", ".xml": "XML",
            ".json": "JSON", ".sql": "SQL", ".py": "Python",
            ".sh": "Shell", ".bat": "Batch", ".yml": "YAML",
            ".yaml": "YAML", ".md": "Markdown", ".txt": "Text",
            ".csv": "CSV", ".ini": "INI", ".conf": "Config",
            ".htaccess": "Apache", ".twig": "Twig", ".tpl": "Template",
            ".inc": "PHP Include", ".module": "PHP Module",
        }
        canonical = constants.get_language_map()
        for ext, lang in legacy.items():
            assert canonical.get(ext) == lang

    def test_category_map_parity_file_analyzer(self) -> None:
        """Every entry from file_analyzer.py CATEGORY_MAP is a subset."""
        legacy = {
            "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
            "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
            "style": {".css", ".scss", ".less", ".sass"},
            "data": {".json", ".csv", ".yml", ".yaml", ".sql"},
            "config": {".ini", ".conf", ".htaccess", ".env"},
            "doc": {".md", ".txt", ".rst", ".pdf"},
        }
        canonical = constants.get_category_map()
        for cat, exts in legacy.items():
            assert exts <= canonical[cat], f"Category {cat!r} missing entries"

    def test_category_map_parity_manifest(self) -> None:
        """Every entry from manifest.py CATEGORY_MAP is a subset."""
        legacy = {
            "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
            "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
            "style": {".css", ".scss", ".less", ".sass"},
            "data": {".json", ".csv", ".yml", ".yaml"},
            "config": {".ini", ".conf", ".htaccess", ".env", ".user.ini"},
            "doc": {".md", ".txt", ".rst"},
            "binary": {
                ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
                ".zip", ".gz", ".tar", ".rar", ".7z", ".exe", ".dll",
                ".so", ".dylib", ".wasm", ".phar", ".db", ".sqlite", ".sqlite3",
            },
        }
        canonical = constants.get_category_map()
        for cat, exts in legacy.items():
            assert exts <= canonical[cat], f"Category {cat!r} missing entries"

    def test_severity_order_parity(self) -> None:
        """Both original dicts are value-equal to canonical."""
        # From reporting/forensic_report.py
        report = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        # From investigation/investigator.py
        invest = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        assert constants.SEVERITY_ORDER == report
        assert constants.SEVERITY_ORDER == invest

    def test_severity_cvss_parity_semgrep(self) -> None:
        """Matches inline dict from semgrep_adapter.py L329."""
        expected = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MEDIUM": 5.5,
            "LOW": 3.0,
            "INFO": 0.0,
        }
        assert constants.SEVERITY_CVSS == expected

    def test_skip_dirs_superset_of_intersection(self) -> None:
        """Canonical set includes the intersection found in ALL 13 sites."""
        intersection = {".git", "node_modules"}
        assert intersection <= constants.get_skip_dirs()

    def test_scannable_superset_of_sensitive_data(self) -> None:
        """21 entries from knowledge/sensitive_data.py SCANNABLE_EXTENSIONS."""
        legacy = frozenset({
            ".php", ".inc", ".js", ".json", ".yml", ".yaml", ".xml", ".sql",
            ".txt", ".csv", ".html", ".htm", ".conf", ".ini", ".env", ".log",
            ".md", ".htaccess", ".user.ini", ".py", ".sh",
        })
        assert legacy <= constants.get_scannable_extensions()

    def test_scannable_superset_of_security_scanner(self) -> None:
        """11 core extensions from forensics/security_scanner.py."""
        legacy = frozenset({
            ".php", ".inc", ".module", ".html", ".js", ".sql",
            ".ini", ".conf", ".json", ".yml", ".yaml",
        })
        assert legacy <= constants.get_scannable_extensions()
