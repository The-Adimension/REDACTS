"""Tests for :mod:`core.file_utils`.

Covers DUP-005 (``detect_category``), DUP-006 (``human_size``), and the
consolidated ``is_binary`` utility.  The :class:`TestLegacyParity` suite
re-implements the original adapter methods inline and asserts identical
output from the new canonical functions.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from REDACTS.core import file_utils
from REDACTS.core.file_utils import (
    BinaryDetectionStrategy,
    detect_category,
    get_binary_strategies,
    get_size_units,
    human_size,
    is_binary,
    null_byte_strategy,
    ratio_strategy,
    register_binary_strategy,
    register_size_units,
    replace_binary_strategy,
    replace_size_units,
)
from REDACTS.core.constants import get_category_map


# ═══════════════════════════════════════════════════════════════════════════
# TestDetectCategory
# ═══════════════════════════════════════════════════════════════════════════


class TestDetectCategory:
    """Tests for :func:`detect_category`."""

    def test_known_code_extension(self) -> None:
        assert detect_category(".php") == "code"

    def test_known_markup_extension(self) -> None:
        assert detect_category(".html") == "markup"

    def test_known_style_extension(self) -> None:
        assert detect_category(".css") == "style"

    def test_known_data_extension(self) -> None:
        assert detect_category(".json") == "data"

    def test_known_config_extension(self) -> None:
        assert detect_category(".ini") == "config"

    def test_known_doc_extension(self) -> None:
        assert detect_category(".md") == "doc"

    def test_known_binary_extension(self) -> None:
        assert detect_category(".png") == "binary"

    def test_unknown_extension_default_other(self) -> None:
        assert detect_category(".xyz") == "other"

    def test_unknown_extension_custom_default(self) -> None:
        assert detect_category(".xyz", default="unknown") == "unknown"

    def test_custom_category_map(self) -> None:
        custom = {"custom_cat": frozenset({".abc", ".def"})}
        assert detect_category(".abc", category_map=custom) == "custom_cat"
        assert detect_category(".xyz", category_map=custom) == "other"

    def test_empty_extension(self) -> None:
        assert detect_category("") == "other"

    def test_uses_canonical_map_by_default(self) -> None:
        """Confirm default uses get_category_map() from constants.

        Note: some extensions (e.g. ".sql") appear in multiple categories.
        ``detect_category`` returns the *first* match (dict iteration
        order), so we verify every extension resolves to *some* category
        rather than asserting the specific one (unless unambiguous).
        """
        canonical = get_category_map()
        all_exts = {ext for exts in canonical.values() for ext in exts}
        for ext in all_exts:
            result = detect_category(ext)
            assert result != "other", f"{ext} should match a category, got 'other'"


# ═══════════════════════════════════════════════════════════════════════════
# TestHumanSize
# ═══════════════════════════════════════════════════════════════════════════


class TestHumanSize:
    """Tests for :func:`human_size`."""

    def test_zero_bytes(self) -> None:
        assert human_size(0) == "0.0 B"

    def test_small_bytes(self) -> None:
        assert human_size(100) == "100.0 B"

    def test_one_kb(self) -> None:
        assert human_size(1024) == "1.0 KB"

    def test_fractional_kb(self) -> None:
        assert human_size(1536) == "1.5 KB"

    def test_one_mb(self) -> None:
        assert human_size(1024 * 1024) == "1.0 MB"

    def test_one_gb(self) -> None:
        assert human_size(1024**3) == "1.0 GB"

    def test_one_tb(self) -> None:
        assert human_size(1024**4) == "1.0 TB"

    def test_large_tb(self) -> None:
        # 5 TiB
        result = human_size(5 * 1024**4)
        assert result == "5.0 TB"

    def test_negative_value(self) -> None:
        """manifest.py uses abs() — verify negative works."""
        assert human_size(-2048) == "-2.0 KB"

    def test_negative_zero(self) -> None:
        assert human_size(-0) == "0.0 B"

    def test_custom_precision(self) -> None:
        assert human_size(1536, precision=2) == "1.50 KB"
        assert human_size(1536, precision=0) == "2 KB"

    def test_iec_units(self) -> None:
        assert human_size(1024, unit_system="iec") == "1.0 KiB"
        assert human_size(1024**2, unit_system="iec") == "1.0 MiB"

    def test_decimal_units(self) -> None:
        assert human_size(1000, unit_system="decimal") == "1.0 kB"
        assert human_size(999, unit_system="decimal") == "999.0 B"

    def test_unknown_unit_system_raises(self) -> None:
        with pytest.raises(KeyError, match="bogus"):
            human_size(100, unit_system="bogus")

    def test_boundary_exactly_1024(self) -> None:
        """At exactly 1024 the divisor kicks in → "1.0 KB"."""
        assert human_size(1024) == "1.0 KB"

    def test_just_under_1024(self) -> None:
        assert human_size(1023) == "1023.0 B"


# ═══════════════════════════════════════════════════════════════════════════
# TestSizeUnitRegistry
# ═══════════════════════════════════════════════════════════════════════════


class TestSizeUnitRegistry:
    """Tests for the size-unit plugin registry."""

    def test_default_systems(self) -> None:
        units = get_size_units()
        assert "binary_si" in units
        assert "iec" in units
        assert "decimal" in units

    def test_register_new_system(self) -> None:
        register_size_units("test_custom", ("b", "k", "m"), 1000)
        try:
            assert "test_custom" in get_size_units()
            assert human_size(2000, unit_system="test_custom") == "2.0 k"
        finally:
            # Clean up
            file_utils._SIZE_UNITS.pop("test_custom", None)

    def test_register_duplicate_raises(self) -> None:
        with pytest.raises(KeyError, match="binary_si"):
            register_size_units("binary_si", ("X",), 10)

    def test_replace_and_restore(self) -> None:
        original = get_size_units()["binary_si"]
        replace_size_units("binary_si", ("byte", "kilo", "mega", "giga", "tera"), 1024)
        try:
            assert human_size(1024, unit_system="binary_si") == "1.0 kilo"
        finally:
            replace_size_units("binary_si", *original)

    def test_get_returns_copy(self) -> None:
        units = get_size_units()
        units["injected"] = (("X",), 1)
        assert "injected" not in get_size_units()


# ═══════════════════════════════════════════════════════════════════════════
# TestBinaryDetectionStrategy
# ═══════════════════════════════════════════════════════════════════════════


class TestBinaryDetectionStrategy:
    """Tests for built-in strategies and the strategy protocol."""

    def test_ratio_strategy_protocol(self) -> None:
        assert isinstance(ratio_strategy, BinaryDetectionStrategy)

    def test_null_byte_strategy_protocol(self) -> None:
        assert isinstance(null_byte_strategy, BinaryDetectionStrategy)

    def test_ratio_empty_chunk(self) -> None:
        assert ratio_strategy(b"", threshold=0.30) is False

    def test_null_byte_empty_chunk(self) -> None:
        assert null_byte_strategy(b"", threshold=0.30) is False

    def test_ratio_null_byte_detected(self) -> None:
        assert ratio_strategy(b"hello\x00world", threshold=0.30) is True

    def test_ratio_high_non_text(self) -> None:
        # All bytes 0x80 — well above 30%
        chunk = bytes([0x80] * 100)
        assert ratio_strategy(chunk, threshold=0.30) is True

    def test_ratio_low_non_text(self) -> None:
        # All printable ASCII — 0% non-text
        chunk = b"Hello, World! 12345"
        assert ratio_strategy(chunk, threshold=0.30) is False

    def test_null_byte_no_null(self) -> None:
        assert null_byte_strategy(b"normal text", threshold=0.30) is False

    def test_null_byte_with_null(self) -> None:
        assert null_byte_strategy(b"has\x00null", threshold=0.30) is True

    def test_custom_strategy(self) -> None:
        """A custom strategy that always reports binary."""

        def always_binary(chunk: bytes, *, threshold: float) -> bool:
            return True

        assert isinstance(always_binary, BinaryDetectionStrategy)


# ═══════════════════════════════════════════════════════════════════════════
# TestBinaryStrategyRegistry
# ═══════════════════════════════════════════════════════════════════════════


class TestBinaryStrategyRegistry:
    """Tests for the binary-strategy plugin registry."""

    def test_default_strategies(self) -> None:
        strategies = get_binary_strategies()
        assert "ratio" in strategies
        assert "null_byte" in strategies

    def test_register_new(self) -> None:
        def my_strat(chunk: bytes, *, threshold: float) -> bool:
            return False

        register_binary_strategy("test_strat", my_strat)
        try:
            assert "test_strat" in get_binary_strategies()
        finally:
            file_utils._BINARY_STRATEGIES.pop("test_strat", None)

    def test_register_duplicate_raises(self) -> None:
        with pytest.raises(KeyError, match="ratio"):
            register_binary_strategy("ratio", ratio_strategy)

    def test_replace_strategy(self) -> None:
        original = get_binary_strategies()["ratio"]
        try:
            replace_binary_strategy("ratio", null_byte_strategy)
            assert get_binary_strategies()["ratio"] is null_byte_strategy
        finally:
            replace_binary_strategy("ratio", original)

    def test_get_returns_copy(self) -> None:
        strats = get_binary_strategies()
        strats["injected"] = null_byte_strategy
        assert "injected" not in get_binary_strategies()


# ═══════════════════════════════════════════════════════════════════════════
# TestIsBinary
# ═══════════════════════════════════════════════════════════════════════════


class TestIsBinary(object):
    """Tests for :func:`is_binary`."""

    def test_binary_extension_shortcut(self, tmp_path: Path) -> None:
        f = tmp_path / "image.png"
        f.write_text("not really an image")
        assert is_binary(f, extension=".png", binary_extensions=frozenset({".png"})) is True

    def test_text_file_not_binary(self, tmp_path: Path) -> None:
        f = tmp_path / "readme.txt"
        f.write_text("Hello, world!")
        assert is_binary(f) is False

    def test_null_bytes_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "data.bin"
        f.write_bytes(b"text\x00binary")
        assert is_binary(f) is True

    def test_high_non_text_ratio(self, tmp_path: Path) -> None:
        f = tmp_path / "weird.dat"
        f.write_bytes(bytes(range(128, 256)))
        assert is_binary(f) is True

    def test_extension_inferred_from_path(self, tmp_path: Path) -> None:
        f = tmp_path / "photo.jpg"
        f.write_text("doesnt matter")
        assert is_binary(f, binary_extensions=frozenset({".jpg"})) is True

    def test_unreadable_file_is_binary(self, tmp_path: Path) -> None:
        fake = tmp_path / "nonexistent.txt"
        assert is_binary(fake) is True

    def test_no_binary_extensions_skips_shortcut(self, tmp_path: Path) -> None:
        """When binary_extensions=None, extension check is skipped."""
        f = tmp_path / "test.png"
        f.write_text("plain text content")
        # .png would match an extension set, but we pass None
        assert is_binary(f, binary_extensions=None) is False

    def test_custom_strategy_as_string(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(bytes([0x80] * 100))  # high non-text, no null byte
        # ratio strategy: True (high ratio)
        assert is_binary(f, strategy="ratio") is True
        # null_byte strategy: False (no null bytes)
        assert is_binary(f, strategy="null_byte") is False

    def test_custom_strategy_as_callable(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")

        def always_true(chunk: bytes, *, threshold: float) -> bool:
            return True

        assert is_binary(f, strategy=always_true) is True

    def test_unknown_strategy_falls_back(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("plain text")
        # Unknown string strategy → falls back to "ratio", which says False
        assert is_binary(f, strategy="nonexistent") is False

    def test_custom_chunk_size(self, tmp_path: Path) -> None:
        f = tmp_path / "mixed.dat"
        # First 10 bytes: text; next 100 bytes: binary
        f.write_bytes(b"0123456789" + bytes([0xFF] * 100))
        # chunk_size=10 → only reads the text part → not binary
        assert is_binary(f, chunk_size=10) is False
        # chunk_size=110 → reads everything → binary
        assert is_binary(f, chunk_size=110) is True

    def test_custom_threshold(self, tmp_path: Path) -> None:
        f = tmp_path / "edge.dat"
        # 80 printable + 20 non-printable = 20% ratio
        f.write_bytes(b"A" * 80 + bytes([0x80] * 20))
        assert is_binary(f, threshold=0.30) is False  # 20% < 30%
        assert is_binary(f, threshold=0.10) is True  # 20% > 10%

    def test_string_path_accepted(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert is_binary(str(f)) is False


# ═══════════════════════════════════════════════════════════════════════════
# TestLegacyParity — guarantee identical output to original adapters
# ═══════════════════════════════════════════════════════════════════════════


class TestLegacyParity:
    """Re-implement original adapter methods inline and assert parity."""

    # -- DUP-005 parity: _detect_category ---------------------------------

    @staticmethod
    def _legacy_file_analyzer_detect_category(extension: str) -> str:
        """Exact reimplementation of FileAnalyzer._detect_category."""
        # Uses the FileAnalyzer.CATEGORY_MAP (6 categories, no "binary")
        file_analyzer_category_map = {
            "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
            "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
            "style": {".css", ".scss", ".less", ".sass"},
            "data": {".json", ".csv", ".yml", ".yaml", ".sql"},
            "config": {".ini", ".conf", ".htaccess", ".env"},
            "doc": {".md", ".txt", ".rst", ".pdf"},
        }
        for category, extensions in file_analyzer_category_map.items():
            if extension in extensions:
                return category
        return "other"

    @staticmethod
    def _legacy_manifest_detect_category(ext: str) -> str:
        """Exact reimplementation of ManifestBuilder._detect_category."""
        # Uses module-level CATEGORY_MAP (7 categories, includes "binary")
        manifest_category_map = {
            "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
            "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
            "style": {".css", ".scss", ".less", ".sass"},
            "data": {".json", ".csv", ".yml", ".yaml"},
            "config": {".ini", ".conf", ".htaccess", ".env", ".user.ini"},
            "doc": {".md", ".txt", ".rst"},
            "binary": {
                ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
                ".zip", ".gz", ".tar", ".rar", ".7z",
                ".exe", ".dll", ".so", ".dylib", ".wasm",
                ".phar", ".db", ".sqlite", ".sqlite3",
            },
        }
        for category, extensions in manifest_category_map.items():
            if ext in extensions:
                return category
        return "unknown"

    def test_parity_file_analyzer_code(self) -> None:
        for ext in (".php", ".js", ".py", ".sh", ".bat", ".sql"):
            legacy = self._legacy_file_analyzer_detect_category(ext)
            # Using file_analyzer's category map (no "binary", no ".user.ini")
            fa_map = {
                "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
                "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
                "style": {".css", ".scss", ".less", ".sass"},
                "data": {".json", ".csv", ".yml", ".yaml", ".sql"},
                "config": {".ini", ".conf", ".htaccess", ".env"},
                "doc": {".md", ".txt", ".rst", ".pdf"},
            }
            canonical = detect_category(ext, category_map=fa_map, default="other")
            assert canonical == legacy, f"Mismatch for {ext}: {canonical!r} != {legacy!r}"

    def test_parity_manifest_unknown(self) -> None:
        for ext in (".xyz", ".zzz", ""):
            legacy = self._legacy_manifest_detect_category(ext)
            m_map = {
                "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
                "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
                "style": {".css", ".scss", ".less", ".sass"},
                "data": {".json", ".csv", ".yml", ".yaml"},
                "config": {".ini", ".conf", ".htaccess", ".env", ".user.ini"},
                "doc": {".md", ".txt", ".rst"},
                "binary": {
                    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
                    ".zip", ".gz", ".tar", ".rar", ".7z",
                    ".exe", ".dll", ".so", ".dylib", ".wasm",
                    ".phar", ".db", ".sqlite", ".sqlite3",
                },
            }
            canonical = detect_category(ext, category_map=m_map, default="unknown")
            assert canonical == legacy, f"Mismatch for {ext}: {canonical!r} != {legacy!r}"

    def test_parity_manifest_binary(self) -> None:
        """manifest.py has 'binary' category — canonical map should match."""
        m_map = {
            "code": {".php", ".js", ".py", ".sh", ".bat", ".sql", ".inc", ".module"},
            "markup": {".html", ".htm", ".xml", ".twig", ".tpl", ".svg"},
            "style": {".css", ".scss", ".less", ".sass"},
            "data": {".json", ".csv", ".yml", ".yaml"},
            "config": {".ini", ".conf", ".htaccess", ".env", ".user.ini"},
            "doc": {".md", ".txt", ".rst"},
            "binary": {
                ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf",
                ".zip", ".gz", ".tar", ".rar", ".7z",
                ".exe", ".dll", ".so", ".dylib", ".wasm",
                ".phar", ".db", ".sqlite", ".sqlite3",
            },
        }
        for ext in (".png", ".jpg", ".exe", ".dll", ".zip"):
            legacy = self._legacy_manifest_detect_category(ext)
            canonical = detect_category(ext, category_map=m_map, default="unknown")
            assert canonical == legacy == "binary"

    # -- DUP-006 parity: _human_size --------------------------------------

    @staticmethod
    def _legacy_file_analyzer_human_size(size_bytes: int) -> str:
        """Exact reimplementation of FileAnalyzer._human_size."""
        for unit in ("B", "KB", "MB", "GB"):
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024  # type: ignore[assignment]
        return f"{size_bytes:.1f} TB"

    @staticmethod
    def _legacy_manifest_human_size(size: int) -> str:
        """Exact reimplementation of ManifestBuilder._human_size."""
        for unit in ("B", "KB", "MB", "GB"):
            if abs(size) < 1024:
                return f"{size:.1f} {unit}"
            size = size / 1024  # type: ignore[assignment]
        return f"{size:.1f} TB"

    @pytest.mark.parametrize(
        "value",
        [0, 1, 100, 512, 1023, 1024, 1536, 2048, 1024**2, 1024**3, 1024**4],
    )
    def test_human_size_parity_file_analyzer(self, value: int) -> None:
        legacy = self._legacy_file_analyzer_human_size(value)
        canonical = human_size(value)
        assert canonical == legacy, f"Mismatch for {value}: {canonical!r} != {legacy!r}"

    @pytest.mark.parametrize(
        "value",
        [0, 1, 100, -1, -100, -1024, -2048, 1024, 1536, 1024**2, 1024**3],
    )
    def test_human_size_parity_manifest(self, value: int) -> None:
        legacy = self._legacy_manifest_human_size(value)
        canonical = human_size(value)
        assert canonical == legacy, f"Mismatch for {value}: {canonical!r} != {legacy!r}"

    # -- is_binary parity -------------------------------------------------

    def test_is_binary_parity_file_analyzer(self, tmp_path: Path) -> None:
        """Match FileAnalyzer._is_binary: ext check + ratio strategy."""
        binary_exts = frozenset({".png", ".jpg", ".exe"})

        # Binary by extension
        f1 = tmp_path / "test.png"
        f1.write_text("text")
        assert is_binary(
            f1, extension=".png", binary_extensions=binary_exts
        ) is True

        # Binary by content (null bytes)
        f2 = tmp_path / "data.dat"
        f2.write_bytes(b"text\x00here")
        assert is_binary(
            f2, binary_extensions=binary_exts, strategy="ratio"
        ) is True

        # Text file
        f3 = tmp_path / "readme.txt"
        f3.write_text("Hello, World!")
        assert is_binary(
            f3, binary_extensions=binary_exts, strategy="ratio"
        ) is False

    def test_is_binary_parity_sensitive_data(self, tmp_path: Path) -> None:
        """Match sensitive_data.py: null_byte only, no extension check."""
        # With high non-text but no nulls → should be False
        f = tmp_path / "high.dat"
        f.write_bytes(bytes([0x80] * 100))
        assert is_binary(
            f, binary_extensions=None, strategy="null_byte"
        ) is False

        # With null bytes → True
        f2 = tmp_path / "null.dat"
        f2.write_bytes(b"has\x00null")
        assert is_binary(
            f2, binary_extensions=None, strategy="null_byte"
        ) is True
