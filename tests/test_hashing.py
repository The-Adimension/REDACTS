"""Tests for core.hashing — Step 1.1 of the REDACTS refactoring plan.

Validates that the new canonical hashing module produces identical results
to the four legacy implementations it replaces, and that the Strategy /
Plugin-registry / Configuration-driven patterns work correctly.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from REDACTS.core.hashing import (
    DEFAULT_ALGORITHMS,
    DEFAULT_BUFFER_SIZE,
    HashStrategy,
    _ALGORITHM_REGISTRY,
    compute_hashes,
    compute_single_hash,
    get_registered_algorithms,
    hash_tree,
    register_algorithm,
    replace_algorithm,
    _resolve_factory,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    """Create a small sample file with known content."""
    p = tmp_path / "sample.txt"
    p.write_bytes(b"REDACTS test content for hashing\n")
    return p


@pytest.fixture
def known_digests(sample_file: Path) -> dict[str, str]:
    """Pre-compute reference digests using raw hashlib."""
    content = sample_file.read_bytes()
    return {
        "md5": hashlib.md5(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "sha512": hashlib.sha512(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
    }


@pytest.fixture
def sample_tree(tmp_path: Path) -> Path:
    """Create a small directory tree for hash_tree tests."""
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_bytes(b"file a\n")
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_bytes(b"file b\n")
    (root / "sub" / "c.bin").write_bytes(b"\x00\x01\x02\x03")
    return root


@pytest.fixture
def empty_file(tmp_path: Path) -> Path:
    """Create an empty file."""
    p = tmp_path / "empty"
    p.write_bytes(b"")
    return p


@pytest.fixture
def large_file(tmp_path: Path) -> Path:
    """Create a file larger than DEFAULT_BUFFER_SIZE to test chunked reads."""
    p = tmp_path / "large.bin"
    # 3 × buffer size ensures at least 3 read iterations
    p.write_bytes(os.urandom(DEFAULT_BUFFER_SIZE * 3 + 17))
    return p


# ---------------------------------------------------------------------------
# Test: Strategy pattern (HashStrategy protocol)
# ---------------------------------------------------------------------------

class TestHashStrategyProtocol:
    """Verify the HashStrategy protocol correctly identifies compliant objects."""

    def test_hashlib_objects_satisfy_protocol(self) -> None:
        assert isinstance(hashlib.md5(), HashStrategy)
        assert isinstance(hashlib.sha256(), HashStrategy)
        assert isinstance(hashlib.sha512(), HashStrategy)
        assert isinstance(hashlib.blake2b(), HashStrategy)

    def test_non_compliant_object_rejected(self) -> None:
        assert not isinstance("not a hasher", HashStrategy)
        assert not isinstance(42, HashStrategy)

    def test_custom_strategy_satisfies_protocol(self) -> None:
        """A custom object with update() and hexdigest() satisfies the protocol."""

        class ConstantHasher:
            def update(self, data: bytes, /) -> None:
                pass

            def hexdigest(self) -> str:
                return "deadbeef"

        assert isinstance(ConstantHasher(), HashStrategy)


# ---------------------------------------------------------------------------
# Test: Plugin registry
# ---------------------------------------------------------------------------

class TestPluginRegistry:
    """Verify the algorithm registry behaves correctly."""

    def test_default_algorithms_registered(self) -> None:
        registered = get_registered_algorithms()
        assert "sha256" in registered
        assert "sha512" in registered
        assert "blake2b" in registered
        # Insecure algorithms should NOT be registered by default
        assert "md5" not in registered
        assert "sha1" not in registered

    def test_register_new_algorithm(self) -> None:
        name = "_test_algo_register"
        try:
            register_algorithm(name, hashlib.sha256)
            assert name in get_registered_algorithms()
        finally:
            _ALGORITHM_REGISTRY.pop(name, None)

    def test_register_duplicate_raises(self) -> None:
        with pytest.raises(ValueError, match="already registered"):
            register_algorithm("sha256", hashlib.sha256)

    def test_register_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            register_algorithm("", hashlib.sha256)

    def test_replace_algorithm(self) -> None:
        name = "_test_algo_replace"
        try:
            register_algorithm(name, hashlib.md5)
            replace_algorithm(name, hashlib.sha256)
            # Should now produce sha256 digests
            hasher = _ALGORITHM_REGISTRY[name]()
            hasher.update(b"test")
            assert hasher.hexdigest() == hashlib.sha256(b"test").hexdigest()
        finally:
            _ALGORITHM_REGISTRY.pop(name, None)

    def test_resolve_unknown_algorithm_raises(self) -> None:
        with pytest.raises(KeyError, match="Unknown hash algorithm"):
            _resolve_factory("nonexistent_algo_xyz")

    def test_case_insensitive_lookup(self) -> None:
        factory = _resolve_factory("SHA256")
        hasher = factory()
        hasher.update(b"test")
        assert hasher.hexdigest() == hashlib.sha256(b"test").hexdigest()


# ---------------------------------------------------------------------------
# Test: compute_hashes (multi-algorithm)
# ---------------------------------------------------------------------------

class TestComputeHashes:
    """Verify compute_hashes produces correct digests."""

    def test_default_algorithms(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        result = compute_hashes(sample_file)
        assert "md5" not in result
        assert result["sha256"] == known_digests["sha256"]
        assert result["sha512"] == known_digests["sha512"]

    def test_custom_algorithm_subset(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        result = compute_hashes(sample_file, algorithms=("sha256",))
        assert list(result.keys()) == ["sha256"]
        assert result["sha256"] == known_digests["sha256"]

    def test_custom_algorithm_superset(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        # Temporarily register md5/sha1 for this test without permanently
        # mutating the internal algorithm registry.
        with patch.dict(
            "REDACTS.core.hashing._ALGORITHM_REGISTRY",
            {"md5": hashlib.md5, "sha1": hashlib.sha1},
            clear=False,
        ):
            result = compute_hashes(
                sample_file, algorithms=("md5", "sha256", "sha512", "sha1")
            )
            assert result["md5"] == known_digests["md5"]
            assert result["sha1"] == known_digests["sha1"]

    def test_empty_file(self, empty_file: Path) -> None:
        result = compute_hashes(empty_file, algorithms=("sha256",))
        assert result["sha256"] == hashlib.sha256(b"").hexdigest()

    def test_large_file_chunked_read(self, large_file: Path) -> None:
        """Ensure chunked reading produces the same result as full-file hashing."""
        content = large_file.read_bytes()
        expected = hashlib.sha256(content).hexdigest()
        result = compute_hashes(large_file, algorithms=("sha256",))
        assert result["sha256"] == expected

    def test_small_buffer_size(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        """Verify correctness with a tiny buffer (1 byte)."""
        result = compute_hashes(sample_file, algorithms=("sha256",), buffer_size=1)
        assert result["sha256"] == known_digests["sha256"]

    def test_buffer_8192_matches_legacy(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        """Verify that results match regardless of buffer size (8192 vs 65536)."""
        r1 = compute_hashes(sample_file, buffer_size=8192)
        r2 = compute_hashes(sample_file, buffer_size=65536)
        assert r1 == r2

    def test_invalid_buffer_size_raises(self, sample_file: Path) -> None:
        with pytest.raises(ValueError, match="positive"):
            compute_hashes(sample_file, buffer_size=0)
        with pytest.raises(ValueError, match="positive"):
            compute_hashes(sample_file, buffer_size=-1)

    def test_nonexistent_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            compute_hashes(tmp_path / "no_such_file.txt")

    def test_unknown_algorithm_raises(self, sample_file: Path) -> None:
        with pytest.raises(KeyError, match="Unknown hash algorithm"):
            compute_hashes(sample_file, algorithms=("nonexistent",))

    def test_accepts_list_not_only_tuple(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        """Ensure list[str] works (ManifestBuilder passes config as list)."""
        result = compute_hashes(sample_file, algorithms=["sha256", "sha512"])
        assert result["sha256"] == known_digests["sha256"]
        assert result["sha512"] == known_digests["sha512"]


# ---------------------------------------------------------------------------
# Test: compute_single_hash
# ---------------------------------------------------------------------------

class TestComputeSingleHash:
    """Verify the single-algorithm convenience function."""

    def test_default_sha256(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        assert compute_single_hash(sample_file) == known_digests["sha256"]

    def test_explicit_algorithm(
        self, sample_file: Path, known_digests: dict[str, str]
    ) -> None:
        register_algorithm("md5", hashlib.md5)
        try:
            assert (
                compute_single_hash(sample_file, algorithm="md5")
                == known_digests["md5"]
            )
        finally:
            _ALGORITHM_REGISTRY.pop("md5", None)

    def test_suppress_errors_returns_empty(self, tmp_path: Path) -> None:
        """Matches Investigator._sha256 semantics: return '' on error."""
        result = compute_single_hash(
            tmp_path / "nonexistent", suppress_errors=True
        )
        assert result == ""

    def test_suppress_errors_false_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            compute_single_hash(tmp_path / "nonexistent", suppress_errors=False)

    def test_empty_file(self, empty_file: Path) -> None:
        expected = hashlib.sha256(b"").hexdigest()
        assert compute_single_hash(empty_file) == expected


# ---------------------------------------------------------------------------
# Test: hash_tree
# ---------------------------------------------------------------------------

class TestHashTree:
    """Verify the directory-tree hashing function."""

    def test_hashes_all_files(self, sample_tree: Path) -> None:
        result = hash_tree(sample_tree)
        assert "a.txt" in result
        assert "sub/b.txt" in result
        assert "sub/c.bin" in result
        assert len(result) == 3

    def test_correct_digests(self, sample_tree: Path) -> None:
        result = hash_tree(sample_tree)
        expected = hashlib.sha256(b"file a\n").hexdigest()
        assert result["a.txt"] == expected

    def test_skip_predicate(self, sample_tree: Path) -> None:
        result = hash_tree(
            sample_tree,
            skip_predicate=lambda p: p.endswith(".bin"),
        )
        assert "a.txt" in result
        assert "sub/b.txt" in result
        assert "sub/c.bin" not in result

    def test_posix_paths_on_windows(self, sample_tree: Path) -> None:
        """All keys must use forward slashes, regardless of OS."""
        result = hash_tree(sample_tree)
        for key in result:
            assert "\\" not in key

    def test_empty_directory(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty_dir"
        empty_dir.mkdir()
        result = hash_tree(empty_dir)
        assert result == {}

    def test_custom_algorithm(self, sample_tree: Path) -> None:
        register_algorithm("md5", hashlib.md5)
        try:
            result = hash_tree(sample_tree, algorithm="md5")
            expected = hashlib.md5(b"file a\n").hexdigest()
            assert result["a.txt"] == expected
        finally:
            _ALGORITHM_REGISTRY.pop("md5", None)

    def test_unreadable_file_logged_and_skipped(
        self, sample_tree: Path
    ) -> None:
        """Files that cannot be read are logged and skipped (not raised)."""
        # Make a file unreadable by replacing it with an invalid path
        bad_path = sample_tree / "bad.txt"
        bad_path.write_bytes(b"data")

        def fake_hash(path, *, algorithm="sha256", buffer_size=65536):
            if path.name == "bad.txt":
                raise PermissionError("denied")
            content = path.read_bytes()
            return hashlib.sha256(content).hexdigest()

        with patch("REDACTS.core.hashing.compute_single_hash", side_effect=fake_hash):
            result = hash_tree(sample_tree)
            # bad.txt should be skipped, others present
            assert "bad.txt" not in result
            assert "a.txt" in result


# ---------------------------------------------------------------------------
# Test: Legacy behavior parity
# ---------------------------------------------------------------------------

class TestLegacyParity:
    """Confirm exact output parity with each legacy implementation."""

    def test_parity_with_file_analyzer(self, sample_file: Path) -> None:
        """FileAnalyzer._compute_hashes returns dict with sha256/sha512."""
        # Updated behavior: md5 removed from defaults
        legacy = self._legacy_file_analyzer_hash(sample_file)
        canonical = compute_hashes(sample_file, algorithms=("sha256", "sha512"))
        assert canonical == legacy

    def test_insecure_algorithms_log_warnings(self, sample_file: Path) -> None:
        """Verify that using md5/sha1 logs warnings."""
        with patch("REDACTS.core.hashing.logger.warning") as mock_warn:
            register_algorithm("md5", hashlib.md5)
            register_algorithm("sha1", hashlib.sha1)
            try:
                compute_hashes(sample_file, algorithms=("md5", "sha1"))
                # Should have warned at least twice per algorithm: once on register, once on resolve
                assert mock_warn.call_count >= 4
                args = [call.args[0] for call in mock_warn.call_args_list]
                assert any("Insecure hash algorithm '%s' registered" in msg for msg in args)
                assert any("Use of insecure hash algorithm '%s' detected" in msg for msg in args)
            finally:
                _ALGORITHM_REGISTRY.pop("md5", None)
                _ALGORITHM_REGISTRY.pop("sha1", None)

    def test_parity_with_investigator_sha256(self, sample_file: Path) -> None:
        """Investigator._sha256 returns str, '' on error, buffer 65536."""
        legacy = self._legacy_investigator_sha256(sample_file)
        canonical = compute_single_hash(sample_file, algorithm="sha256")
        assert canonical == legacy

    def test_parity_with_investigator_sha256_error(self, tmp_path: Path) -> None:
        """Investigator._sha256 returns '' on error."""
        legacy = self._legacy_investigator_sha256(tmp_path / "nonexistent")
        canonical = compute_single_hash(
            tmp_path / "nonexistent", suppress_errors=True
        )
        assert canonical == legacy == ""

    def test_parity_with_baseline_validator(self, sample_tree: Path) -> None:
        """BaselineValidator._hash_tree returns {rel_path: sha256}."""
        legacy = self._legacy_hash_tree(sample_tree)
        canonical = hash_tree(sample_tree, algorithm="sha256")
        assert canonical == legacy

    # -- Legacy reimplementations (inline, for comparison only) --

    @staticmethod
    def _legacy_file_analyzer_hash(file_path: Path) -> dict[str, str]:
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                sha512.update(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "sha512": sha512.hexdigest(),
        }

    @staticmethod
    def _legacy_investigator_sha256(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except Exception:
            return ""
        return h.hexdigest()

    @staticmethod
    def _legacy_hash_tree(root: Path) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue
            rel_path = str(file_path.relative_to(root)).replace("\\", "/")
            try:
                h = hashlib.sha256()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                hashes[rel_path] = h.hexdigest()
            except Exception:
                pass
        return hashes


# ---------------------------------------------------------------------------
# Test: Configuration-driven defaults
# ---------------------------------------------------------------------------

class TestConfigurationDefaults:
    """Verify configuration constants match existing config dataclass defaults."""

    def test_default_algorithms_match_config(self) -> None:
        """DEFAULT_ALGORITHMS must match AnalysisConfig.hash_algorithms default."""
        assert set(DEFAULT_ALGORITHMS) == {"sha256", "sha512"}

    def test_default_buffer_size(self) -> None:
        """DEFAULT_BUFFER_SIZE must be 65536 (largest existing buffer)."""
        assert DEFAULT_BUFFER_SIZE == 65536
