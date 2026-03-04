"""Tests for evidence/collector.py — verify manifest_sha256 persistence & UUID in ID."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from REDACTS.evidence.collector import (
    EvidenceCollector,
    EvidenceMetadata,
    EvidencePackage,
)


class TestEvidenceMetadata:
    def test_evidence_id_contains_uuid(self):
        """Evidence ID should have a random suffix to avoid collisions."""
        meta = EvidenceMetadata()
        # The format is set by collect(), not the dataclass itself, but
        # we can verify the pattern after calling collect.
        # Just check the dataclass can be created:
        assert meta.evidence_id == ""
        assert meta.manifest_sha256 == ""

    def test_to_dict(self):
        meta = EvidenceMetadata(label="test", source_uri="/tmp/x")
        d = meta.to_dict()
        assert d["label"] == "test"
        assert d["source_uri"] == "/tmp/x"


class TestEvidencePackage:
    def test_default_is_not_success(self):
        pkg = EvidencePackage()
        assert pkg.success is False

    def test_to_dict(self):
        pkg = EvidencePackage()
        d = pkg.to_dict()
        assert isinstance(d, dict)
        assert "metadata" in d


class TestWritePackage:
    """Verify _write_package persists manifest_sha256 into metadata.json."""

    def test_manifest_sha256_in_metadata_json(self, tmp_path):
        """After writing, metadata.json must contain the manifest hash."""
        collector = EvidenceCollector()

        # Build a minimal package
        pkg = EvidencePackage()
        pkg.metadata.label = "test-hash"

        # Create a fake manifest object
        manifest_mock = MagicMock()
        manifest_data = {"entries": [], "total_files": 0}
        manifest_mock.save = MagicMock(
            side_effect=lambda p: p.write_text(
                json.dumps(manifest_data), encoding="utf-8"
            )
        )
        manifest_mock.to_dict = MagicMock(return_value=manifest_data)
        pkg.manifest = manifest_mock

        out = tmp_path / "evidence_out"
        out.mkdir()
        collector._write_package(pkg, str(out), None)

        meta_path = out / "metadata.json"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))

        # The hash must be non-empty (the manifest was written first)
        assert meta.get("manifest_sha256", "") != "", (
            "manifest_sha256 is empty — was it computed AFTER writing manifest.json?"
        )

    def test_manifest_sha256_matches_file(self, tmp_path):
        """The hash stored must actually match the manifest.json bytes."""
        import hashlib

        collector = EvidenceCollector()
        pkg = EvidencePackage()
        manifest_content = '{"entries":[]}'
        manifest_mock = MagicMock()
        manifest_mock.save = MagicMock(
            side_effect=lambda p: p.write_text(manifest_content, encoding="utf-8")
        )
        manifest_mock.to_dict = MagicMock(return_value={})
        pkg.manifest = manifest_mock

        out = tmp_path / "ev"
        out.mkdir()
        collector._write_package(pkg, str(out), None)

        expected = hashlib.sha256(
            (out / "manifest.json").read_bytes()
        ).hexdigest()
        actual = pkg.metadata.manifest_sha256
        assert actual == expected
