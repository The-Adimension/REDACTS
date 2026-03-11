"""
Tests for REDACTS CWE Knowledge Base — knowledge/cwe_database.py

Coverage:
    - CSV loading and parsing
    - Mitigation extraction from MITRE serialized format
    - CWE ID normalization
    - Integrity verification (checksum match / mismatch / missing)
    - Offline guarantee (zero network imports)
    - CweEntry dataclass immutability
    - Integration with InvestigationFinding and UnifiedFinding
"""

from __future__ import annotations

import ast
import hashlib
import textwrap
from pathlib import Path

import pytest

from REDACTS.knowledge.cwe_database import (
    CWE_ATTRIBUTION,
    CWE_CSV_FILENAME,
    CWE_VERSION,
    CweDatabase,
    _extract_first_mitigation,
)


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════

_SAMPLE_CSV = textwrap.dedent("""\
    CWE-ID,Name,Weakness Abstraction,Status,Description,Extended Description,Related Weaknesses,Weakness Ordinalities,Applicable Platforms,Background Details,Alternate Terms,Modes Of Introduction,Exploitation Factors,Likelihood of Exploit,Common Consequences,Detection Methods,Potential Mitigations,Observed Examples,Functional Areas,Affected Resources,Taxonomy Mappings,Related Attack Patterns,Notes
    79,Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'),Base,Stable,The product does not properly handle input.,,,,,,,,,High,,,::PHASE:Implementation:DESCRIPTION:Use context-aware output encoding.::PHASE:Architecture:DESCRIPTION:Use a templating engine.,,,,,
    89,Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'),Base,Stable,The product constructs SQL commands.,,,,,,,,,High,,,::PHASE:Implementation:DESCRIPTION:Use parameterized queries.,,,,,
    9999,Fake Deprecated Entry,Base,Deprecated,Should be skipped.,,,,,,,,,,,,,,,,,
""")


@pytest.fixture
def cwe_data_dir(tmp_path: Path) -> Path:
    """Create a temp directory with sample CWE CSV and valid checksum."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()

    csv_path = data_dir / CWE_CSV_FILENAME
    csv_path.write_text(_SAMPLE_CSV, encoding="utf-8")

    # Compute real SHA-256 of what we wrote
    h = hashlib.sha256()
    with open(csv_path, "rb") as f:
        h.update(f.read())
    sha = h.hexdigest()

    checksum_path = data_dir / f"{CWE_CSV_FILENAME}.sha256"
    checksum_path.write_text(f"{sha}  {CWE_CSV_FILENAME}\n", encoding="utf-8")

    return data_dir


@pytest.fixture
def cwe_db(cwe_data_dir: Path) -> CweDatabase:
    """CweDatabase backed by the sample CSV."""
    return CweDatabase(data_dir=cwe_data_dir)


# ═══════════════════════════════════════════════════════════════════════════
# CSV loading
# ═══════════════════════════════════════════════════════════════════════════


class TestCsvLoading:
    """Verify CSV parsing and entry creation."""

    def test_loads_non_deprecated_entries(self, cwe_db: CweDatabase) -> None:
        assert len(cwe_db) == 2  # 79 and 89 only, 9999 is Deprecated

    def test_entry_fields(self, cwe_db: CweDatabase) -> None:
        entry = cwe_db.get("CWE-79")
        assert entry is not None
        assert entry.cwe_id == "CWE-79"
        assert "Cross-site Scripting" in entry.name
        assert entry.likelihood == "High"

    def test_deprecated_skipped(self, cwe_db: CweDatabase) -> None:
        assert not cwe_db.contains("CWE-9999")

    def test_entry_is_frozen(self, cwe_db: CweDatabase) -> None:
        entry = cwe_db.get("CWE-89")
        assert entry is not None
        with pytest.raises(AttributeError):
            entry.name = "tampered"  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════
# Mitigation parsing
# ═══════════════════════════════════════════════════════════════════════════


class TestMitigationParsing:
    """Verify extraction from MITRE's serialized format."""

    def test_extracts_first_description(self) -> None:
        raw = "::PHASE:Impl:DESCRIPTION:Use parameterized queries.::PHASE:Design:DESCRIPTION:Use ORM."
        result = _extract_first_mitigation(raw)
        assert result == "Use parameterized queries."

    def test_empty_input(self) -> None:
        assert _extract_first_mitigation("") == ""

    def test_no_description_marker(self) -> None:
        assert _extract_first_mitigation("::PHASE:Impl::") == ""

    def test_mitigation_from_loaded_entry(self, cwe_db: CweDatabase) -> None:
        entry = cwe_db.get("CWE-79")
        assert entry is not None
        assert "context-aware" in entry.mitigation.lower()


# ═══════════════════════════════════════════════════════════════════════════
# ID normalization
# ═══════════════════════════════════════════════════════════════════════════


class TestIdNormalization:
    """Verify CWE ID normalization to canonical 'CWE-NNN' form."""

    def test_canonical_form(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.get("CWE-89") is not None

    def test_bare_number(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.get("89") is not None

    def test_lowercase(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.get("cwe-89") is not None

    def test_unknown_id(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.get("CWE-000000") is None

    def test_empty_string(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.get("") is None


# ═══════════════════════════════════════════════════════════════════════════
# Lookup helpers
# ═══════════════════════════════════════════════════════════════════════════


class TestLookups:
    def test_get_name(self, cwe_db: CweDatabase) -> None:
        name = cwe_db.get_name("CWE-89")
        assert "SQL Injection" in name

    def test_get_name_unknown(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.get_name("CWE-000000") == ""

    def test_get_recommendation(self, cwe_db: CweDatabase) -> None:
        rec = cwe_db.get_recommendation("CWE-89")
        assert "parameterized" in rec.lower()

    def test_contains(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.contains("CWE-79")
        assert not cwe_db.contains("CWE-000000")

    def test_enrich_name_known(self, cwe_db: CweDatabase) -> None:
        display = cwe_db.enrich_name("CWE-89")
        assert display.startswith("CWE-89:")
        assert "SQL" in display

    def test_enrich_name_unknown(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.enrich_name("CWE-000000") == "CWE-000000"


# ═══════════════════════════════════════════════════════════════════════════
# Integrity verification
# ═══════════════════════════════════════════════════════════════════════════


class TestIntegrity:
    """Verify SHA-256 integrity reporting."""

    def test_verified_status(self, cwe_db: CweDatabase) -> None:
        report = cwe_db.integrity_report
        assert report.status == "VERIFIED"
        assert report.match is True
        assert report.csv_exists is True
        assert report.checksum_exists is True
        assert report.cwe_entry_count == 2

    def test_verify_integrity_method(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.verify_integrity() is True

    def test_mismatch_raises_valueerror(self, tmp_path: Path) -> None:
        """Tampered checksum must raise ValueError, NOT log a warning."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        csv_path = data_dir / CWE_CSV_FILENAME
        csv_path.write_text(_SAMPLE_CSV, encoding="utf-8")

        checksum_path = data_dir / f"{CWE_CSV_FILENAME}.sha256"
        checksum_path.write_text(f"{'0' * 64}  {CWE_CSV_FILENAME}\n", encoding="utf-8")

        with pytest.raises(ValueError, match="integrity check FAILED"):
            CweDatabase(data_dir=data_dir)

    def test_missing_csv_warns(self, tmp_path: Path) -> None:
        """Missing CSV should NOT raise — just log warning and be empty."""
        data_dir = tmp_path / "empty"
        data_dir.mkdir()
        db = CweDatabase(data_dir=data_dir)
        assert len(db) == 0
        assert db.integrity_report.status == "MISSING_CSV"

    def test_missing_checksum_warns(self, tmp_path: Path) -> None:
        """Missing checksum file — loads data but status is UNVERIFIED."""
        data_dir = tmp_path / "data"
        data_dir.mkdir()

        csv_path = data_dir / CWE_CSV_FILENAME
        csv_path.write_text(_SAMPLE_CSV, encoding="utf-8")

        db = CweDatabase(data_dir=data_dir)
        assert len(db) == 2  # Data still loaded
        assert db.integrity_report.status == "MISSING_CHECKSUM"

    def test_integrity_report_fields(self, cwe_db: CweDatabase) -> None:
        """Every field in IntegrityReport must be populated."""
        report = cwe_db.integrity_report
        assert report.csv_path  # non-empty string
        assert report.checksum_path
        assert report.expected_sha256
        assert report.actual_sha256
        assert report.load_timestamp  # ISO 8601


# ═══════════════════════════════════════════════════════════════════════════
# Offline guarantee
# ═══════════════════════════════════════════════════════════════════════════


class TestOfflineGuarantee:
    """Verify that cwe_database.py contains zero network imports.

    PINNED FOUNDATION: this module must operate in an air-gapped
    environment.  We parse the AST to ensure no network modules
    are imported.
    """

    _FORBIDDEN_MODULES = {
        "urllib",
        "urllib.request",
        "urllib.parse",
        "http",
        "http.client",
        "http.server",
        "requests",
        "httpx",
        "aiohttp",
        "socket",
        "ssl",
        "ftplib",
        "smtplib",
        "xmlrpc",
        "paramiko",
    }

    def test_no_network_imports(self) -> None:
        source_path = (
            Path(__file__).resolve().parent.parent / "knowledge" / "cwe_database.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))

        imported_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported_modules.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                    imported_modules.add(node.module.split(".")[0])

        violations = imported_modules & self._FORBIDDEN_MODULES
        assert not violations, (
            f"cwe_database.py imports network modules: {violations}. "
            f"This violates the offline-only guarantee."
        )


# ═══════════════════════════════════════════════════════════════════════════
# Metadata
# ═══════════════════════════════════════════════════════════════════════════


class TestMetadata:
    def test_version(self, cwe_db: CweDatabase) -> None:
        assert cwe_db.version == CWE_VERSION

    def test_attribution(self, cwe_db: CweDatabase) -> None:
        assert "MITRE" in cwe_db.attribution

    def test_repr(self, cwe_db: CweDatabase) -> None:
        r = repr(cwe_db)
        assert "CweDatabase" in r
        assert "VERIFIED" in r

    def test_attribution_constant(self) -> None:
        assert "MITRE" in CWE_ATTRIBUTION
        assert "Terms of Use" in CWE_ATTRIBUTION


# ═══════════════════════════════════════════════════════════════════════════
# Backward compatibility
# ═══════════════════════════════════════════════════════════════════════════


class TestBackwardCompatibility:
    """Ensure existing code is not broken by the new fields."""

    def test_investigation_finding_new_fields(self) -> None:
        """InvestigationFinding must accept cwe_id and cwe_name."""
        from REDACTS.investigation.step_protocol import InvestigationFinding

        f = InvestigationFinding(
            id="INV-001",
            source="security_scan",
            severity="HIGH",
            title="Test",
            description="Test finding",
            file_path="test.php",
            line=1,
            conclusiveness="suspicious",
            category="injection",
            recommendation="Fix it",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
        )
        assert f.cwe_id == "CWE-89"
        assert f.cwe_name == "SQL Injection"
        d = f.to_dict()
        assert d["cwe_id"] == "CWE-89"
        assert d["cwe_name"] == "SQL Injection"

    def test_investigation_finding_defaults(self) -> None:
        """Existing code that doesn't set cwe_id/cwe_name must still work."""
        from REDACTS.investigation.step_protocol import InvestigationFinding

        f = InvestigationFinding(
            id="INV-002",
            source="ioc_scan",
            severity="LOW",
            title="Test",
            description="Compat test",
            file_path="test.php",
            line=0,
            conclusiveness="informational",
            category="test",
            recommendation="",
        )
        assert f.cwe_id == ""
        assert f.cwe_name == ""

    def test_unified_finding_cwe_name_in_sarif(self) -> None:
        """UnifiedFinding.to_sarif_result() must include cwe_name in taxa."""
        from REDACTS.core.models import (
            Confidence,
            FindingSource,
            SeverityLevel,
            UnifiedFinding,
        )

        f = UnifiedFinding(
            id="test-001",
            rule_id="SEC001",
            title="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            confidence=Confidence.HIGH,
            source=FindingSource.SEMGREP,
            category="injection",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
        )
        sarif = f.to_sarif_result()
        taxa = sarif.get("taxa", [])
        assert len(taxa) == 1
        assert taxa[0]["id"] == "89"
        assert taxa[0]["name"] == "SQL Injection"

    def test_unified_finding_cwe_name_omitted_when_empty(self) -> None:
        """When cwe_name is empty, taxa should not include 'name' key."""
        from REDACTS.core.models import (
            Confidence,
            FindingSource,
            SeverityLevel,
            UnifiedFinding,
        )

        f = UnifiedFinding(
            id="test-002",
            rule_id="SEC001",
            title="Test",
            description="Test",
            severity=SeverityLevel.HIGH,
            confidence=Confidence.HIGH,
            source=FindingSource.SEMGREP,
            category="injection",
            cwe_id="CWE-89",
            cwe_name="",
        )
        sarif = f.to_sarif_result()
        taxa = sarif.get("taxa", [])
        assert len(taxa) == 1
        assert "name" not in taxa[0]


# ═══════════════════════════════════════════════════════════════════════════
# Bundled data smoke test
# ═══════════════════════════════════════════════════════════════════════════


class TestBundledData:
    """Smoke-test the actual bundled MITRE CSV (if present)."""

    @pytest.fixture
    def bundled_db(self) -> CweDatabase:
        """Load the real bundled database.  Skip if not available."""
        real_data_dir = Path(__file__).resolve().parent.parent / "knowledge" / "data"
        csv_path = real_data_dir / CWE_CSV_FILENAME
        if not csv_path.is_file():
            pytest.skip("Bundled CWE CSV not available")
        return CweDatabase(data_dir=real_data_dir)

    def test_has_many_entries(self, bundled_db: CweDatabase) -> None:
        assert len(bundled_db) > 900

    def test_well_known_cwes(self, bundled_db: CweDatabase) -> None:
        assert bundled_db.contains("CWE-79")  # XSS
        assert bundled_db.contains("CWE-89")  # SQL Injection
        assert bundled_db.contains("CWE-78")  # OS Command Injection
        assert bundled_db.contains("CWE-22")  # Path Traversal
        assert bundled_db.contains("CWE-502")  # Deserialization

    def test_integrity_verified(self, bundled_db: CweDatabase) -> None:
        assert bundled_db.integrity_report.status == "VERIFIED"

    def test_sql_injection_has_mitigation(self, bundled_db: CweDatabase) -> None:
        rec = bundled_db.get_recommendation("CWE-89")
        assert rec  # Must not be empty
