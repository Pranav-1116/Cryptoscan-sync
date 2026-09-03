"""
Integration tests for evidence_loader.py.

Tests the full loading pipeline including pre-load verification,
bulk insertion, post-load verification, and audit logging.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from db.loader.evidence_loader import EvidenceLoader
from db.models.base import Base


def _make_finding(
    algorithm: str = "AES",
    file_path: str = "src/Crypto.java",
    line_number: int = 42,
) -> dict:
    """Create a minimal valid finding dict."""
    return {
        "finding_id": str(uuid.uuid4()),
        "scanner_id": "test-scanner-v0.1",
        "scanner_version": "0.1.0",
        "source": {
            "type": "SOURCE_CODE",
            "language": "JAVA",
            "file_path": file_path,
            "line_number": line_number,
            "class_name": "com.example.CryptoService",
            "method_name": "encrypt",
        },
        "crypto": {
            "algorithm": algorithm,
            "mode": "GCM",
            "key_size": 256,
            "purpose": "ENCRYPTION",
        },
        "metadata": {
            "confidence": "HIGH",
            "is_hardcoded_key": False,
        },
    }


def _compute_content_hash(finding: dict) -> str:
    canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_chain_hash(content_hash: str, previous: str) -> str:
    return hashlib.sha256((content_hash + previous).encode("utf-8")).hexdigest()


def _build_evidence_records(
    findings: list[dict],
    scan_session_id: str,
) -> list[dict]:
    """Build properly chained evidence records from findings."""
    records = []
    previous_hash = None

    for i, finding in enumerate(findings):
        content_hash = _compute_content_hash(finding)

        if i == 0:
            chain_hash = _compute_chain_hash(content_hash, scan_session_id)
        else:
            chain_hash = _compute_chain_hash(content_hash, previous_hash)

        records.append({
            "evidence_id": str(uuid.uuid4()),
            "content_hash": content_hash,
            "finding": finding,
            "chain": {
                "position": i,
                "chain_hash": chain_hash,
                "previous_hash": previous_hash,
            },
            "provenance": {
                "scanner_id": "test-scanner-v0.1",
                "scanner_version": "0.1.0",
            },
        })

        previous_hash = chain_hash

    return records


@pytest.fixture
def db_session(tmp_path):
    """Create an in-memory SQLite DB for testing (structural only)."""
    # Note: For full integration tests, use a real PostgreSQL test DB
    # This uses SQLite for unit-level integration testing
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    # Import all models to ensure they're registered
    from db.models import base, scan, evidence_record, verification_log  # noqa
    Base.metadata.create_all(engine)

    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = factory()
    yield session
    session.close()
    Base.metadata.drop_all(engine)


@pytest.fixture
def valid_scan_data() -> dict:
    """Valid scan metadata dict."""
    return {
        "scan_id": str(uuid.uuid4()),
        "scan_start": datetime.now(timezone.utc).isoformat(),
        "scan_end": datetime.now(timezone.utc).isoformat(),
        "scanner_id": "static-java-scanner-v0.1",
        "scanner_version": "0.1.0",
        "target_type": "GIT_REPOSITORY",
        "target_location": "https://github.com/test/repo",
        "target_commit": "a" * 40,
        "target_branch": "main",
        "operator": "test-user",
        "statistics": {"files_scanned": 10, "total_findings": 3},
        "status": "COMPLETED",
    }


class TestEvidenceLoaderHappyPath:
    """Tests for successful evidence loading."""

    def test_load_valid_evidence_succeeds(self, db_session, valid_scan_data):
        """Loading valid, properly-chained evidence should succeed."""
        scan_id = valid_scan_data["scan_id"]
        scan_session_id = str(uuid.uuid4())

        findings = [
            _make_finding("AES", "src/Auth.java", 10),
            _make_finding("SHA-256", "src/Hash.java", 20),
            _make_finding("RSA", "src/Sign.java", 30),
        ]
        evidence_records = _build_evidence_records(findings, scan_session_id)

        loader = EvidenceLoader(db_session)
        result = loader.load_from_data(
            scan_id=scan_id,
            scan_data=valid_scan_data,
            evidence_records=evidence_records,
            scan_session_id=scan_session_id,
            operator="test-user",
        )

        assert result.success is True
        assert result.records_loaded == 3
        assert result.error is None
        assert result.pre_verification is not None
        assert result.pre_verification.passed is True
        assert result.post_verification is not None
        assert result.post_verification.passed is True

    def test_load_empty_evidence_succeeds(self, db_session, valid_scan_data):
        """Loading a scan with no findings should succeed."""
        loader = EvidenceLoader(db_session)
        result = loader.load_from_data(
            scan_id=valid_scan_data["scan_id"],
            scan_data=valid_scan_data,
            evidence_records=[],
            operator="test-user",
        )

        assert result.success is True
        assert result.records_loaded == 0

    def test_load_creates_verification_log(self, db_session, valid_scan_data):
        """Successful load should create a PASS verification log record."""
        scan_id = valid_scan_data["scan_id"]
        scan_session_id = str(uuid.uuid4())

        findings = [_make_finding()]
        evidence_records = _build_evidence_records(findings, scan_session_id)

        loader = EvidenceLoader(db_session)
        loader.load_from_data(
            scan_id=scan_id,
            scan_data=valid_scan_data,
            evidence_records=evidence_records,
            scan_session_id=scan_session_id,
        )

        # Verify audit log was created
        from db.repositories.verification_repository import VerificationRepository
        repo = VerificationRepository(db_session)
        log = repo.get_latest_for_scan(uuid.UUID(scan_id))

        assert log is not None
        assert log.result == "PASS"
        assert log.chain_valid is True
        assert log.content_hashes_valid is True


class TestEvidenceLoaderTamperDetection:
    """Tests that verify tamper detection works correctly."""

    def test_tampered_content_hash_aborts_load(self, db_session, valid_scan_data):
        """Modifying a finding's content should fail content hash check."""
        scan_id = valid_scan_data["scan_id"]
        scan_session_id = str(uuid.uuid4())

        findings = [_make_finding("DES")]
        evidence_records = _build_evidence_records(findings, scan_session_id)

        # Tamper: modify the finding content but not the hash
        evidence_records[0]["finding"]["crypto"]["algorithm"] = "AES"
        # content_hash is now wrong (computed for DES but finding says AES)

        loader = EvidenceLoader(db_session)
        result = loader.load_from_data(
            scan_id=scan_id,
            scan_data=valid_scan_data,
            evidence_records=evidence_records,
            scan_session_id=scan_session_id,
        )

        assert result.success is False
        assert "Pre-load integrity verification failed" in result.error
        assert result.pre_verification is not None
        assert not result.pre_verification.passed
        assert len(result.pre_verification.content_hash_errors) > 0

    def test_broken_chain_aborts_load(self, db_session, valid_scan_data):
        """Broken chain hash linkage should abort the load."""
        scan_id = valid_scan_data["scan_id"]
        scan_session_id = str(uuid.uuid4())

        findings = [_make_finding("AES"), _make_finding("RSA")]
        evidence_records = _build_evidence_records(findings, scan_session_id)

        # Tamper: corrupt the chain hash of record 1
        evidence_records[1]["chain"]["chain_hash"] = "a" * 64

        loader = EvidenceLoader(db_session)
        result = loader.load_from_data(
            scan_id=scan_id,
            scan_data=valid_scan_data,
            evidence_records=evidence_records,
            scan_session_id=scan_session_id,
        )

        assert result.success is False
        assert result.pre_verification is not None
        assert not result.pre_verification.passed
        assert len(result.pre_verification.chain_hash_errors) > 0

    def test_missing_required_fields_aborts_load(self, db_session, valid_scan_data):
        """Evidence records missing required fields should abort the load."""
        invalid_records = [
            {"evidence_id": str(uuid.uuid4())},  # Missing content_hash, finding, chain
        ]

        loader = EvidenceLoader(db_session)
        result = loader.load_from_data(
            scan_id=valid_scan_data["scan_id"],
            scan_data=valid_scan_data,
            evidence_records=invalid_records,
        )

        assert result.success is False
        assert result.pre_verification.structural_errors


class TestEvidenceLoaderTransactionSafety:
    """Tests for transaction atomicity."""

    def test_failed_insertion_rollbacks_completely(self, db_session, valid_scan_data):
        """If insertion fails midway, no partial data should remain."""
        scan_id = valid_scan_data["scan_id"]
        scan_session_id = str(uuid.uuid4())

        findings = [_make_finding("AES")]
        evidence_records = _build_evidence_records(findings, scan_session_id)

        loader = EvidenceLoader(db_session)

        # Simulate insertion failure
        with patch.object(loader.bulk_inserter, "insert_scan_with_evidence") as mock_insert:
            mock_insert.side_effect = RuntimeError("Simulated DB failure")

            result = loader.load_from_data(
                scan_id=scan_id,
                scan_data=valid_scan_data,
                evidence_records=evidence_records,
                scan_session_id=scan_session_id,
            )

        assert result.success is False
        assert "Database insertion failed" in result.error

        # Verify nothing was committed (id column is String(36))
        from db.repositories.scan_repository import ScanRepository
        repo = ScanRepository(db_session)
        scan = repo.get_by_id(str(scan_id))
        assert scan is None