"""
Tests for evidence chain verification from the database.

Verifies that the blockchain-style chain hash linkage is maintained
correctly after insertion and can detect tampering. Uses ORM objects so the
suite is portable across SQLite (test) and PostgreSQL (production).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from db.loader.post_load_verifier import PostLoadVerifier
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _content_hash(finding: dict) -> str:
    canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"))
    return _sha256(canonical)


def _build_chain(n_records: int, scan_session_id: str) -> list[dict]:
    """Build a properly-chained set of evidence records."""
    records = []
    prev_hash = None

    for i in range(n_records):
        finding = {"algo": f"ALGO_{i}", "line": i * 10}
        c_hash = _content_hash(finding)

        if i == 0:
            ch_hash = _sha256(c_hash + scan_session_id)
        else:
            ch_hash = _sha256(c_hash + prev_hash)

        records.append(
            {
                "evidence_id": str(uuid.uuid4()),
                "content_hash": c_hash,
                "chain_position": i,
                "chain_hash": ch_hash,
                "previous_hash": prev_hash,
                "algorithm": "AES",
                "key_size": 256,
                "purpose": "ENCRYPTION",
                "confidence": "HIGH",
                "file_path": f"File{i}.java",
                "line_number": i * 10,
                "is_hardcoded_key": False,
                "finding_data": finding,
                "provenance": {},
            }
        )
        prev_hash = ch_hash

    return records


def _insert_scan_and_records(db_session, n_records: int, scan_session_id: str):
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        scan_start=datetime.now(timezone.utc),
        scanner_id="test",
        scanner_version="0.1",
        target_type="GIT_REPOSITORY",
        target_location="http://test",
        operator="test",
        status="COMPLETED",
    )
    db_session.add(scan)
    db_session.flush()

    records = _build_chain(n_records, scan_session_id)
    for rec in records:
        db_session.add(
            EvidenceRecord(
                id=rec["evidence_id"],
                scan_id=scan_id,
                content_hash=rec["content_hash"],
                chain_position=rec["chain_position"],
                chain_hash=rec["chain_hash"],
                previous_hash=rec["previous_hash"],
                algorithm=rec["algorithm"],
                confidence=rec["confidence"],
                is_hardcoded_key=rec["is_hardcoded_key"],
                file_path=rec["file_path"],
                line_number=rec["line_number"],
                finding_data=rec["finding_data"],
                provenance=rec["provenance"],
            )
        )
    db_session.commit()
    return scan_id, records


class TestChainVerificationFromDB:
    """Tests for post-load chain verification."""

    def test_valid_chain_passes_verification(self, db_session):
        """A properly-chained set of records should verify successfully."""
        session_id = str(uuid.uuid4())
        scan_id, _ = _insert_scan_and_records(db_session, 5, session_id)

        result = PostLoadVerifier(db_session).verify(
            scan_id=scan_id, expected_count=5, scan_session_id=session_id
        )

        assert result.passed is True
        assert result.records_checked == 5
        assert result.chain_errors == []
        assert not result.count_mismatch

    def test_tampered_chain_hash_fails_verification(self, db_session):
        """Manually modifying a chain_hash in the DB should fail verification."""
        session_id = str(uuid.uuid4())
        scan_id, records = _insert_scan_and_records(db_session, 3, session_id)

        # TAMPER: modify chain_hash of record at position 1
        tampered_id = records[1]["evidence_id"]
        row = db_session.get(EvidenceRecord, tampered_id)
        row.chain_hash = "f" * 64
        db_session.commit()

        result = PostLoadVerifier(db_session).verify(
            scan_id=scan_id, expected_count=3, scan_session_id=session_id
        )

        assert result.passed is False
        assert len(result.chain_errors) > 0
        assert any(str(tampered_id) in str(e) for e in result.chain_errors)

    def test_count_mismatch_fails_verification(self, db_session):
        """Expecting more records than in DB should fail verification."""
        session_id = str(uuid.uuid4())
        scan_id, _ = _insert_scan_and_records(db_session, 2, session_id)

        result = PostLoadVerifier(db_session).verify(
            scan_id=scan_id,
            expected_count=5,  # Wrong — only 2 in DB
            scan_session_id=session_id,
        )

        assert result.count_mismatch is True
        assert result.actual_count == 2
        assert result.expected_count == 5
        assert result.passed is False
