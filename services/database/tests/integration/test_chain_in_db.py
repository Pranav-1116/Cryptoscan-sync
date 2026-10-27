"""
Tests for evidence chain verification from the database.

Verifies that the blockchain-style chain hash linkage is maintained
correctly after insertion and can detect tampering.
"""
from __future__ import annotations

import hashlib
import json
import uuid

from sqlalchemy import text

from db.loader.post_load_verifier import PostLoadVerifier


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

        records.append({
            "evidence_id": uuid.uuid4(),
            "scan_id": None,  # Will be set during insert
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
        })
        prev_hash = ch_hash

    return records


class TestChainVerificationFromDB:
    """Tests for post-load chain verification."""

    def test_valid_chain_passes_verification(self, db_session):
        """A properly-chained set of records should verify successfully."""
        scan_id = uuid.uuid4()
        session_id = str(uuid.uuid4())

        # Insert scan
        db_session.execute(
            text("""
                INSERT INTO scans (scan_id, scan_start, scanner_id, scanner_version,
                    target_type, target_location, operator, status)
                VALUES (:sid, NOW(), 'test', '0.1', 'GIT_REPOSITORY', 'http://test', 'test', 'COMPLETED')
            """),
            {"sid": scan_id},
        )

        records = _build_chain(5, session_id)
        for rec in records:
            rec["scan_id"] = scan_id
            db_session.execute(
                text("""
                    INSERT INTO evidence_records
                        (evidence_id, scan_id, content_hash, chain_position, chain_hash,
                         previous_hash, algorithm, confidence, is_hardcoded_key,
                         finding_data, provenance)
                    VALUES
                        (:eid, :sid, :ch, :pos, :chash, :prev, :algo, :conf, :hk,
                         :fd::jsonb, :prov::jsonb)
                """),
                {
                    "eid": rec["evidence_id"],
                    "sid": scan_id,
                    "ch": rec["content_hash"],
                    "pos": rec["chain_position"],
                    "chash": rec["chain_hash"],
                    "prev": rec["previous_hash"],
                    "algo": "AES",
                    "conf": "HIGH",
                    "hk": False,
                    "fd": json.dumps(rec["finding_data"]),
                    "prov": "{}",
                },
            )
        db_session.commit()

        verifier = PostLoadVerifier(db_session)
        result = verifier.verify(
            scan_id=scan_id,
            expected_count=5,
            scan_session_id=session_id,
        )

        assert result.passed is True
        assert result.records_checked == 5
        assert result.chain_errors == []
        assert not result.count_mismatch

    def test_tampered_chain_hash_fails_verification(self, db_session):
        """Manually modifying a chain_hash in the DB should fail verification."""
        scan_id = uuid.uuid4()
        session_id = str(uuid.uuid4())

        # Insert scan
        db_session.execute(
            text("""
                INSERT INTO scans (scan_id, scan_start, scanner_id, scanner_version,
                    target_type, target_location, operator, status)
                VALUES (:sid, NOW(), 'test', '0.1', 'GIT_REPOSITORY', 'http://test', 'test', 'COMPLETED')
            """),
            {"sid": scan_id},
        )

        records = _build_chain(3, session_id)
        for rec in records:
            rec["scan_id"] = scan_id
            db_session.execute(
                text("""
                    INSERT INTO evidence_records
                        (evidence_id, scan_id, content_hash, chain_position, chain_hash,
                         previous_hash, algorithm, confidence, is_hardcoded_key,
                         finding_data, provenance)
                    VALUES
                        (:eid, :sid, :ch, :pos, :chash, :prev, :algo, :conf, :hk,
                         :fd::jsonb, :prov::jsonb)
                """),
                {
                    "eid": rec["evidence_id"],
                    "sid": scan_id,
                    "ch": rec["content_hash"],
                    "pos": rec["chain_position"],
                    "chash": rec["chain_hash"],
                    "prev": rec["previous_hash"],
                    "algo": "AES",
                    "conf": "HIGH",
                    "hk": False,
                    "fd": json.dumps(rec["finding_data"]),
                    "prov": "{}",
                },
            )

        # TAMPER: modify chain_hash of record at position 1
        tampered_id = records[1]["evidence_id"]
        db_session.execute(
            text(
                "UPDATE evidence_records SET chain_hash = :fake WHERE evidence_id = :eid"
            ),
            {"fake": "f" * 64, "eid": tampered_id},
        )
        db_session.commit()

        verifier = PostLoadVerifier(db_session)
        result = verifier.verify(
            scan_id=scan_id,
            expected_count=3,
            scan_session_id=session_id,
        )

        assert result.passed is False
        assert len(result.chain_errors) > 0
        assert any(str(tampered_id) in str(e) for e in result.chain_errors)

    def test_count_mismatch_fails_verification(self, db_session):
        """Expecting more records than in DB should fail verification."""
        scan_id = uuid.uuid4()
        session_id = str(uuid.uuid4())

        db_session.execute(
            text("""
                INSERT INTO scans (scan_id, scan_start, scanner_id, scanner_version,
                    target_type, target_location, operator, status)
                VALUES (:sid, NOW(), 'test', '0.1', 'GIT_REPOSITORY', 'http://test', 'test', 'COMPLETED')
            """),
            {"sid": scan_id},
        )

        records = _build_chain(2, session_id)
        for rec in records:
            db_session.execute(
                text("""
                    INSERT INTO evidence_records
                        (evidence_id, scan_id, content_hash, chain_position, chain_hash,
                         previous_hash, algorithm, confidence, is_hardcoded_key,
                         finding_data, provenance)
                    VALUES
                        (:eid, :sid, :ch, :pos, :chash, :prev, 'AES', 'HIGH', false,
                         :fd::jsonb, '{}'::jsonb)
                """),
                {
                    "eid": rec["evidence_id"],
                    "sid": scan_id,
                    "ch": rec["content_hash"],
                    "pos": rec["chain_position"],
                    "chash": rec["chain_hash"],
                    "prev": rec["previous_hash"],
                    "fd": json.dumps(rec["finding_data"]),
                },
            )
        db_session.commit()

        verifier = PostLoadVerifier(db_session)
        result = verifier.verify(
            scan_id=scan_id,
            expected_count=5,  # Wrong — only 2 in DB
            scan_session_id=session_id,
        )

        assert result.count_mismatch is True
        assert result.actual_count == 2
        assert result.expected_count == 5
        assert result.passed is False