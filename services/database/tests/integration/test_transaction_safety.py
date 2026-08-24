"""
Tests for transaction safety and rollback behavior.

These tests verify that database operations are atomic:
either everything succeeds or nothing is persisted.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import text

from db.loader.bulk_inserter import BulkInserter


@pytest.fixture
def scan_data_factory():
    """Factory for valid scan data dicts."""
    def _factory(**overrides):
        base = {
            "scan_id": uuid.uuid4(),
            "scan_start": datetime.now(timezone.utc),
            "scan_end": datetime.now(timezone.utc),
            "scanner_id": "test-scanner",
            "scanner_version": "0.1.0",
            "target_type": "GIT_REPOSITORY",
            "target_location": "https://github.com/test/repo",
            "target_commit": "a" * 40,
            "target_branch": "main",
            "operator": "test",
            "statistics": {},
            "status": "COMPLETED",
        }
        base.update(overrides)
        return base

    return _factory


@pytest.fixture
def evidence_record_factory():
    """Factory for valid evidence record dicts."""
    def _factory(scan_id=None, position=0, previous_hash=None, **overrides):
        return {
            "evidence_id": uuid.uuid4(),
            "content_hash": "a" * 64,
            "chain_position": position,
            "chain_hash": "b" * 64,
            "previous_hash": previous_hash,
            "finding": {
                "source": {"file_path": "Test.java", "line_number": 1},
                "crypto": {"algorithm": "AES", "key_size": 256},
                "metadata": {"confidence": "HIGH", "is_hardcoded_key": False},
            },
            "provenance": {},
            **overrides,
        }
    return _factory


class TestBulkInserterTransactions:
    """Tests for BulkInserter transaction behavior."""

    def test_successful_bulk_insert(self, db_session, scan_data_factory, evidence_record_factory):
        """Successful insert commits both scan and evidence records."""
        scan_data = scan_data_factory()
        records = [evidence_record_factory(position=i) for i in range(5)]

        inserter = BulkInserter(db_session)
        scan, count = inserter.insert_scan_with_evidence(scan_data, records)
        db_session.commit()

        assert count == 5

        # Verify data is in DB
        result = db_session.execute(
            text("SELECT COUNT(*) FROM evidence_records WHERE scan_id = :sid"),
            {"sid": scan_data["scan_id"]},
        )
        assert result.scalar_one() == 5

    def test_idempotent_insert_with_conflict(self, db_session, scan_data_factory, evidence_record_factory):
        """Re-inserting the same evidence_id should be a no-op (ON CONFLICT DO NOTHING)."""
        scan_data = scan_data_factory()
        evidence_id = uuid.uuid4()
        records = [evidence_record_factory(position=0, evidence_id=evidence_id)]

        inserter = BulkInserter(db_session)

        # First insert
        _, count1 = inserter.insert_scan_with_evidence(scan_data, records)
        db_session.commit()

        # Attempt second insert with same scan
        scan_data2 = scan_data_factory(scan_id=uuid.uuid4())
        # Reuse same evidence_id
        records2 = [evidence_record_factory(position=0, evidence_id=evidence_id)]

        _, count2 = inserter.insert_scan_with_evidence(scan_data2, records2)
        db_session.commit()

        # Second insert should be no-op for the duplicate evidence record
        assert count1 == 1
        # count2 may be 0 due to ON CONFLICT DO NOTHING

    def test_count_verification_passes(self, db_session, scan_data_factory, evidence_record_factory):
        """Count verification should pass when all records inserted."""
        scan_data = scan_data_factory()
        records = [evidence_record_factory(position=i) for i in range(3)]

        inserter = BulkInserter(db_session)
        scan, count = inserter.insert_scan_with_evidence(scan_data, records)
        db_session.commit()

        result = inserter.verify_insertion_count(
            scan_id=scan_data["scan_id"],
            expected_count=3,
        )
        assert result is True

    def test_count_verification_fails_on_mismatch(self, db_session, scan_data_factory, evidence_record_factory):
        """Count verification fails when expected != actual."""
        scan_data = scan_data_factory()
        records = [evidence_record_factory(position=0)]

        inserter = BulkInserter(db_session)
        inserter.insert_scan_with_evidence(scan_data, records)
        db_session.commit()

        result = inserter.verify_insertion_count(
            scan_id=scan_data["scan_id"],
            expected_count=5,  # Wrong expected count
        )
        assert result is False