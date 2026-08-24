"""
Bulk inserter for evidence records.

Provides transaction-safe bulk insertion with integrity verification.
Designed for high-throughput loading of scan results.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..models.evidence_record import EvidenceRecord
from ..models.scan import Scan

logger = logging.getLogger(__name__)

# Batch size for bulk inserts — tuned for PostgreSQL performance
_BATCH_SIZE = 500


class BulkInserter:
    """
    Handles bulk insertion of scans and evidence records.

    Uses PostgreSQL-specific INSERT with ON CONFLICT DO NOTHING
    for idempotent operations. All insertions are wrapped in a
    single transaction for atomicity.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def insert_scan_with_evidence(
        self,
        scan_data: dict[str, Any],
        evidence_records: list[dict[str, Any]],
    ) -> tuple[Scan, int]:
        """
        Insert a scan and all its evidence records atomically.

        This is the primary entry point for loading scan results.
        If ANY part fails, the entire transaction is rolled back.

        Args:
            scan_data: Dict of scan attributes for the scans table.
            evidence_records: List of evidence record dicts.

        Returns:
            Tuple of (Scan ORM object, number of records inserted).

        Raises:
            ValueError: If scan_data or evidence_records are invalid.
            IntegrityError: If a scan with the same ID already exists.
        """
        if not scan_data.get("scan_id"):
            raise ValueError("scan_data must contain 'scan_id'")

        scan_id = scan_data["scan_id"]
        if isinstance(scan_id, str):
            scan_id = uuid.UUID(scan_id)

        logger.info(
            "Starting bulk insert",
            extra={
                "scan_id": str(scan_id),
                "evidence_count": len(evidence_records),
            },
        )

        # Step 1: Insert scan record
        scan = self._insert_scan(scan_data)

        # Step 2: Bulk insert evidence records in batches
        total_inserted = self._bulk_insert_evidence(
            scan_id=scan_id,
            records=evidence_records,
        )

        logger.info(
            "Bulk insert complete",
            extra={
                "scan_id": str(scan_id),
                "records_inserted": total_inserted,
            },
        )

        return scan, total_inserted

    def _insert_scan(self, scan_data: dict[str, Any]) -> Scan:
        """Insert a single scan record."""
        scan = Scan(
            scan_id=scan_data["scan_id"],
            scan_start=scan_data.get("scan_start") or datetime.now(timezone.utc),
            scan_end=scan_data.get("scan_end"),
            scanner_id=scan_data.get("scanner_id", "unknown"),
            scanner_version=scan_data.get("scanner_version", "0.0.0"),
            target_type=scan_data.get("target_type", "UNKNOWN"),
            target_location=scan_data.get("target_location", ""),
            target_commit=scan_data.get("target_commit"),
            target_branch=scan_data.get("target_branch"),
            operator=scan_data.get("operator", "system"),
            statistics=scan_data.get("statistics") or {},
            manifest_hash=scan_data.get("manifest_hash"),
            status=scan_data.get("status", "COMPLETED"),
        )
        self.session.add(scan)
        self.session.flush()  # Get the ID without committing
        return scan

    def _bulk_insert_evidence(
        self,
        scan_id: uuid.UUID,
        records: list[dict[str, Any]],
    ) -> int:
        """
        Bulk insert evidence records in batches.

        Args:
            scan_id: Parent scan ID.
            records: List of evidence record dicts.

        Returns:
            Total number of records inserted.
        """
        if not records:
            return 0

        total = 0
        for batch_start in range(0, len(records), _BATCH_SIZE):
            batch = records[batch_start : batch_start + _BATCH_SIZE]
            rows = [self._prepare_evidence_row(scan_id, rec) for rec in batch]

            # Use PostgreSQL INSERT ... ON CONFLICT DO NOTHING for idempotency
            stmt = pg_insert(EvidenceRecord.__table__).values(rows)
            stmt = stmt.on_conflict_do_nothing(index_elements=["evidence_id"])

            result = self.session.execute(stmt)
            inserted = result.rowcount
            total += inserted

            logger.debug(
                "Evidence batch inserted",
                extra={
                    "batch_start": batch_start,
                    "batch_size": len(batch),
                    "inserted": inserted,
                },
            )

        return total

    def _prepare_evidence_row(
        self,
        scan_id: uuid.UUID,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Prepare an evidence record dict for bulk insertion.

        Extracts flat columns from nested finding_data JSONB
        for efficient querying.

        Args:
            scan_id: Parent scan ID.
            record: Evidence record dict from evidence pipeline.

        Returns:
            Flat dict suitable for PostgreSQL INSERT.
        """
        finding_data = record.get("finding", {}) or {}
        crypto = finding_data.get("crypto", {}) or {}
        source = finding_data.get("source", {}) or {}
        metadata = finding_data.get("metadata", {}) or {}
        git_context = finding_data.get("git_context", {}) or {}

        evidence_id = record.get("evidence_id")
        if evidence_id and isinstance(evidence_id, str):
            evidence_id = uuid.UUID(evidence_id)
        elif not evidence_id:
            evidence_id = uuid.uuid4()

        now = datetime.now(timezone.utc)

        return {
            "evidence_id": evidence_id,
            "scan_id": scan_id,
            "content_hash": record.get("content_hash", ""),
            "chain_position": record.get("chain", {}).get("position", 0),
            "chain_hash": record.get("chain", {}).get("chain_hash", ""),
            "previous_hash": record.get("chain", {}).get("previous_hash"),
            # Extracted fields for fast queries
            "algorithm": crypto.get("algorithm"),
            "key_size": crypto.get("key_size"),
            "purpose": crypto.get("purpose"),
            "confidence": metadata.get("confidence", "LOW"),
            "file_path": source.get("file_path"),
            "line_number": source.get("line_number"),
            "class_name": source.get("class_name"),
            "method_name": source.get("method_name"),
            "is_hardcoded_key": metadata.get("is_hardcoded_key", False),
            # Full JSONB data
            "finding_data": finding_data,
            "provenance": record.get("provenance", {}),
            # Timestamps
            "created_at": now,
            "updated_at": now,
        }

    def verify_insertion_count(
        self,
        scan_id: uuid.UUID,
        expected_count: int,
    ) -> bool:
        """
        Verify that the expected number of records were inserted.

        Args:
            scan_id: The scan to check.
            expected_count: Expected number of evidence records.

        Returns:
            True if counts match.
        """
        result = self.session.execute(
            text(
                "SELECT COUNT(*) FROM evidence_records WHERE scan_id = :scan_id"
            ),
            {"scan_id": scan_id},
        )
        actual_count = result.scalar_one()

        if actual_count != expected_count:
            logger.error(
                "Count mismatch after bulk insert",
                extra={
                    "scan_id": str(scan_id),
                    "expected": expected_count,
                    "actual": actual_count,
                },
            )
            return False

        logger.info(
            "Count verification passed",
            extra={
                "scan_id": str(scan_id),
                "count": actual_count,
            },
        )
        return True