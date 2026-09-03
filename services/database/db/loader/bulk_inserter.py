"""Bulk insert helpers.

``BulkInserter`` atomically persists a scan together with its hash-chained
evidence records. It is idempotent: evidence rows whose ``evidence_id`` already
exists are skipped (ON CONFLICT DO NOTHING semantics), and it exposes a count
verification used by the post-load verifier.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

logger = logging.getLogger(__name__)


def _as_datetime(value: Any) -> datetime | None:
    """Coerce an ISO-8601 string (or datetime) to a datetime instance."""
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def bulk_insert(session: Session, objects: Iterable[object]) -> None:
    session.add_all(list(objects))
    session.flush()


class BulkInserter:
    """Transactional, idempotent scan + evidence ingestion."""

    def __init__(self, session: Session):
        self.session = session

    def insert_scan_with_evidence(
        self,
        scan_data: dict[str, Any],
        evidence_records: list[dict[str, Any]],
    ) -> tuple[Scan, int]:
        """Insert a scan row and its evidence records in the open transaction.

        Returns ``(scan, inserted_count)`` where ``inserted_count`` excludes
        records skipped because their ``evidence_id`` already exists. The
        caller is responsible for ``session.commit()``; a failure rolls back
        the whole unit of work.
        """
        scan = self._upsert_scan(scan_data)
        inserted = self._insert_evidence(scan, evidence_records)
        logger.info(
            "bulk_insert",
            extra={"scan_id": scan.id, "submitted": len(evidence_records), "inserted": inserted},
        )
        return scan, inserted

    def verify_insertion_count(self, *, scan_id: str, expected_count: int) -> bool:
        """Return True when the persisted evidence count matches expectation."""
        actual = self.session.execute(
            select(func.count(EvidenceRecord.id)).where(EvidenceRecord.scan_id == str(scan_id))
        ).scalar_one()
        return int(actual) == int(expected_count)

    # ------------------------------------------------------------------ #

    def _upsert_scan(self, scan_data: dict[str, Any]) -> Scan:
        raw_id = scan_data.get("scan_id") or scan_data.get("id")
        scan_id = str(raw_id) if raw_id else ""
        scan = self.session.get(Scan, scan_id) if scan_id else None
        if scan is not None:
            return scan

        now = datetime.now(timezone.utc)
        scan = Scan(
            id=scan_id,
            scan_start=_as_datetime(scan_data.get("scan_start")) or now,
            scan_end=_as_datetime(scan_data.get("scan_end")),
            scanner_id=scan_data.get("scanner_id", "static-java-scanner-v0.1"),
            scanner_version=scan_data.get("scanner_version", "0.1.0"),
            target_type=scan_data.get("target_type", "LOCAL_DIRECTORY"),
            target_location=scan_data.get("target_location") or "unknown",
            target_commit=scan_data.get("target_commit"),
            target_branch=scan_data.get("target_branch"),
            operator=scan_data.get("operator", "system"),
            status=scan_data.get("status", "COMPLETED"),
        )
        self.session.add(scan)
        self.session.flush()
        return scan

    def _insert_evidence(self, scan: Scan, records: list[dict[str, Any]]) -> int:
        if not records:
            return 0

        dialect = self.session.get_bind().dialect.name
        if dialect == "postgresql":
            return self._insert_evidence_pg(scan, records)
        return self._insert_evidence_portable(scan, records)

    def _build_row(self, scan: Scan, rec: dict[str, Any]) -> dict[str, Any]:
        finding = rec.get("finding") or rec.get("finding_data") or {}
        crypto = finding.get("crypto") or {}
        source = finding.get("source") or {}
        metadata = finding.get("metadata") or {}
        chain = rec.get("chain") if isinstance(rec.get("chain"), dict) else {}
        return {
            "id": str(rec.get("evidence_id")),
            "scan_id": scan.id,
            "content_hash": rec["content_hash"],
            "chain_hash": chain.get("chain_hash") or rec.get("chain_hash") or rec["content_hash"],
            "chain_position": int(chain.get("position", rec.get("chain_position") or 0) or 0),
            "previous_hash": chain.get("previous_hash", rec.get("previous_hash")),
            "algorithm": crypto.get("algorithm") or rec.get("algorithm") or "UNKNOWN",
            "key_size": crypto.get("key_size") or rec.get("key_size"),
            "mode": crypto.get("mode") or rec.get("mode"),
            "padding": crypto.get("padding") or rec.get("padding"),
            "purpose": crypto.get("purpose") or rec.get("purpose"),
            "confidence": metadata.get("confidence") or rec.get("confidence") or "LOW",
            "is_hardcoded_key": bool(metadata.get("is_hardcoded_key") or rec.get("is_hardcoded_key")),
            "file_path": source.get("file_path") or rec.get("file_path") or "unknown",
            "line_number": int(source.get("line_number") or rec.get("line_number") or 0),
            "class_name": source.get("class_name") or rec.get("class_name"),
            "method_name": source.get("method_name") or rec.get("method_name"),
            "finding_data": finding,
            "provenance": rec.get("provenance") or rec.get("integrity"),
        }

    def _insert_evidence_pg(self, scan: Scan, records: list[dict[str, Any]]) -> int:
        rows = [self._build_row(scan, rec) for rec in records]
        stmt = pg_insert(EvidenceRecord).values(rows).on_conflict_do_nothing(index_elements=["id"])
        result = self.session.execute(stmt)
        return result.rowcount if result.rowcount is not None else len(rows)

    def _insert_evidence_portable(self, scan: Scan, records: list[dict[str, Any]]) -> int:
        """SQLite and other dialects: skip rows whose evidence_id already exists."""
        ids = [str(rec.get("evidence_id")) for rec in records]
        existing = set(
            self.session.execute(
                select(EvidenceRecord.id).where(EvidenceRecord.id.in_(ids))
            ).scalars()
        )
        inserted = 0
        for rec in records:
            row = self._build_row(scan, rec)
            if row["id"] in existing:
                continue
            self.session.add(EvidenceRecord(**row))
            existing.add(row["id"])
            inserted += 1
        self.session.flush()
        return inserted
