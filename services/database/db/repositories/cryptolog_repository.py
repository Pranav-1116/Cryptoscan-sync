"""CryptoLog event repository (Phase 2): idempotent writes, keyset reads.

Ingestion follows the Phase-1 identity rules exactly: identical
re-ingestion is DUPLICATE (the existing record stands), a different event
under an existing deduplication key is CONFLICT (never a silent overwrite),
and corrections are appended to their own table — the original row is never
rewritten.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from db.models.cryptolog import CryptoLogCorrection, CryptoLogEvent
from shared_models.cryptolog_events import (
    CONFLICT, DUPLICATE, INSERTED, event_hash, validate_event,
)

_OUTCOMES = (INSERTED, DUPLICATE, CONFLICT)


def partition_for(event: Mapping[str, Any]) -> str:
    """Partitions are tenant and time window (observed month)."""
    observed = str(((event.get("observation") or {}).get("observed_at")) or "")
    return f"{event.get('tenant_id')}:{observed[:7]}"


def row_to_event(row: CryptoLogEvent) -> dict[str, Any]:
    """The canonical event shape reconstructed from its stored row."""
    return {
        "event_id": row.event_id,
        "event_schema": (row.processing or {}).get("event_schema")
        or "cryptoscan.cryptolog-event/1",
        "tenant_id": row.tenant_id,
        "event_type": row.event_type,
        "category": row.category,
        "logging_kind": row.logging_kind,
        "severity": row.severity,
        "investigation_status": row.investigation_status,
        "asset_id": row.asset_id,
        "business_system_id": row.business_system_id,
        "source": row.source or {},
        "cryptographic_context": row.cryptographic_context or {},
        "observation": row.observation or {},
        "evidence": row.evidence or {},
        "relationships": row.relationships or {},
        "processing": row.processing or {},
        "telemetry_mode": row.telemetry_mode,
        "approval_ref": row.approval_ref,
        "attributes": row.attributes or {},
    }


class CryptoLogRepository:
    def __init__(self, db: Session):
        self.db = db

    def insert_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Idempotent insert. Returns {outcome, event, note}; never rewrites."""
        canonical = validate_event(event)
        digest = event_hash(canonical)
        key = (canonical.get("processing") or {}).get("deduplication_key")
        stmt = select(CryptoLogEvent).where(
            CryptoLogEvent.tenant_id == canonical["tenant_id"])
        if key:
            stmt = stmt.where(CryptoLogEvent.deduplication_key == key)
        else:
            stmt = stmt.where(CryptoLogEvent.event_hash == digest)
        existing = self.db.execute(
            stmt.order_by(CryptoLogEvent.created_at.asc(),
                          CryptoLogEvent.id.asc())).scalars().first()
        if existing is not None:
            if existing.event_hash == digest:
                return {"outcome": DUPLICATE, "event": row_to_event(existing),
                        "note": "idempotent re-ingestion: the existing "
                                "record stands"}
            return {"outcome": CONFLICT, "event": row_to_event(existing),
                    "note": "a different event under an existing "
                            "deduplication key is never a silent overwrite: "
                            "file a correction or use a new key"}
        proc = dict(canonical.get("processing") or {})
        proc["event_schema"] = canonical.get("event_schema")
        row = CryptoLogEvent(
            event_id=canonical["event_id"],
            partition_id=partition_for(canonical),
            event_hash=digest,
            deduplication_key=key or None,
            event_type=canonical["event_type"],
            category=canonical["category"],
            logging_kind=canonical["logging_kind"],
            severity=canonical["severity"],
            investigation_status=canonical["investigation_status"],
            telemetry_mode=canonical["telemetry_mode"],
            approval_ref=canonical.get("approval_ref"),
            asset_id=canonical["asset_id"],
            business_system_id=canonical.get("business_system_id"),
            source=canonical.get("source") or {},
            cryptographic_context=canonical.get("cryptographic_context") or {},
            observation=canonical.get("observation") or {},
            evidence=canonical.get("evidence") or {},
            relationships=canonical.get("relationships") or {},
            processing=proc,
            attributes=canonical.get("attributes") or {},
            tenant_id=canonical["tenant_id"],
        )
        self.db.add(row)
        self.db.commit()
        return {"outcome": INSERTED, "event": row_to_event(row),
                "note": "new event"}

    def get_event(self, tenant_id: Optional[str], event_id: str
                  ) -> CryptoLogEvent | None:
        stmt = select(CryptoLogEvent).where(
            CryptoLogEvent.event_id == event_id)
        if tenant_id is not None:
            stmt = stmt.where(CryptoLogEvent.tenant_id == tenant_id)
        return self.db.execute(stmt).scalars().first()

    def list_events(self, *, tenant_id: Optional[str] = None,
                    category: Optional[str] = None,
                    severity: Optional[str] = None,
                    event_type: Optional[str] = None,
                    asset_id: Optional[str] = None,
                    investigation_status: Optional[str] = None,
                    limit: int = 50,
                    cursor: Optional[str] = None) -> dict[str, Any]:
        """Keyset pagination (created_at, id) — stable over inserts, honest
        about boundaries: ``next_cursor`` is null on the last page and the
        response claims no totals it did not count."""
        stmt = select(CryptoLogEvent)
        if tenant_id is not None:
            stmt = stmt.where(CryptoLogEvent.tenant_id == tenant_id)
        if category is not None:
            stmt = stmt.where(CryptoLogEvent.category == category)
        if severity is not None:
            stmt = stmt.where(CryptoLogEvent.severity == severity)
        if event_type is not None:
            stmt = stmt.where(CryptoLogEvent.event_type == event_type)
        if asset_id is not None:
            stmt = stmt.where(CryptoLogEvent.asset_id == asset_id)
        if investigation_status is not None:
            stmt = stmt.where(
                CryptoLogEvent.investigation_status == investigation_status)
        if cursor:
            anchor = self.db.execute(
                select(CryptoLogEvent).where(
                    CryptoLogEvent.id == cursor)).scalars().first()
            if anchor is None:
                raise ValueError(f"unknown cursor {cursor!r}: a cursor names "
                                 "the last row of the previous page")
            stmt = stmt.where(or_(
                CryptoLogEvent.created_at > anchor.created_at,
                and_(CryptoLogEvent.created_at == anchor.created_at,
                     CryptoLogEvent.id > anchor.id)))
        rows = self.db.execute(
            stmt.order_by(CryptoLogEvent.created_at.asc(),
                          CryptoLogEvent.id.asc())
            .limit(limit + 1)).scalars().all()
        page = rows[:limit]
        # the cursor is the LAST row returned; the next page is strictly
        # after it (an exclusive anchor never skips a row)
        next_cursor = page[-1].id if len(rows) > limit else None
        return {"events": [row_to_event(r) for r in page],
                "next_cursor": next_cursor,
                "returned": len(page)}

    def insert_correction(self, *, tenant_id: str, original: Mapping[str, Any],
                          correction: Mapping[str, Any]) -> dict[str, Any]:
        """Append a superseding correction; the original row is untouched."""
        row = CryptoLogCorrection(
            corrects_event_id=str(correction.get("corrects_event_id") or ""),
            original_hash=str(correction.get("original_hash") or ""),
            corrected_event=dict(correction.get("corrected_event") or {}),
            reason=str(correction.get("reason") or ""),
            actor=str(correction.get("actor") or ""),
            evidence={"evidence_ids": list(correction.get("evidence_ids") or [])},
            tenant_id=tenant_id,
        )
        self.db.add(row)
        self.db.commit()
        return {"outcome": INSERTED, "correction": {
            "corrects_event_id": row.corrects_event_id,
            "original_hash": row.original_hash,
            "corrected_event": row.corrected_event,
            "reason": row.reason, "actor": row.actor,
            "evidence_ids": (row.evidence or {}).get("evidence_ids", []),
        }}

    def list_corrections(self, event_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute(
            select(CryptoLogCorrection)
            .where(CryptoLogCorrection.corrects_event_id == event_id)
            .order_by(CryptoLogCorrection.created_at.asc(),
                      CryptoLogCorrection.id.asc())).scalars().all()
        return [{
            "corrects_event_id": r.corrects_event_id,
            "original_hash": r.original_hash,
            "corrected_event": r.corrected_event,
            "reason": r.reason, "actor": r.actor,
            "evidence_ids": (r.evidence or {}).get("evidence_ids", []),
        } for r in rows]
