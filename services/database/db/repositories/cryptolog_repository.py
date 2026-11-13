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

from db.models.cryptolog import CryptoLogCorrection, CryptoLogEvent, CryptoLogAlert, CryptoLogCheckpoint
from shared_models.cryptolog_events import (
    CONFLICT, DUPLICATE, INSERTED, event_hash, validate_event,
)

_OUTCOMES = (INSERTED, DUPLICATE, CONFLICT)


class CryptoLogWindowTooLarge(ValueError):
    """An auditor export cannot include a complete bounded event window."""


def partition_for(event: Mapping[str, Any]) -> str:
    """Partitions are tenant and time window (observed month)."""
    observed = str(((event.get("observation") or {}).get("observed_at")) or "")
    return f"{event.get('tenant_id')}:{observed[:7]}"


def row_to_event(row: CryptoLogEvent) -> dict[str, Any]:
    """The canonical event shape reconstructed from its stored row.

    Reproduces the hashed canonical form byte-for-byte: the schema marker
    the insert stashed inside processing is lifted back to its top-level
    field, never left as a processing key the hash never covered.
    """
    processing = dict(row.processing or {})
    processing.pop("event_schema", None)
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
        "processing": processing,
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



class CryptoLogAlertRepository:
    """Alerts and integrity checkpoints. Alerts carry their honest boundary;
    transitions and checkpoints are append-only records."""

    def __init__(self, db: Session):
        self.db = db

    def insert_alert(self, *, tenant_id: str, alert: Mapping[str, Any]) -> dict[str, Any]:
        existing = (
            self.db.query(CryptoLogAlert)
            .filter(CryptoLogAlert.tenant_id == tenant_id,
                    CryptoLogAlert.alert_id == str(alert["alert_id"]))
            .one_or_none()
        )
        if existing is not None:
            return {"outcome": DUPLICATE, "alert": self._row(existing)}
        row = CryptoLogAlert(
            tenant_id=tenant_id,
            alert_id=str(alert["alert_id"]),
            rule_id=str(alert["rule_id"]),
            event_id=str(alert["event_id"]),
            asset_id=str(alert["asset_id"]),
            severity=str(alert["severity"]),
            state=str(alert.get("state", "NEW")),
            title=str(alert["title"]),
            basis=dict(alert.get("basis") or {}),
            what_is_proven=list(alert.get("what_is_proven") or []),
            what_is_not_proven=list(alert.get("what_is_not_proven") or []),
            evidence_ids=list(alert.get("evidence_ids") or []),
            occurred_at=str(alert["occurred_at"]),
            transitions=list(alert.get("transitions") or []),
        )
        self.db.add(row)
        self.db.flush()
        return {"outcome": INSERTED, "alert": self._row(row)}

    def _row(self, row: CryptoLogAlert) -> dict[str, Any]:
        return {
            "alert_id": row.alert_id,
            "rule_id": row.rule_id,
            "event_id": row.event_id,
            "asset_id": row.asset_id,
            "severity": row.severity,
            "state": row.state,
            "title": row.title,
            "basis": dict(row.basis or {}),
            "what_is_proven": list(row.what_is_proven or []),
            "what_is_not_proven": list(row.what_is_not_proven or []),
            "evidence_ids": list(row.evidence_ids or []),
            "occurred_at": row.occurred_at,
            "transitions": list(row.transitions or []),
            "tenant_id": row.tenant_id,
        }

    def get_alert(self, tenant_id: Optional[str], alert_id: str) -> Optional[dict[str, Any]]:
        query = self.db.query(CryptoLogAlert).filter(CryptoLogAlert.alert_id == alert_id)
        if tenant_id:
            query = query.filter(CryptoLogAlert.tenant_id == tenant_id)
        row = query.one_or_none()
        return self._row(row) if row is not None else None

    def list_alerts(self, *, tenant_id: Optional[str] = None,
                    state: Optional[str] = None,
                    severity: Optional[str] = None,
                    rule_id: Optional[str] = None,
                    event_id: Optional[str] = None,
                    limit: int = 50,
                    cursor: Optional[str] = None) -> dict[str, Any]:
        query = self.db.query(CryptoLogAlert)
        if tenant_id:
            query = query.filter(CryptoLogAlert.tenant_id == tenant_id)
        if state:
            query = query.filter(CryptoLogAlert.state == state)
        if severity:
            query = query.filter(CryptoLogAlert.severity == severity)
        if rule_id:
            query = query.filter(CryptoLogAlert.rule_id == rule_id)
        if event_id:
            query = query.filter(CryptoLogAlert.event_id == event_id)
        total = query.count()
        if cursor:
            query = query.filter(CryptoLogAlert.alert_id < cursor)
        rows = query.order_by(CryptoLogAlert.alert_id.desc()).limit(limit).all()
        return {
            "rows": [self._row(r) for r in rows],
            "total_count": total,
            "next_cursor": rows[-1].alert_id if rows else None,
            "has_more": len(rows) == limit,
        }

    def append_transition(self, *, tenant_id: Optional[str], alert_id: str,
                          entry: Mapping[str, Any]) -> Optional[dict[str, Any]]:
        query = self.db.query(CryptoLogAlert).filter(
            CryptoLogAlert.alert_id == alert_id)
        if tenant_id:
            query = query.filter(CryptoLogAlert.tenant_id == tenant_id)
        row = query.one_or_none()
        if row is None:
            return None
        history = list(row.transitions or [])
        history.append(dict(entry))  # append-only: never rewrite prior entries
        row.transitions = history
        if "state" in entry:
            row.state = str(entry["state"])
        self.db.flush()
        return self._row(row)

    def insert_checkpoint(self, *, tenant_id: str,
                          checkpoint: Mapping[str, Any]) -> dict[str, Any]:
        ref = str(checkpoint["checkpoint_ref"])
        existing = (
            self.db.query(CryptoLogCheckpoint)
            .filter(CryptoLogCheckpoint.tenant_id == tenant_id,
                    CryptoLogCheckpoint.checkpoint_ref == ref)
            .one_or_none()
        )
        if existing is not None:
            return {"outcome": DUPLICATE, "checkpoint": self._cp_row(existing)}
        canonical = {
            "schema": str(checkpoint.get("schema") or "chain-checkpoint/1"),
            "partition_id": str(checkpoint.get("partition_id") or ""),
            "sequence": int(checkpoint.get("sequence") or 0),
            "chain_hash": str(checkpoint.get("chain_hash") or ""),
            "merkle_root_hash": str(checkpoint.get("merkle_root_hash") or ""),
            "event_count": int(checkpoint.get("event_count") or 0),
            "created_at": str(checkpoint.get("created_at") or ""),
            "retention_ref": str(checkpoint.get("retention_ref") or ""),
            "signer_id": str(checkpoint.get("signer_id") or ""),
            "signature": str(checkpoint.get("signature") or ""),
        }
        window = {"canonical": canonical}
        window.update(dict(checkpoint.get("window") or {}))
        row = CryptoLogCheckpoint(
            tenant_id=tenant_id,
            checkpoint_ref=ref,
            algorithm=canonical["schema"],
            leaf_count=canonical["event_count"],
            merkle_root=canonical["merkle_root_hash"],
            head_hash=canonical["chain_hash"],
            chain_head_event_id=checkpoint.get("chain_head_event_id"),
            window=window,
            signer_id=canonical["signer_id"],
            signature=canonical["signature"],
            retention_ref=canonical["retention_ref"],
            previous_checkpoint=dict(checkpoint.get("previous_checkpoint") or {}),
            verification_notes=list(checkpoint.get("verification_notes") or []),
        )
        self.db.add(row)
        self.db.flush()
        return {"outcome": INSERTED, "checkpoint": self._cp_row(row)}

    def _cp_row(self, row: CryptoLogCheckpoint) -> dict[str, Any]:
        window = dict(row.window or {})
        canonical = dict(window.pop("canonical", {}) or {})
        out = dict(canonical)
        out.update({
            "checkpoint_ref": row.checkpoint_ref,
            "algorithm": row.algorithm,
            "leaf_count": row.leaf_count,
            "merkle_root": row.merkle_root,
            "head_hash": row.head_hash,
            "chain_head_event_id": row.chain_head_event_id,
            "window": window,
            "signer_id": row.signer_id,
            "signature": row.signature,
            "retention_ref": row.retention_ref,
            "previous_checkpoint": dict(row.previous_checkpoint or {}),
            "verification_notes": list(row.verification_notes or []),
        })
        return out

    def count_checkpoints(self, tenant_id: Optional[str],
                          partition_id: str) -> int:
        query = self.db.query(CryptoLogCheckpoint)
        if tenant_id:
            query = query.filter(CryptoLogCheckpoint.tenant_id == tenant_id)
        return sum(
            1 for r in query.all()
            if str((r.window or {}).get("canonical", {}).get("partition_id") or "")
            == partition_id)

    def get_checkpoint(self, tenant_id: Optional[str],
                       checkpoint_ref: str) -> Optional[dict[str, Any]]:
        query = self.db.query(CryptoLogCheckpoint).filter(
            CryptoLogCheckpoint.checkpoint_ref == checkpoint_ref)
        if tenant_id:
            query = query.filter(CryptoLogCheckpoint.tenant_id == tenant_id)
        row = query.one_or_none()
        return self._cp_row(row) if row is not None else None

    def latest_checkpoint(self, tenant_id: Optional[str]) -> Optional[dict[str, Any]]:
        query = self.db.query(CryptoLogCheckpoint)
        if tenant_id:
            query = query.filter(CryptoLogCheckpoint.tenant_id == tenant_id)
        row = query.order_by(CryptoLogCheckpoint.created_at.desc()).first()
        return self._cp_row(row) if row is not None else None

    def list_checkpoints(self, *, tenant_id: Optional[str] = None,
                         limit: int = 50) -> dict[str, Any]:
        query = self.db.query(CryptoLogCheckpoint)
        if tenant_id:
            query = query.filter(CryptoLogCheckpoint.tenant_id == tenant_id)
        total = query.count()
        rows = query.order_by(CryptoLogCheckpoint.created_at.desc()).limit(limit).all()
        return {"rows": [self._cp_row(r) for r in rows], "total_count": total}

    def events_in_range(self, *, tenant_id: Optional[str] = None,
                        start_occurred: Optional[str] = None,
                        end_occurred: Optional[str] = None,
                        asset_id: Optional[str] = None,
                        max_events: Optional[int] = None) -> list[dict[str, Any]]:
        """Stored events in ledger order; refuse an oversized auditor window.

        Stream rows instead of materializing the entire table before checking
        the budget. Filtering by observed time stays exact and portable across
        SQLite/PostgreSQL; only matching rows count toward max_events.
        """
        query = self.db.query(CryptoLogEvent)
        if tenant_id:
            query = query.filter(CryptoLogEvent.tenant_id == tenant_id)
        if asset_id:
            query = query.filter(CryptoLogEvent.asset_id == asset_id)
        if max_events is not None and max_events <= 0:
            raise ValueError("max_events must be positive")
        events: list[dict[str, Any]] = []
        for row in query.order_by(
                CryptoLogEvent.created_at, CryptoLogEvent.event_id).yield_per(256):
            event = row_to_event(row)
            observed = str((event.get("observation") or {}).get("observed_at") or "")
            if start_occurred and observed < start_occurred:
                continue
            if end_occurred and observed > end_occurred:
                continue
            events.append({"event": event, "event_hash": row.event_hash,
                           "partition_id": row.partition_id})
            if max_events is not None and len(events) > max_events:
                raise CryptoLogWindowTooLarge(
                    f"event window exceeds {max_events} records")
        return events
