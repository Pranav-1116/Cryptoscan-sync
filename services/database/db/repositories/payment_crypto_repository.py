"""Repository layer for the payment-crypto inventory."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.payment_crypto import (
    HsmEvent,
    KeyCeremony,
    PaymentKey,
    PaymentPolicyFinding,
    PaymentTransactionVolume,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PaymentCryptoRepository:
    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------ keys

    def upsert_key(self, payload: dict) -> PaymentKey:
        """Create or update a key by its key_id reference."""
        key_id = str(payload.get("key_id") or "").strip()
        if not key_id:
            raise ValueError("key_id is required")
        row = self.get_key(key_id)
        if row is None:
            row = PaymentKey(
                key_id=key_id,
                name=payload.get("name"),
                hsm_device=payload.get("hsm_device"),
                key_usage=payload.get("key_usage"),
                algorithm=payload.get("algorithm"),
                key_size=payload.get("key_size"),
                state=payload.get("state") or "ACTIVE",
                enabled=bool(payload.get("enabled", True)),
                key_block_version=payload.get("key_block_version"),
                key_block_error=payload.get("key_block_error"),
                activation_at=payload.get("activation_at"),
                expiry_at=payload.get("expiry_at"),
                custodian_count=payload.get("custodian_count"),
                source=payload.get("source") or "MANUAL",
                notes=payload.get("notes"),
            )
            self.session.add(row)
        else:
            for field in (
                "name", "hsm_device", "key_usage", "algorithm", "key_size", "state",
                "key_block_version", "key_block_error", "activation_at", "expiry_at",
                "custodian_count", "notes",
            ):
                if payload.get(field) is not None:
                    setattr(row, field, payload[field])
            if payload.get("enabled") is not None:
                row.enabled = bool(payload["enabled"])
            if payload.get("source"):
                row.source = payload["source"]
        self.session.flush()
        return row

    def get_key(self, key_id: str) -> Optional[PaymentKey]:
        return self.session.execute(
            select(PaymentKey).where(PaymentKey.key_id == key_id)
        ).scalar_one_or_none()

    def list_keys(self, *, state: Optional[str] = None, hsm_device: Optional[str] = None) -> list[PaymentKey]:
        query = select(PaymentKey)
        if state:
            query = query.where(PaymentKey.state == state)
        if hsm_device:
            query = query.where(PaymentKey.hsm_device == hsm_device)
        return list(self.session.scalars(query.order_by(PaymentKey.key_id)))

    def delete_key(self, key_id: str) -> bool:
        row = self.get_key(key_id)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

    # ------------------------------------------------------------- ceremonies

    def upsert_ceremony(self, payload: dict) -> KeyCeremony:
        ceremony_id = str(payload.get("ceremony_id") or "").strip()
        if not ceremony_id:
            raise ValueError("ceremony_id is required")
        row = self.session.execute(
            select(KeyCeremony).where(KeyCeremony.ceremony_id == ceremony_id)
        ).scalar_one_or_none()
        if row is None:
            held_at = payload.get("held_at")
            derived = dict(payload)
            if not derived.get("status"):
                derived["status"] = _ceremony_status(held_at)
            row = KeyCeremony(ceremony_id=ceremony_id, **{
                key: value for key, value in derived.items() if key != "ceremony_id"
            })
            self.session.add(row)
        else:
            for field in ("key_id", "held_at", "custodians", "m_of_n", "dual_control",
                          "location", "documented", "notes", "status"):
                if payload.get(field) is not None:
                    setattr(row, field, payload[field])
        self.session.flush()
        return row

    def list_ceremonies(self, *, key_id: Optional[str] = None, status: Optional[str] = None,
                        upcoming_only: bool = False) -> list[KeyCeremony]:
        query = select(KeyCeremony)
        if key_id:
            query = query.where(KeyCeremony.key_id == key_id)
        if status:
            query = query.where(KeyCeremony.status == status)
        if upcoming_only:
            query = query.where(
                KeyCeremony.status == "PLANNED", KeyCeremony.held_at >= utcnow()
            )
        return list(self.session.scalars(query.order_by(KeyCeremony.held_at.desc())))

    def update_ceremony(self, ceremony_id: str, updates: dict) -> Optional[KeyCeremony]:
        row = self.session.execute(
            select(KeyCeremony).where(KeyCeremony.ceremony_id == ceremony_id)
        ).scalar_one_or_none()
        if row is None:
            return None
        for field in ("key_id", "held_at", "custodians", "m_of_n", "dual_control",
                      "location", "documented", "notes", "status"):
            if updates.get(field) is not None:
                setattr(row, field, updates[field])
        if updates.get("held_at") is not None and "status" not in updates:
            row.status = _ceremony_status(updates["held_at"])
        self.session.flush()
        return row


    def add_events(self, records: list[dict]) -> list[HsmEvent]:
        rows = []
        for record in records:
            occurred = record.get("occurred_at")
            if isinstance(occurred, str):
                occurred = datetime.fromisoformat(occurred.replace("Z", "+00:00"))
            row = HsmEvent(
                occurred_at=occurred or utcnow(),
                device=record.get("device") or "?",
                event_type=record.get("event_type") or "UNKNOWN_EVENT",
                key_id=record.get("key_id"),
                actor=record.get("actor"),
                severity=record.get("severity") or "INFO",
                detail=record.get("detail") or {},
                raw=record.get("raw"),
            )
            self.session.add(row)
            rows.append(row)
        self.session.flush()
        return rows

    def recent_events(self, *, days: int = 30, device: Optional[str] = None) -> list[HsmEvent]:
        window_start = utcnow() - timedelta(days=days)
        query = select(HsmEvent).where(HsmEvent.occurred_at >= window_start)
        if device:
            query = query.where(HsmEvent.device == device)
        return list(self.session.scalars(query.order_by(HsmEvent.occurred_at.desc()).limit(5000)))

    # ---------------------------------------------------- transaction volume

    def upsert_transaction_volume(self, day, transaction_count: int, *, source: str | None = None) -> PaymentTransactionVolume:
        if transaction_count < 0:
            raise ValueError("transaction_count must be >= 0")
        row = self.session.execute(
            select(PaymentTransactionVolume).where(PaymentTransactionVolume.day == day)
        ).scalar_one_or_none()
        if row is None:
            row = PaymentTransactionVolume(day=day, transaction_count=transaction_count, source=source)
            self.session.add(row)
        else:
            row.transaction_count = transaction_count
            if source:
                row.source = source
        self.session.flush()
        return row

    def transaction_series(self, *, days: int = 60) -> dict:
        from datetime import timedelta

        window_start = (utcnow() - timedelta(days=days)).date()
        rows = self.session.scalars(
            select(PaymentTransactionVolume).where(PaymentTransactionVolume.day >= window_start)
            .order_by(PaymentTransactionVolume.day)
        )
        return {row.day.isoformat(): row.transaction_count for row in rows}

    # -------------------------------------------------------------- findings

    def replace_findings(self, findings: list[dict]) -> list[PaymentPolicyFinding]:
        """Replace OPEN findings with a fresh evaluation, preserving ACCEPTED ones."""
        accepted = {
            (row.rule_id, row.key_id or "")
            for row in self.session.scalars(
                select(PaymentPolicyFinding).where(PaymentPolicyFinding.status == "ACCEPTED")
            )
        }
        for row in self.session.scalars(select(PaymentPolicyFinding).where(PaymentPolicyFinding.status == "OPEN")):
            self.session.delete(row)
        rows = []
        now = utcnow()
        for finding in findings:
            if (finding.get("rule_id"), finding.get("key_id") or "") in accepted:
                continue  # operator accepted this risk; do not re-open silently
            rows.append(PaymentPolicyFinding(
                rule_id=finding["rule_id"],
                key_id=finding.get("key_id"),
                severity=finding.get("severity", 1),
                blocking=bool(finding.get("blocking")),
                message=finding.get("message", ""),
                evidence=finding.get("evidence"),
                evaluated_at=now,
            ))
            self.session.add(rows[-1])
        self.session.flush()
        return rows

    def list_findings(self, *, status: Optional[str] = None) -> list[PaymentPolicyFinding]:
        query = select(PaymentPolicyFinding)
        if status:
            query = query.where(PaymentPolicyFinding.status == status)
        return list(self.session.scalars(query.order_by(PaymentPolicyFinding.severity.desc())))

    def set_finding_status(self, finding_id: str, status: str, *, resolved_by: str | None = None) -> Optional[PaymentPolicyFinding]:
        if status not in {"OPEN", "ACCEPTED", "RESOLVED"}:
            raise ValueError("status must be OPEN, ACCEPTED or RESOLVED")
        row = self.session.execute(select(PaymentPolicyFinding).where(PaymentPolicyFinding.id == finding_id)).scalars().first()
        if row is None:
            return None
        row.status = status
        row.resolved_by = resolved_by
        self.session.flush()
        return row


def _ceremony_status(held_at) -> str:
    """A ceremony dated in the future is a booking (PLANNED); past = it happened."""
    if isinstance(held_at, datetime) and held_at.tzinfo is None:
        held_at = held_at.replace(tzinfo=timezone.utc)
    if isinstance(held_at, str) and held_at:
        try:
            held_at = datetime.fromisoformat(held_at.replace("Z", "+00:00"))
        except ValueError:
            return "HELD"
    if isinstance(held_at, datetime):
        if held_at.tzinfo is None:
            held_at = held_at.replace(tzinfo=timezone.utc)
        return "PLANNED" if held_at > utcnow() else "HELD"
    return "HELD"

    # ---------------------------------------------------------------- events
