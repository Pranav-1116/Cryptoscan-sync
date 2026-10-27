"""Certificate inventory persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.certificate import Certificate
from db.repositories.base_repository import BaseRepository
from shared_models.composite_certificates import composite_block


def _as_dt(value):
    """ISO string (scanner payload) -> aware datetime; None passes through."""
    from datetime import datetime, timezone

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


class CertificateRepository(BaseRepository[Certificate]):
    def __init__(self, session: Session):
        super().__init__(Certificate, session)

    RENEWAL_STATUSES = ("NONE", "PLANNED", "IN_PROGRESS", "DONE")

    def update_renewal(self, fingerprint: str, status: str, *,
                       ticket: str | None = None, note: str | None = None) -> Certificate | None:
        """Track the renewal workflow for one certificate (by sha256 fingerprint)."""
        from datetime import datetime, timezone

        row = self.session.execute(
            select(Certificate).where(Certificate.fingerprint_sha256 == fingerprint)
        ).scalar_one_or_none()
        if row is None:
            return None
        if status not in self.RENEWAL_STATUSES:
            raise ValueError(f"status must be one of {self.RENEWAL_STATUSES}")
        row.renewal_status = status
        if ticket is not None:
            row.renewal_ticket = ticket
        if note is not None:
            row.renewal_note = note
        if status == "DONE":
            row.renewed_at = datetime.now(timezone.utc)
        self.session.flush()
        return row

    def _composite_extra(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Composite/hybrid detection (audit 59) — pure registry lookup.

        Detection re-runs on every ingest; the result is stored in
        ``extra["composite"]`` so listing surfaces stay single-query.
        """
        extra = dict(payload.get("extra") or {})
        composite = composite_block(payload)
        if composite is not None:
            extra["composite"] = composite
        return extra

    def upsert(self, payload: dict[str, Any]) -> Certificate:
        fp = payload.get("fingerprint_sha256")
        row = None
        if fp:
            row = self.session.execute(select(Certificate).where(Certificate.fingerprint_sha256 == fp)).scalar_one_or_none()
        usages = list(payload.get("usages") or [])
        if row is None:
            row = Certificate(
                fingerprint_sha256=str(fp or ""),
                subject=payload.get("subject"),
                issuer=payload.get("issuer"),
                serial_number=payload.get("serial_number"),
                not_before=_as_dt(payload.get("not_before")),
                not_after=_as_dt(payload.get("not_after")),
                public_key_algorithm=payload.get("public_key_algorithm"),
                public_key_size=payload.get("public_key_size"),
                expiry_status=payload.get("expiry_status"),
                days_until_expiry=payload.get("days_until_expiry"),
                is_self_signed=bool(payload.get("is_self_signed")),
                san=payload.get("san"),
                usages=usages,
                revocation_status=payload.get("revocation_status"),
                revocation_method=payload.get("revocation_method"),
                ocsp_url=payload.get("ocsp_url"),
                crl_url=payload.get("crl_url"),
                extra=self._composite_extra(payload) or None,
            )
            return self.create(row)
        merged = list(row.usages or [])
        for item in usages:
            if item not in merged:
                merged.append(item)
        row.usages = merged
        for key in (
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "expiry_status",
            "days_until_expiry",
            "public_key_algorithm",
            "public_key_size",
            "revocation_status",
            "revocation_method",
            "ocsp_url",
            "crl_url",
        ):
            if payload.get(key) is not None:
                value = payload[key]
                if key in {"not_before", "not_after"}:
                    value = _as_dt(value)  # scanner payloads carry ISO strings
                setattr(row, key, value)
        if payload.get("revocation_status") is not None:
            row.revocation_checked_at = datetime.now(timezone.utc)
        extra = dict(row.extra or {})
        if payload.get("extra"):
            extra.update(payload["extra"])
        composite = composite_block(payload)
        if composite is not None:
            extra["composite"] = composite
        if payload.get("revocation"):
            extra["revocation"] = payload["revocation"]
        if payload.get("chain_validation"):
            extra["chain_validation"] = payload["chain_validation"]
        row.extra = extra or row.extra
        row.updated_at = datetime.now(timezone.utc)
        self.session.flush()
        return row

    def get_by_fingerprint(self, fingerprint: str) -> Certificate | None:
        """Look up one certificate by its SHA-256 fingerprint."""
        return self.session.execute(
            select(Certificate).where(Certificate.fingerprint_sha256 == fingerprint)
        ).scalar_one_or_none()

    def list_all(self, *, expiring_days: int | None = None) -> list[Certificate]:
        rows = list(self.session.execute(select(Certificate)).scalars())
        rows.sort(key=lambda row: (row.days_until_expiry is None, row.days_until_expiry or 0))
        if expiring_days is None:
            return rows
        return [row for row in rows if row.days_until_expiry is not None and 0 <= row.days_until_expiry <= expiring_days]

    def list_composite(self) -> list[Certificate]:
        """Certificates whose algorithm was detected as composite/hybrid.

        Detection is stored on ingest (``extra["composite"]``); this is a
        straight filter over the inventory — no heuristic runs here.
        """
        return [row for row in self.list_all() if (row.extra or {}).get("composite")]
