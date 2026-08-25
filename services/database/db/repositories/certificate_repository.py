"""Certificate inventory persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.certificate import Certificate
from db.repositories.base_repository import BaseRepository


class CertificateRepository(BaseRepository[Certificate]):
    def __init__(self, session: Session):
        super().__init__(Certificate, session)

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
                extra=payload.get("extra"),
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
                setattr(row, key, payload[key])
        if payload.get("revocation_status") is not None:
            row.revocation_checked_at = datetime.now(timezone.utc)
        extra = dict(row.extra or {})
        if payload.get("extra"):
            extra.update(payload["extra"])
        if payload.get("revocation"):
            extra["revocation"] = payload["revocation"]
        if payload.get("chain_validation"):
            extra["chain_validation"] = payload["chain_validation"]
        row.extra = extra or row.extra
        row.updated_at = datetime.now(timezone.utc)
        self.session.flush()
        return row

    def list_all(self, *, expiring_days: int | None = None) -> list[Certificate]:
        rows = list(self.session.execute(select(Certificate)).scalars())
        rows.sort(key=lambda row: (row.days_until_expiry is None, row.days_until_expiry or 0))
        if expiring_days is None:
            return rows
        return [row for row in rows if row.days_until_expiry is not None and 0 <= row.days_until_expiry <= expiring_days]
