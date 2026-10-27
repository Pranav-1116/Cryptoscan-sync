"""Verification log repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from db.models.verification_log import VerificationLog
from db.repositories.base_repository import BaseRepository


class VerificationRepository(BaseRepository[VerificationLog]):
    def __init__(self, session: Session):
        super().__init__(VerificationLog, session)

    def log(
        self,
        scan_id: str,
        result: str,
        verified_by: str,
        details: dict | None = None,
        *,
        chain_valid: bool = True,
        content_hashes_valid: bool = True,
    ) -> VerificationLog:
        rec = VerificationLog(
            scan_id=str(scan_id),
            verified_at=datetime.now(timezone.utc),
            verified_by=verified_by,
            result=result,
            chain_valid=chain_valid,
            content_hashes_valid=content_hashes_valid,
            details=details or {},
        )
        return self.create(rec)

    def get_latest_for_scan(self, scan_id) -> VerificationLog | None:
        from sqlalchemy import select

        return self.session.execute(
            select(VerificationLog)
            .where(VerificationLog.scan_id == str(scan_id))
            .order_by(VerificationLog.verified_at.desc(), VerificationLog.id.desc())
            .limit(1)
        ).scalars().first()
