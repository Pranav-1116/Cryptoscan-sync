"""Verification log repository."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from db.models.verification_log import VerificationLog
from db.repositories.base_repository import BaseRepository


class VerificationRepository(BaseRepository[VerificationLog]):
    def __init__(self, session: Session):
        super().__init__(VerificationLog, session)

    def log(self, scan_id: str, result: str, verified_by: str, details: dict | None = None) -> VerificationLog:
        rec = VerificationLog(
            scan_id=scan_id,
            verified_at=datetime.now(timezone.utc),
            verified_by=verified_by,
            result=result,
            details=details or {},
        )
        return self.create(rec)
