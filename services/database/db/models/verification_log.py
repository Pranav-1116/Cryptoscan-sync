"""Integrity verification audit log."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class VerificationLog(BaseModel):
    __tablename__ = "verification_log"

    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_by: Mapped[str] = mapped_column(String(100), nullable=False)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
