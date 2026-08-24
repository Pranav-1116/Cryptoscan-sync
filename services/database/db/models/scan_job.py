"""Background scan job ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class ScanJob(BaseModel):
    __tablename__ = "scan_jobs"

    job_type: Mapped[str] = mapped_column(String(50), nullable=False, default="MANUAL")
    target_repo: Mapped[str] = mapped_column(Text, nullable=False)
    target_commit: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target_branch: Mapped[str] = mapped_column(String(200), nullable=False, default="main")
    triggered_by: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="QUEUED")
    scan_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    progress: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    @property
    def job_id(self) -> str:
        return self.id
