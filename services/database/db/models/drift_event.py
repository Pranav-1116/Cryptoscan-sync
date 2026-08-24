"""Drift event ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class DriftEvent(BaseModel):
    __tablename__ = "drift_events"

    baseline_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("baselines.id", ondelete="SET NULL"), nullable=True
    )
    current_scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    drift_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    drift_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    resolution_status: Mapped[str] = mapped_column(String(50), nullable=False, default="OPEN")
    resolved_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    @property
    def drift_id(self) -> str:
        return self.id
