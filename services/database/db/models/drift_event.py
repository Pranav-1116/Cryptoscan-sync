"""Drift event ORM model."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class DriftEvent(BaseModel, TenantScoped):
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
    # Acknowledgment is not resolution (report 31 §5): an auditor has seen
    # the event and taken ownership, the fix is still pending. Timestamps are
    # nullable by design — rows acknowledged before this column existed have
    # an unknown acknowledge time, surfaced honestly by the SLA endpoint.
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resolved_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # §4.7 (round 40): condition-level verification, computed from a LATER
    # scan's evidence — never set by hand, never a substitute for RESOLVED.
    # VERIFIED = the rescan observed the file and the condition is gone;
    # CONDITION_PRESENT = the administrative closure closed nothing.
    # NULL = not (yet) verified by any rescan.
    verification_status: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    verified_by_scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    @property
    def drift_id(self) -> str:
        return self.id
