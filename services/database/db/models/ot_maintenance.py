"""OT/ICS maintenance-window model (deterministic safety control, no AI).

A maintenance window is an approved, time-bounded authorization to perform
active/intrusive operations against operational equipment. Passive scanning
never needs one. Windows are stored but never trust the client clock for the
enforcement decision — the ot_safety policy evaluates wall-clock server time.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class OtMaintenanceWindow(BaseModel):
    __tablename__ = "ot_maintenance_windows"

    window_ref: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    #: comma-separated device ids; may be empty when scoped by zone/site
    device_ids: Mapped[str | None] = mapped_column(Text, nullable=True)
    zones: Mapped[str | None] = mapped_column(Text, nullable=True)
    sites: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: observe | interact | change
    allowed_action_class: Mapped[str] = mapped_column(String(20), nullable=False, default="interact")
    approved_by: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    change_ticket: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    requested_by: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    #: approved windows are only created through the approval-gated endpoint
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="APPROVED", index=True)
    operations: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_cancelled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    def _split(self, raw: str | None) -> list[str]:
        if not raw:
            return []
        return [x.strip() for x in str(raw).replace(";", ",").split(",") if x.strip()]

    def to_policy_dict(self) -> dict:
        return {
            "id": self.window_ref,
            "starts_at": self.starts_at,
            "ends_at": self.ends_at,
            "device_ids": self._split(self.device_ids),
            "zones": self._split(self.zones),
            "sites": self._split(self.sites),
            "allowed_action_class": self.allowed_action_class,
            "approved_by": self.approved_by,
            "change_ticket": self.change_ticket,
            "operations": self._split(self.operations) or None,
        }

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "window_ref": self.window_ref,
            "title": self.title,
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "ends_at": self.ends_at.isoformat() if self.ends_at else None,
            "device_ids": self._split(self.device_ids),
            "zones": self._split(self.zones),
            "sites": self._split(self.sites),
            "allowed_action_class": self.allowed_action_class,
            "approved_by": self.approved_by,
            "change_ticket": self.change_ticket,
            "requested_by": self.requested_by,
            "status": self.status,
            "is_cancelled": self.is_cancelled,
        }
