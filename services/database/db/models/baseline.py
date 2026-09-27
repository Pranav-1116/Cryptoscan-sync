"""Approved baseline for drift detection."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class Baseline(BaseModel, TenantScoped):
    __tablename__ = "baselines"

    system_identifier: Mapped[str] = mapped_column(String(400), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(50), nullable=False, default="default")
    approved_scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    approved_by: Mapped[str] = mapped_column(String(100), nullable=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    @property
    def baseline_id(self) -> str:
        return self.id
