"""Historical 6-factor crypto agility scores."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class SystemAgilityScore(BaseModel, TenantScoped):
    __tablename__ = "system_agility_scores"

    system_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    agility_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    category: Mapped[str] = mapped_column(String(20), nullable=False, default="CRITICAL")
    factor_scores: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    recommendations: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    calculated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    calculation_version: Mapped[str] = mapped_column(String(20), nullable=False, default="agility-v1.0")
    readiness_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    readiness_category: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    readiness: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
