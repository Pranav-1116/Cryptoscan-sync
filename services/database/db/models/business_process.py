"""Revenue-bearing business process."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Float, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class BusinessProcess(BaseModel):
    __tablename__ = "business_processes"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    process_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    revenue_daily: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    customer_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sla_uptime: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    executive_sponsor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    data_classifications: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
