"""Which systems support which business processes."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class SystemBusinessProcess(BaseModel):
    __tablename__ = "system_business_process_map"
    __table_args__ = (UniqueConstraint("system_id", "process_id", name="uq_system_process"),)

    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True)
    process_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("business_processes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
