"""Directed system-to-system dependency (Part 2: simple edges only)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class SystemDependency(BaseModel, TenantScoped):
    __tablename__ = "system_dependencies"
    __table_args__ = (UniqueConstraint("parent_id", "child_id", name="uq_system_dep"),)

    parent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)

    parent = relationship("System", foreign_keys=[parent_id], back_populates="outgoing")
    child = relationship("System", foreign_keys=[child_id])
