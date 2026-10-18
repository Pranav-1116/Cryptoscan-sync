"""Directed system-to-system dependency (Part 2: simple edges only)."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel
from db.tenancy import TenantScoped
from db.models.relationship_lifecycle import RelationshipLifecycle


class SystemDependency(BaseModel, TenantScoped, RelationshipLifecycle):
    __tablename__ = "system_dependencies"
    __table_args__ = (UniqueConstraint("parent_id", "child_id", name="uq_system_dep"),)

    parent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    child_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    # provenance: where this edge came from and who vouches for it. Edges
    # were previously bare (parent, child, relation) — nothing said whether
    # a human registered them, a scanner discovered them, or an import
    # created them, and nothing recorded when they were last confirmed.
    source: Mapped[str] = mapped_column(
        String(20), nullable=False, default="manual")  # manual|discovered|imported
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    evidence_ref: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    confidence_meaning: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    operational_dependency: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_verified: Mapped[Optional[object]] = mapped_column(
        DateTime(timezone=True), nullable=True)

    parent = relationship("System", foreign_keys=[parent_id], back_populates="outgoing")
    child = relationship("System", foreign_keys=[child_id])
