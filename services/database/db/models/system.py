"""Business / technical system that owns cryptographic assets."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, JSON, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class System(BaseModel):
    __tablename__ = "systems"
    __table_args__ = (
        Index("ix_systems_agility_score", "current_agility_score"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    environment: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    compliance_scopes: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    current_agility_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    agility_category: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    migration_readiness_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    migration_readiness_category: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    scan_target: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_branch: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    last_scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    coverage_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    business_unit: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    criticality: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cloud_provider: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    cloud_account: Mapped[Optional[str]] = mapped_column(String(200), nullable=True, index=True)

    assets = relationship(
        "SystemAsset",
        back_populates="system",
        cascade="all, delete-orphan",
        lazy="select",
    )
    outgoing = relationship(
        "SystemDependency",
        foreign_keys="SystemDependency.parent_id",
        back_populates="parent",
        cascade="all, delete-orphan",
        lazy="select",
    )
