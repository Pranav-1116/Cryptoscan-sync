"""Business / technical system that owns cryptographic assets."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class System(BaseModel):
    __tablename__ = "systems"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    environment: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    compliance_scopes: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

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
