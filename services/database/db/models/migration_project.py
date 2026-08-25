"""Crypto migration project tracker."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Float, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class MigrationProject(BaseModel):
    __tablename__ = "migration_projects"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    system_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    algorithm_from: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    algorithm_to: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="PLANNED")
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
