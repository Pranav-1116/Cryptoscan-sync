"""Crypto migration project tracker."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, JSON, String, Text
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


class MigrationTask(BaseModel):
    """One concrete migration unit inside a project (asset/site to move)."""

    __tablename__ = "migration_tasks"

    project_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    system_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    algorithm_from: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    algorithm_to: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    priority: Mapped[str] = mapped_column(String(4), nullable=False, default="P2")
    effort: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    # TODO | IN_PROGRESS | DONE | SKIPPED | BLOCKED
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="TODO")
    blocked_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # AUTO | MANUAL | GITHUB | JIRA — provenance of this task/its status
    source: Mapped[str] = mapped_column(String(10), nullable=False, default="MANUAL")
    external_ref: Mapped[Optional[str]] = mapped_column(String(300), nullable=True, index=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class MigrationMilestone(BaseModel):
    """Timeline anchor for a project; status is recomputed from progress."""

    __tablename__ = "migration_milestones"

    project_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # PLANNED | AT_RISK | ACHIEVED | MISSED
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PLANNED")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
