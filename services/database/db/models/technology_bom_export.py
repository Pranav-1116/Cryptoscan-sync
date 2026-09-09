"""Scheduled Technology BOM exports and their immutable runs (spec: scheduled exports).

A schedule captures *how often* to export the unified BOM (daily / weekly /
monthly / after scan / after major change), which format + layer + filters to
render, and where it goes. Each ``run`` stores the full downloadable artifact
(base64), its content hash, its HMAC signature and the audit event id — because
an audit artifact must not change when the live state changes underneath it.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel

VALID_FREQUENCIES = ("daily", "weekly", "monthly", "after_scan", "after_major_change")


class TechnologyBomExportSchedule(BaseModel):
    __tablename__ = "technology_bom_export_schedules"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    frequency: Mapped[str] = mapped_column(String(32), nullable=False, default="weekly")
    fmt: Mapped[str] = mapped_column(String(32), nullable=False, default="json")
    layer: Mapped[str] = mapped_column(String(32), nullable=False, default="all")
    filters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    environment: Mapped[str] = mapped_column(String(100), nullable=False, default="default")
    recipients: Mapped[list | None] = mapped_column(JSON, nullable=True)  # auditor emails
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_snapshot_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "frequency": self.frequency,
            "fmt": self.fmt,
            "layer": self.layer,
            "filters": self.filters or {},
            "environment": self.environment,
            "recipients": self.recipients or [],
            "active": self.active,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "last_snapshot_id": self.last_snapshot_id,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TechnologyBomExportRun(BaseModel):
    __tablename__ = "technology_bom_export_runs"

    schedule_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("technology_bom_export_schedules.id", ondelete="SET NULL"),
        nullable=True, index=True)
    schedule_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    snapshot_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(100), nullable=False, default="default")
    fmt: Mapped[str] = mapped_column(String(32), nullable=False)
    layer: Mapped[str] = mapped_column(String(32), nullable=False, default="all")
    filters: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    total_components: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    signature_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    artifact_b64: Mapped[str | None] = mapped_column(Text, nullable=True)  # base64 body
    mime_type: Mapped[str | None] = mapped_column(String(80), nullable=True)
    audit_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    trigger: Mapped[str | None] = mapped_column(String(32), nullable=True)  # schedule/manual

    def to_dict(self, *, include_artifact: bool = False) -> dict:
        d = {
            "schedule_id": self.schedule_id,
            "schedule_name": self.schedule_name,
            "version": self.version,
            "snapshot_id": self.snapshot_id,
            "environment": self.environment,
            "fmt": self.fmt,
            "layer": self.layer,
            "filters": self.filters or {},
            "total_components": self.total_components,
            "content_sha256": self.content_sha256,
            "signature_hmac": self.signature_hmac,
            "mime_type": self.mime_type,
            "audit_event_id": self.audit_event_id,
            "trigger": self.trigger,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_artifact:
            d["artifact_b64"] = self.artifact_b64
        return d
