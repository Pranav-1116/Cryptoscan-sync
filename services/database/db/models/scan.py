"""Scan session ORM model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class Scan(BaseModel):
    __tablename__ = "scans"

    scan_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    scan_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    scanner_id: Mapped[str] = mapped_column(String(100), nullable=False, default="static-java-scanner-v0.1")
    scanner_version: Mapped[str] = mapped_column(String(20), nullable=False, default="0.1.0")
    target_type: Mapped[str] = mapped_column(String(50), nullable=False, default="GIT_REPOSITORY")
    target_location: Mapped[str] = mapped_column(Text, nullable=False)
    target_commit: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target_branch: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    operator: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="QUEUED")
    statistics: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    manifest_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    evidence_records = relationship(
        "EvidenceRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    @property
    def scan_id(self) -> str:
        return self.id

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.scan_end is None:
            return None
        return (self.scan_end - self.scan_start).total_seconds()

    def mark_running(self) -> None:
        self.status = "RUNNING"
        if self.scan_start is None:
            self.scan_start = datetime.now(timezone.utc)

    def mark_completed(self, manifest_hash: str | None, statistics: dict | None) -> None:
        self.status = "COMPLETED"
        self.scan_end = datetime.now(timezone.utc)
        self.manifest_hash = manifest_hash
        self.statistics = statistics

    def mark_failed(self, error_message: str) -> None:
        self.status = "FAILED"
        self.scan_end = datetime.now(timezone.utc)
        self.error_message = error_message
