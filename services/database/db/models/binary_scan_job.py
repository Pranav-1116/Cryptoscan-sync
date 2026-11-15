"""Durable binary scan job ORM model.

The database-backed artifact handoff for asynchronous Binary scans. A job row
carries the bounded artifact bytes themselves: the queue is the handoff, so a
restart of the accepting API process cannot lose an acknowledged job and any
replica's worker can claim it. Claims are lease-based with an optimistic
version counter — a stale worker completing a job the reaper already requeued
cannot silently overwrite the verdict (the same compare-and-set discipline as
``scan_jobs.version``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, Integer, JSON, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned


class BinaryScanJob(BaseModel, TenantOwned):
    __tablename__ = "binary_scan_jobs"
    __table_args__ = (
        Index("ix_binary_scan_jobs_claim", "status", "lease_expires_at"),
        Index("ix_binary_scan_jobs_tenant_page", "tenant_id", "created_at", "id"),
    )

    #: The queue-visible id (``bjob-…``) — stable across the API and workers.
    job_id: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="QUEUED")
    #: Bounded artifact bytes; the queue refuses anything above the worker's
    #: declared limit rather than storing it unbounded.
    artifact_bytes: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    artifact_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(40), nullable=False, default="upload")
    source_location: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    uploaded_by: Mapped[str] = mapped_column(String(100), nullable=False)
    profile: Mapped[str] = mapped_column(String(40), nullable=False, default="standard")
    #: Submitting request's trace id — the job outlives its HTTP request, so
    #: the identity rides the row (0158) and the worker reads it back.
    trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    #: Optimistic-lock counter: every status transition is a compare-and-set on
    #: the version it read.
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    claimed_by: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    #: The persisted run summary (status, scan_id, finding_count, timings).
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
