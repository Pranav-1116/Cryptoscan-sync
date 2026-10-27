"""Scheduled compliance reports and their immutable snapshots (W55-56 items 7-8).

A schedule says "render this template against the latest completed scan of
that target, this often, and send it to these auditors". Each run stores a
snapshot — the full rendered report including its tamper hash (and PKI
signature when configured) — because an audit artifact must not change when
the live findings change underneath it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class ReportSchedule(BaseModel, TenantScoped):
    __tablename__ = "report_schedules"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    template_id: Mapped[str] = mapped_column(String(60), nullable=False)  # pci-dss-4.0, custom, ...
    requirements: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)  # custom selection
    frequency: Mapped[str] = mapped_column(String(20), nullable=False, default="quarterly")
    scan_target: Mapped[str] = mapped_column(String(500), nullable=False)  # scans.target_location
    recipients: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)  # auditor emails
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class ReportSnapshot(BaseModel, TenantScoped):
    __tablename__ = "report_snapshots"
    __table_args__ = (
        # identical (scan, payload) pins collapse to one row — the same
        # content-addressing discipline as cbom_snapshots (round 69)
        UniqueConstraint("scan_id", "payload_hash", name="uq_report_snapshot_scan_payload"),
    )

    schedule_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("report_schedules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    schedule_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)  # survives schedule deletion
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    template_id: Mapped[str] = mapped_column(String(60), nullable=False)
    report_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: SHA-256 over the canonical JSON of the EXACT stored payload (PDF,
    #: signature and the scan→BOM chain citation included) — the report leg
    #: of scan-run → BOM → report (round 69). NULL on legacy rows, which the
    #: read path reports as UNVERIFIED_LEGACY instead of pretending.
    payload_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    report: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    emailed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    email_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)  # SENT/SKIPPED_NO_SMTP/FAILED
    email_detail: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
