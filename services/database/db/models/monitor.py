"""24/7 continuous monitoring: watch-list targets and their event feed.

A monitor target is one thing CryptoScan keeps an eye on around the clock —
a TLS endpoint set, a cloud account, a repository, a container image. The
monitor daemon ticks, runs whatever is due through the same live scanners the
manual flows use, stores a rolling summary, and records every outcome as an
event. Banks don't reboot their monitoring: the loop never dies, targets back
off on failure, and anything it cannot scan (e.g. cloud without credentials)
is reported as BLOCKED — never silently skipped.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel

# What a target's last cycle produced. PENDING = never ran.
TARGET_STATUSES = ("PENDING", "OK", "DEGRADED", "FAILING", "BLOCKED", "PAUSED")

# Supported target types; each maps to a runner in worker.monitor.runners.
TARGET_TYPES = ("NETWORK", "CLOUD", "REPO", "CONTAINER", "PAYMENT", "OT", "VENDOR", "TELECOM")


class MonitorTarget(BaseModel):
    __tablename__ = "monitor_targets"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    target_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)  # runner-specific
    interval_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=900)  # healthy rescan cadence
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING", index=True)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_summary: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class MonitorLease(BaseModel):
    """Leader lease for multi-AZ monitor daemons (exactly-one-scans).

    One row per lease name; ``holder`` + ``expires_at`` decide who may tick.
    Written via conditional UPDATE from worker.monitor.lease, not the ORM —
    the model exists so schema parity and create_all stay exact.
    """

    __tablename__ = "monitor_leases"

    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    holder: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class MonitorEvent(BaseModel):
    __tablename__ = "monitor_events"
    __table_args__ = (Index("ix_monitor_events_created_at", "created_at"),)  # realtime replay

    target_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("monitor_targets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    target_name: Mapped[str] = mapped_column(String(200), nullable=False)  # survives deletion
    event_type: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    # SCAN_OK | SCAN_DEGRADED | SCAN_FAILED | BLOCKED | ALERT | NOTE
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
