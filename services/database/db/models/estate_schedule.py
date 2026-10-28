"""Saved schedules for the estate discovery job (spec 93 §18).

A scheduled run is not "call the API every N minutes from cron(8)". The schedule
lives in the database, the tick claims it with a lease so two workers cannot run
the same schedule twice, and the outcome of every run is recorded next to the
schedule — including the verdict, because a schedule that silently runs a
PARTIAL_COVERAGE estate every night is exactly the failure this is meant to make
visible.

Two cadence forms are supported, and no more:

* ``interval_minutes`` — "every 6h" (fixed spacing from the previous run);
* ``cron`` — a five-field UTC expression (``0 2 * * *``). Cron is accepted because
  operators think in it; UTC-only is stated rather than inherited silently from
  the host clock, so a DST change never moves an audit run by an hour.

A schedule whose run raises still advances: a broken connector must not pin
``next_run_at`` in the past and spin.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateSchedule(BaseModel, TenantScoped):
    """One saved "re-run the estate job this often" entry."""

    __tablename__ = "estate_schedules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_estate_schedule_tenant_name"),
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(80), nullable=False, default="production")
    estate: Mapped[str] = mapped_column(String(120), nullable=False, default="default")
    #: JSON list of plane names; NULL means every plane
    planes: Mapped[Optional[str]] = mapped_column(String(600), nullable=True)

    interval_minutes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    cron: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    last_verdict: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    last_coverage_state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: worker id holding the lease, and until when — the single-writer guarantee
    claimed_by: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    claimed_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)


class EstateScheduleRun(BaseModel, TenantScoped):
    """One execution of a schedule, kept so "it ran" is checkable afterwards."""

    __tablename__ = "estate_schedule_runs"

    schedule_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("estate_schedules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)  # OK | ERROR | SKIPPED
    estate_run_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    verdict: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    coverage_state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    detail: Mapped[Optional[str]] = mapped_column(String(800), nullable=True)
    worker: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
