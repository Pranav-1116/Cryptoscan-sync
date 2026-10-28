"""Liveness records for the 24/7 estate daemon (spec 93 §18).

A monitoring product has to be able to answer "is anything actually running?"
about *itself*. The alternative — trusting a log line, or an uptime monitor that
only proves the API process answered a request — is how a bank ends up with a
console showing last week's coverage while nothing has scanned since Tuesday.

One row per daemon identity (``id`` is the worker name, which the heartbeat
upserts). The fields are chosen so an operator can distinguish the three states
that matter without reading logs:

* ``LIVE`` — ``last_cycle_at`` is recent;
* ``STALE`` — a daemon registered but its last cycle is old (it died, was
  suspended, or its host vanished);
* ``NEVER_STARTED`` — no row at all: nothing is running the schedules.

``state`` also carries ``STOPPED`` after a graceful shutdown, so a clean stop is
never mistaken for a crash. ``idle_reason`` records why nothing ran — "no enabled
schedule" is an honest answer, and a very different one from "nothing was due".
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class EstateDaemon(BaseModel):
    """The last known heartbeat of one estate daemon process."""

    __tablename__ = "estate_daemons"

    worker: Mapped[str] = mapped_column(String(120), nullable=False, unique=True, index=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="RUNNING")
    version: Mapped[Optional[str]] = mapped_column(String(40))
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_cycle_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), index=True)
    last_cycle_seconds: Mapped[Optional[float]] = mapped_column()
    cycles: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    runs: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    next_wake_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    idle_reason: Mapped[Optional[str]] = mapped_column(Text)
    pid: Mapped[Optional[int]] = mapped_column(Integer)
