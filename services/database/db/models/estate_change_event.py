"""Detected changes between two observations of the estate (spec 94 §17–§18, §23).

A change event is the record that something moved between two observations, and of
what it was: the claims (``changes``), the severity consequence, the next action and
the pair of projection ids it was derived from.

Three properties make this table a monitoring record rather than a news feed:

* **it is derived, never collected.** Every claim comes from comparing two stored
  observations; nothing here was re-read from the estate to make a change look
  bigger, and the two projection ids are stored so a reader can go back to the
  evidence the claim came from;
* **identical evidence produces no row.** ``NONE`` is not stored — the discovery run
  is already the record that someone looked, and a row per quiet scan would bury the
  afternoon something moved;
* **findings are immutable; only acknowledgement moves.** ``acknowledged_at/by/note``
  are the only mutable columns, because a feed whose contents can be edited is not an
  audit trail.

The row is tenant-scoped through :class:`TenantScoped`, so a change detected in one
estate cannot be read from another.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateChangeEvent(BaseModel, TenantScoped):
    __tablename__ = "estate_change_events"
    __table_args__ = (
        Index("ix_estate_change_events_tenant_event", "tenant_id", "event_id", unique=True),
        Index("ix_estate_change_events_severity_created", "severity", "created_at"),
    )

    #: deterministic: sha256(baseline|current|verdict) — a replay cannot duplicate it
    event_id: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    verdict: Mapped[str] = mapped_column(String(40), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    changed: Mapped[Optional[bool]] = mapped_column(Boolean)
    headline: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text)
    next_action: Mapped[Optional[str]] = mapped_column(Text)

    #: one entry per thing that moved: kind, subject, before, after, detail, means
    changes: Mapped[Optional[list]] = mapped_column(JSON)
    counts: Mapped[Optional[dict]] = mapped_column(JSON)

    baseline_projection_id: Mapped[Optional[str]] = mapped_column(String(64))
    current_projection_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(64))
    trigger: Mapped[str] = mapped_column(String(40), nullable=False, default="manual")
    detected_by: Mapped[Optional[str]] = mapped_column(String(160))

    observations: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_detected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[Optional[str]] = mapped_column(String(160))
    acknowledgement_note: Mapped[Optional[str]] = mapped_column(Text)
