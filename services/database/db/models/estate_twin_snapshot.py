"""Persisted Digital Twin snapshots (spec 94 §14, §19).

A twin snapshot is the estate *as it was observed*, with the evidence that
supports it. Until now a snapshot only existed implicitly inside an
``estate-discovery`` scan run, which meant:

* history was limited to estate-discovery runs — a snapshot could not be captured
  from an imported CMDB register, a vendor questionnaire or a manual collection;
* two runs of identical evidence were two rows, and "did anything change?" was a
  question about timestamps rather than about evidence.

This table fixes both. The identity of a snapshot is its **projection id** (a hash
over assets, relationships, evidence content and collector outcomes), so:

* re-capturing identical evidence updates ``last_seen_at`` and ``observations``
  instead of inserting a duplicate;
* two snapshots are comparable exactly when their payloads describe the same
  evidence;
* the payload is stored whole, so a comparison years later does not depend on the
  code that produced it — or on the scan runs still being in retention.

What is deliberately **not** stored: simulation runs. A simulation is a question
asked of a copy; persisting it next to observations would let a "what if" be read
back later as something that happened.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class EstateTwinSnapshot(BaseModel, TenantScoped):
    """One content-addressed view of the estate, with the evidence behind it."""

    __tablename__ = "estate_twin_snapshots"
    __table_args__ = (
        Index("ix_estate_twin_snapshots_tenant_projection", "tenant_id", "projection_id", unique=True),
        Index("ix_estate_twin_snapshots_last_seen", "last_seen_at"),
    )

    # the tenant_id column (and its ORM guard) come from TenantScoped
    estate: Mapped[Optional[str]] = mapped_column(String(160))
    scope: Mapped[Optional[str]] = mapped_column(String(160))

    #: ``twin:<projection_id>`` — the id a user quotes at another user
    snapshot_id: Mapped[str] = mapped_column(String(96), nullable=False)
    projection_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    #: the whole snapshot payload: assets, evidence, relationships, collectors
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    counts: Mapped[Optional[dict]] = mapped_column(JSON)
    #: ``collector@version`` for every collector behind the evidence, so a probe upgrade is
    #: distinguishable from an estate change
    collector_versions: Mapped[Optional[list]] = mapped_column(JSON)
    #: §19 — which version of the rules (confidence table, identity keys, conflict fields)
    #: read this evidence. Two snapshots with the same projection id and different policy
    #: versions describe the same evidence judged differently
    policy_version: Mapped[Optional[str]] = mapped_column(String(80))

    assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    relationships: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unresolved_relationships: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completeness_percent: Mapped[Optional[float]] = mapped_column(Float)

    #: how many times this exact evidence has been captured, and when last
    observations: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    source_run_id: Mapped[Optional[str]] = mapped_column(String(36))
    captured_by: Mapped[Optional[str]] = mapped_column(String(160))
    note: Mapped[Optional[str]] = mapped_column(Text)
