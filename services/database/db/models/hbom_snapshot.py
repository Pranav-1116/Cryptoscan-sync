"""Persisted, content-addressed HBOM snapshots (§4.4, round 71).

Mirrors the pinning discipline of ``cbom_snapshots`` (round 45) and
``report_snapshots`` (round 69) for the independent estate HBOM: the
exact generated document is stored verbatim, content-addressed by
SHA-256 over its canonical serialization, served back verbatim with an
integrity self-check — never regenerated.

Differences from the CBOM leg, both deliberate:

* **no scan foreign key** — the HBOM is an ESTATE document (the whole
  ``hardware_assets`` truth), not the rendering of one scan run;
* **environment-keyed uniqueness** — ``uq_hbom_snapshot_tenant_env_hash``
  includes ``tenant_id`` and ``environment`` so identical documents
  pinned by different tenants (or in different environments) stay
  separate rows while identical re-pins collapse idempotently.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class HbomSnapshot(BaseModel, TenantScoped):
    __tablename__ = "hbom_snapshots"
    __table_args__ = (
        UniqueConstraint("tenant_id", "environment", "content_hash",
                         name="uq_hbom_snapshot_tenant_env_hash"),
    )

    #: environment label the pinned estate document belongs to
    environment: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    #: SHA-256 hex over the canonical serialization of the stored payload
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: serialization format of the stored payload ("json")
    format: Mapped[str] = mapped_column(String(10), nullable=False, default="json")
    #: which surface produced the rendering (api | pipeline)
    generator: Mapped[str] = mapped_column(String(30), nullable=False, default="api")
    #: the exact generated document — served verbatim, never regenerated
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    snapshotted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    #: the document's own deterministic anchor (latest last_seen), if any
    as_of: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)

    def to_dict(self, exclude: set[str] | None = None) -> dict:
        exclude = (exclude or set()) | {"payload"}
        data = super().to_dict(exclude=exclude)
        for key in ("snapshotted_at", "created_at", "updated_at"):
            value = data.get(key)
            if hasattr(value, "isoformat"):
                data[key] = value.isoformat()
        return data
