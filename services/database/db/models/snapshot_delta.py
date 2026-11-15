"""Incremental scan snapshots: deltas between snapshots, not copies of them.

Continuous scanning re-observes the same estate every run (spec 2.1):
Monday's RSA-2048 is still there on Tuesday. A snapshot that repeats the
whole estate every run multiplies storage; a snapshot that records **what
changed** and references what did not does not.

``snapshot_deltas`` stores:

* ``delta_content_sha256`` — the compressed difference (added items,
  removed items, changed items) in the content-addressed store.
* ``unchanged_refs`` — content hashes of items unchanged since the base
  snapshot. Reference-based storage: multiple BOMs/snapshots reference the
  same shared evidence; the bytes exist once.

A snapshot with ``base_snapshot_id = NULL`` is a full baseline; every
later snapshot chains to one. History is preserved by never rewriting a
stored delta (a changed cryptographic configuration links a NEW
observation to the historical state; it never overwrites it).
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import BigInteger, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantOwned


class SnapshotDelta(BaseModel, TenantOwned):
    """One snapshot's difference against its base snapshot."""

    __tablename__ = "snapshot_deltas"
    __table_args__ = (
        Index("uq_snapshot_deltas_tenant_snapshot", "tenant_id", "snapshot_id", unique=True),
        Index("ix_snapshot_deltas_tenant_base", "tenant_id", "base_snapshot_id"),
    )

    #: The snapshot this delta materializes (scan id, CBOM snapshot id …).
    snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The snapshot this one is a difference against. NULL = full baseline.
    base_snapshot_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    #: What kind of snapshot (scan | cbom | estate | …).
    snapshot_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="scan")
    #: Content address of the compressed delta document (added / removed /
    #: changed item keys with their new content hashes).
    delta_content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Counts kept in metadata so monitoring never decompresses deltas.
    added_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    removed_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    changed_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    unchanged_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    #: Content hashes of items carried forward unchanged from the base —
    #: shared references, stored once across every snapshot that uses them.
    unchanged_refs: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
