"""Cryptographic fact rows (advanced/51 P0#1 write-side step, round 35).

The first materialised piece of the fact/evidence separation: one row per
cryptographic *fact* — (algorithm, purpose, file, key size, mode) — with
observation counters and the exact evidence ids behind it. Evidence rows
stay the immutable append-only truth; fact rows are the derived,
rebuildable store that the 51 rearchitecture reads from. Any fact row can
be recomputed from evidence at any time (`FactRepository.rebuild`), which
is what makes this a safe migration step rather than a second source of
truth that can drift.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CryptographicFact(TenantScoped, BaseModel):
    __tablename__ = "cryptographic_facts"
    __table_args__ = (
        UniqueConstraint(
            "algorithm", "purpose", "file_path", "key_size", "mode",
            name="uq_fact_identity",
        ),
        Index("ix_facts_algorithm", "algorithm"),
        Index("ix_facts_file", "file_path"),
    )

    algorithm: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    purpose: Mapped[str | None] = mapped_column(String(50), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text(), nullable=True)
    key_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mode: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # observation rollups — recomputed from evidence, never hand-edited
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scanners: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # observed confidence values (round 37) — the last field the live
    # projection carried that the store lacked; with it, a store row is
    # exactly equivalent to a live-projected fact
    confidences: Mapped[list | None] = mapped_column(JSON, nullable=True)
    hardcoded_key_observations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # rebuild bookkeeping: which evidence generation produced these numbers
    rebuilt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
