"""Coverage intelligence batches: one collection run's outcomes, as filed.

:mod:`shared_models.estate_coverage` decides what the counts mean (a gap is
never "clean"; a failed read never reports zero). This table stores the filed
counts per batch so the coverage endpoint computes over real rows instead of
zeros: the batch's estate counts plus the per-plane outcome rows live together
in ``document``, because a count with no outcome rows behind it is the very
zero this model refuses to draw.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


# platform-scope: product coverage-evidence plane — filed collection-run
# outcomes for the coverage programme (a gap is never clean; a failed
# read never reports zero), not tenant inventory.
class CoverageReport(BaseModel):
    __tablename__ = "coverage_reports"
    __table_args__ = (
        Index("ix_coverage_report_captured", "captured_at"),
    )

    #: the collector run / batch this filing describes
    batch_id: Mapped[str] = mapped_column(String(80), nullable=False, unique=True,
                                          index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                  nullable=False)
    authorized_targets: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    discovered_assets: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    #: the full batch body: outcome rows + the rest of the counts
    document: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
