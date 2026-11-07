"""Acceptance gate filings (gap analysis §6).

A row is filed evidence against one of the twelve product acceptance gates.
The gate logic lives in :mod:`shared_models.acceptance_gates` (external gates
are never passed by the platform or by synthetic drills); this table is the
register those rules read.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class GateFiling(BaseModel):
    __tablename__ = "gate_filings"
    __table_args__ = (
        Index("ix_gate_filing_gate_performed", "gate", "performed_at"),
    )

    gate: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    performed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    evidence_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   nullable=False)
    result: Mapped[str] = mapped_column(String(20), nullable=False,
                                        default="PASSED")
    synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False,
                                            default=False)
    note: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
