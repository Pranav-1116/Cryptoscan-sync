"""CI gate evaluation records — the blocked-deployments trail."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class GateEvaluation(BaseModel, TenantScoped):
    """One CI gate call: what was evaluated, by whom, and the decision.

    Written by POST /ci/gate so "blocked deployments" are countable after
    the fact; never affects the decision itself (logging is fail-open).
    """

    __tablename__ = "gate_evaluations"

    scan_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    profile: Mapped[str] = mapped_column(String(20), nullable=False, default="standard")
    decision: Mapped[str] = mapped_column(String(10), nullable=False)
    blocking_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
