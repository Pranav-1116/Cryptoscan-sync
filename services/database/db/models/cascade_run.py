"""Persisted cross-BOM cascade runs.

Every "what breaks if X changes?" answer is a snapshot of the estate at the
moment it was asked — dependency edges move, certificates renew, vendors
change. Storing the run makes the answer reproducible for an audit trail:
the verdict, the layers and the honest unknowns are kept exactly as
returned, alongside who asked and over how many hops the blast radius was
allowed to propagate.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CascadeRun(BaseModel, TenantScoped):
    __tablename__ = "cascade_runs"

    target: Mapped[str] = mapped_column(String(500), nullable=False)
    target_kind: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    verdict: Mapped[str] = mapped_column(String(30), nullable=False)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
