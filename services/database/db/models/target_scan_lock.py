"""Target-scoped scan lock: one job per target at a time (§10).

Two workers scanning the same target duplicate findings and race on
shared state. The lock is a single row per (tenant, target): acquired by
compare-and-set, stealable when the holder's lease expired (a worker that
died mid-scan must not wedge its target forever), released after the run.

The tenant is part of the identity: two tenants scanning the same repo
string are independent estates and never contend — tenant isolation is
enforced here and by RLS (migration 0159), not assumed from a key.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class TargetScanLock(BaseModel, TenantScoped):
    __tablename__ = "target_scan_locks"
    __table_args__ = (
        Index("uq_target_scan_locks_tenant_target", "tenant_id", "target_key",
              unique=True),
    )

    target_key: Mapped[str] = mapped_column(String(200), nullable=False)
    owner: Mapped[str] = mapped_column(String(100), nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True)
