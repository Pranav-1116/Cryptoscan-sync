"""Retired-asset registry for reintroduction detection (audit 69 / GAP-023).

When weak crypto is deliberately retired (removed, replaced, exceptioned),
the retirement is registered here. Every scan can then be checked against
the registry: a retired algorithm reappearing at a retired location is a
reintroduction — detected, severity-rated, and alerted, not silently
re-discovered as a brand-new finding.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class RetiredAsset(BaseModel, TenantScoped):
    __tablename__ = "retired_assets"

    __table_args__ = (
        Index("ix_retired_assets_algorithm", "algorithm"),
        Index("ix_retired_assets_active", "active"),
    )

    # normalized algorithm name the retirement covers (e.g. DES, RC4, MD5)
    algorithm: Mapped[str] = mapped_column(String(80), nullable=False)
    # FILE  — the algorithm must not reappear at this location
    # ASSET — the algorithm must not reappear on this deduplicated asset
    # ALGORITHM — the algorithm must not reappear anywhere in the estate
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="FILE")
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # optional provenance: the remediation task whose VERIFIED result retired it
    source_task_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    retired_by: Mapped[str] = mapped_column(String(100), nullable=False, default="system")
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # lifted retirements stay in the registry for the audit trail but stop matching
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    lifted_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
