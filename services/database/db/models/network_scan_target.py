"""Scheduled TLS probe targets."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class NetworkScanTarget(BaseModel, TenantScoped):
    __tablename__ = "network_scan_targets"

    endpoint: Mapped[str] = mapped_column(String(300), nullable=False, unique=True, index=True)
    system_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    scan_frequency: Mapped[str] = mapped_column(String(20), nullable=False, default="daily")
    # Provenance: who put this target into the due-scan rotation —
    # "onboarding" (declared authorized scope), "subnet-discovery" (an
    # operator-approved sweep's register step) or "manual" (POST
    # /network/targets). Revocation when authorized scope is removed keys on
    # this, so a scope deletion cannot disable a target an operator added by
    # hand.
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scan_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    next_scan_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
