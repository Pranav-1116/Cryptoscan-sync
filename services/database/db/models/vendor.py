"""External vendor that a system depends on."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class Vendor(BaseModel, TenantScoped):
    __tablename__ = "vendors"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    criticality: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    extra: Mapped[Optional[str]] = mapped_column(String(400), nullable=True)
    vendor_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    contract_end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    data_classifications: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    integration_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    primary_contact: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    security_contact: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # technical contact (audit 55 P0#5, round 27): commercial + security
    # contacts existed; the party answering crypto questions did not
    technical_contact: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    last_assessment_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    extra_json: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)


class SystemVendor(BaseModel, TenantScoped):
    __tablename__ = "system_vendors"
    __table_args__ = (UniqueConstraint("system_id", "vendor_id", name="uq_system_vendor"),)

    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    vendor_id: Mapped[str] = mapped_column(String(36), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False)
    dependency_type: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
