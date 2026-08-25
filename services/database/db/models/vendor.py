"""External vendor that a system depends on."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class Vendor(BaseModel):
    __tablename__ = "vendors"

    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    criticality: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    extra: Mapped[Optional[str]] = mapped_column(String(400), nullable=True)


class SystemVendor(BaseModel):
    __tablename__ = "system_vendors"
    __table_args__ = (UniqueConstraint("system_id", "vendor_id", name="uq_system_vendor"),)

    system_id: Mapped[str] = mapped_column(String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False)
    vendor_id: Mapped[str] = mapped_column(String(36), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False)
    dependency_type: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
