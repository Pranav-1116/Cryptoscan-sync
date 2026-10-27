"""Vendor crypto inventory discovered via questionnaire, SBOM, docs, or API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class VendorCryptoInventory(BaseModel, TenantScoped):
    __tablename__ = "vendor_crypto_inventory"

    vendor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    crypto_use_case: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    algorithm: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    mode: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    key_management: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    pqc_ready: Mapped[bool] = mapped_column(Boolean, default=False)
    discovery_method: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    confidence: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    discovered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    source_document: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
