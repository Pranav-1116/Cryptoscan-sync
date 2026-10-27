"""OT/ICS devices and passive crypto observations."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class OtDevice(BaseModel):
    __tablename__ = "ot_devices"

    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    firmware_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocols_observed: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    criticality: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    findings = relationship(
        "OtCryptoFinding",
        back_populates="device",
        cascade="all, delete-orphan",
        lazy="select",
    )


class OtCryptoFinding(BaseModel):
    __tablename__ = "ot_crypto_findings"

    device_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("ot_devices.id", ondelete="CASCADE"), nullable=True, index=True
    )
    protocol: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    crypto_config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    has_crypto: Mapped[bool] = mapped_column(Boolean, default=False)
    security_level: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    vulnerabilities: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    observed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    compliance_issue: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    device = relationship("OtDevice", back_populates="findings")
