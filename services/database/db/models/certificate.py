"""X.509 certificate inventory, deduped by SHA-256 fingerprint."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class Certificate(BaseModel):
    __tablename__ = "certificates"

    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    subject: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    issuer: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    not_before: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    not_after: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    public_key_algorithm: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    public_key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expiry_status: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    days_until_expiry: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_self_signed: Mapped[bool] = mapped_column(Boolean, default=False)
    san: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    usages: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    revocation_status: Mapped[Optional[str]] = mapped_column(String(30), nullable=True)
    revocation_method: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    revocation_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    ocsp_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    crl_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # Renewal workflow: NONE (not started) | PLANNED | IN_PROGRESS | DONE
    renewal_status: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, default="NONE")
    renewal_ticket: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    renewal_note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    renewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
