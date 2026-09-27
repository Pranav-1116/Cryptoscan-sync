"""Where a certificate is observed (endpoint, PEM path, k8s secret)."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CertificateUsage(BaseModel, TenantScoped):
    __tablename__ = "certificate_usages"
    __table_args__ = (
        UniqueConstraint("fingerprint_sha256", "location", name="uq_cert_usage_location"),
    )

    fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    usage_type: Mapped[str] = mapped_column(String(40), nullable=False, default="UNKNOWN")
    location: Mapped[str] = mapped_column(String(400), nullable=False)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
