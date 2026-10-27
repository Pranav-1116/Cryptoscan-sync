"""Versioned, append-only vendor due-diligence profile revisions."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class VendorProfileRevision(BaseModel, TenantScoped):
    __tablename__ = "vendor_profile_revisions"
    __table_args__ = (
        UniqueConstraint("vendor_id", "revision", name="uq_vendor_profile_revision"),
    )

    vendor_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    revision: Mapped[int] = mapped_column(nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT", index=True)
    source: Mapped[str] = mapped_column(String(120), nullable=False, default="operator")
    profile_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    completeness_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dict(self, exclude: set[str] | None = None) -> dict:
        data = super().to_dict(exclude=exclude)
        data["profile"] = data.pop("profile_json", None)
        data["completeness"] = data.pop("completeness_json", None)
        return data
