"""Versioned tenant-scoped network inventory snapshots."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class NetworkInventoryRevision(BaseModel, TenantScoped):
    __tablename__ = "network_inventory_revisions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "inventory_id", "revision", name="uq_network_inventory_revision"),
    )

    inventory_id: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(nullable=False)
    schema_version: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="DRAFT", index=True)
    source: Mapped[str] = mapped_column(String(80), nullable=False, default="MANUAL")
    inventory_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    completeness_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    captured_at: Mapped[datetime] = mapped_column(nullable=False)
    created_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(160), nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dict(self, exclude: set[str] | None = None) -> dict:
        data = super().to_dict(exclude=exclude)
        data["inventory"] = data.pop("inventory_json", None)
        data["completeness"] = data.pop("completeness_json", None)
        return data
