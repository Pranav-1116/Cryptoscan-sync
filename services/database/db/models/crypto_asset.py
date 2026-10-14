"""Deduplicated cryptographic asset."""

from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, Integer, JSON, String, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CryptoAsset(BaseModel, TenantScoped):
    __tablename__ = "crypto_assets"
    __table_args__ = (
        Index("ix_assets_algorithm_file", "algorithm", "file_path"),
    )

    algorithm: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    purpose: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    mode: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    key_size: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    # §4.2 identity spine (round 57): the ONE canonical durable identity —
    # shared/shared_models/asset_identity.py — same string for the evidence
    # row, the fact row and the BOM component of this asset. Nullable only
    # for pre-0092 rows until the backfill/maintenance path converges them.
    asset_key: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_language: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    is_hardcoded_key: Mapped[bool] = mapped_column(Boolean, default=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    scanner_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    libraries: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # lifecycle (audit 54): DISCOVERED -> VERIFIED -> ACTIVE -> DEPRECATED ->
    # RETIRED. Transitions are enforced by the inventory router's rules table;
    # DISCOVERED is the only state the pipeline ever writes on its own.
    lifecycle_state: Mapped[str] = mapped_column(
        String(20), nullable=False, default="DISCOVERED", server_default="DISCOVERED")

    # direct ownership (audit 55 P0#3, round 27): an asset without a system
    # link used to have no owner at all. Free-form identity strings — the
    # same convention as System.technical_owner / security_owner (round 19).
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    technical_owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    security_owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    evidence_links = relationship(
        "CryptoAssetEvidence",
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="select",
    )
