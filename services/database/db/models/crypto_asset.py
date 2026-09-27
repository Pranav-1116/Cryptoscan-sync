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
    line_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_language: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    is_hardcoded_key: Mapped[bool] = mapped_column(Boolean, default=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    scanner_ids: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    libraries: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    extra: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    evidence_links = relationship(
        "CryptoAssetEvidence",
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="select",
    )
