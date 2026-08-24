"""Link table between crypto assets and evidence records."""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class CryptoAssetEvidence(BaseModel):
    __tablename__ = "crypto_asset_evidence"
    __table_args__ = (UniqueConstraint("asset_id", "evidence_id", name="uq_asset_evidence"),)

    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("crypto_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    evidence_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("evidence_records.id", ondelete="CASCADE"), nullable=False, index=True
    )

    asset = relationship("CryptoAsset", back_populates="evidence_links")
