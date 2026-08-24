"""Many-to-many link between systems and crypto assets."""

from __future__ import annotations

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.models.base import BaseModel


class SystemAsset(BaseModel):
    __tablename__ = "system_assets"
    __table_args__ = (UniqueConstraint("system_id", "asset_id", name="uq_system_asset"),)

    system_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("systems.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("crypto_assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    system = relationship("System", back_populates="assets")
    asset = relationship("CryptoAsset")
