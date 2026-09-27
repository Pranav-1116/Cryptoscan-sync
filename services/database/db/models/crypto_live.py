"""Live crypto state ORM models (§34/§35 of the Universal Crypto Scanner).

The database is the current truth of the live crypto environment:
``crypto_live_states`` — current state (algorithms, quantum status,
readiness, agility, risk, versioned CBOM); ``crypto_live_events`` — the
immutable event journal (timeline + point-in-time reconstruction).

Never stores key material — only metadata and the CBOM (which itself
carries only algorithm identifiers per the CycloneDX cryptography registry).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel
from db.tenancy import TenantScoped


class CryptoLiveState(BaseModel, TenantScoped):
    __tablename__ = "crypto_live_states"

    asset_id: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    cbom_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    algorithms: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    quantum_status: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    capabilities: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    usage: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    protocols: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    certificates: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    libraries: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    readiness: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    agility: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cbom: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    last_event: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def state_dict(self) -> dict:
        data = self.to_dict()
        for key in ("id", "created_at", "updated_at"):
            data.pop(key, None)
        data["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return data


class CryptoLiveEventRow(BaseModel, TenantScoped):
    """Immutable live-crypto event journal entry (§34 timeline)."""

    __tablename__ = "crypto_live_events"

    event_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="live")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    cbom_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    def event_dict(self) -> dict:
        data = self.to_dict()
        data["observed_at"] = self.observed_at.isoformat() if self.observed_at else None
        return data
