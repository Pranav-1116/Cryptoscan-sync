"""Live hardware state ORM models (24/7 hardware spec §3).

The database is the current truth of the observed environment: asset state,
the immutable event journal (which reconstructs any past state, §16) and
edge-agent heartbeat health (§4).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from db.models.base import BaseModel


class HardwareAsset(BaseModel):
    __tablename__ = "hardware_assets"

    asset_id: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    manufacturer: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    model: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    device_type: Mapped[str] = mapped_column(String(50), nullable=False, default="other")
    serial_reference: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    hardware_revision: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    current_fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    previous_fingerprint: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_firmware_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_crypto_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_change: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    firmware: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    tpm: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    hsm: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    capabilities: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    crypto_capabilities: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    previous_state: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    evidence_history: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    risk_score: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    def state_dict(self) -> dict:
        data = self.to_dict()
        for key in ("id", "created_at", "updated_at"):
            data.pop(key, None)
        return data


class HardwareEventRow(BaseModel):
    """Immutable hardware event journal entry (§2, §16)."""

    __tablename__ = "hardware_events"

    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    change_class: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    state_verdict: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    evidence_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    def event_dict(self) -> dict:
        data = self.to_dict()
        data["observed_at"] = self.observed_at.isoformat() if self.observed_at else None
        return data


class HardwareAgentRow(BaseModel):
    """Edge-agent heartbeat health (§4)."""

    __tablename__ = "hardware_agents"

    agent_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    last_heartbeat: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_successful_discovery: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_crypto_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_firmware_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    event_queue_depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_lag_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    agent_health: Mapped[str] = mapped_column(String(20), nullable=False, default="HEALTHY")
    agent_status: Mapped[str] = mapped_column(String(20), nullable=False, default="ONLINE")
    hardware_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)

    def agent_dict(self) -> dict:
        data = self.to_dict()
        for key in ("id", "created_at", "updated_at"):
            data.pop(key, None)
        for key in ("last_heartbeat", "last_successful_discovery",
                    "last_crypto_check", "last_firmware_check"):
            value = getattr(self, key, None)
            data[key] = value.isoformat() if value else None
        return data
