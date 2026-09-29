"""Live hardware repository — state, event journal, agent heartbeats.

Persistence for the 24/7 hardware engine: the ``hardware_assets`` table is
the current truth, ``hardware_events`` the immutable journal (timeline +
point-in-time reconstruction), ``hardware_agents`` the heartbeat health.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.models.hardware_live import HardwareAgentRow, HardwareAsset, HardwareEventRow
from db.repositories.base_repository import BaseRepository


def _as_dt(value: Any) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


class HardwareRepository(BaseRepository[HardwareAsset]):
    def __init__(self, session: Session):
        super().__init__(HardwareAsset, session)

    # ── assets ────────────────────────────────────────────────────────

    def upsert_asset(self, state: dict[str, Any]) -> HardwareAsset:
        """Persist a live state dict (HardwareState.to_dict) as the truth."""
        asset_id = str(state.get("asset_id") or "")
        row = self.session.execute(
            select(HardwareAsset).where(HardwareAsset.asset_id == asset_id)
        ).scalar_one_or_none()
        if row is None:
            row = HardwareAsset(asset_id=asset_id)
            self.session.add(row)
        row.agent_id = state.get("agent_id")
        row.manufacturer = str(state.get("manufacturer") or "")
        row.model = str(state.get("model") or "")
        row.device_type = str(state.get("device_type") or "other")
        row.serial_reference = state.get("serial_reference")
        row.hardware_revision = state.get("hardware_revision")
        row.current_fingerprint = state.get("current_fingerprint")
        row.previous_fingerprint = state.get("previous_fingerprint")
        row.first_seen = _as_dt(state.get("first_seen"))
        row.last_seen = _as_dt(state.get("last_seen"))
        row.last_verified = _as_dt(state.get("last_verified"))
        row.last_firmware_check = _as_dt(state.get("last_firmware_check"))
        row.last_crypto_check = _as_dt(state.get("last_crypto_check"))
        row.last_change = state.get("last_change")
        row.firmware = state.get("firmware")
        row.tpm = state.get("tpm")
        row.hsm = state.get("hsm")
        row.capabilities = state.get("capabilities")
        row.crypto_capabilities = state.get("crypto_capabilities")
        row.previous_state = state.get("previous_state")
        row.evidence_history = state.get("evidence_history")
        if state.get("risk_score") is not None:
            row.risk_score = int(state["risk_score"])
        if state.get("risk_level") is not None:
            row.risk_level = str(state["risk_level"])
        self.session.flush()
        return row

    def get_asset(self, asset_id: str) -> Optional[HardwareAsset]:
        return self.session.execute(
            select(HardwareAsset).where(HardwareAsset.asset_id == asset_id)
        ).scalar_one_or_none()

    def list_assets(self, *, agent_id: Optional[str] = None) -> list[HardwareAsset]:
        stmt = select(HardwareAsset).order_by(HardwareAsset.asset_id)
        if agent_id:
            stmt = stmt.where(HardwareAsset.agent_id == agent_id)
        return list(self.session.execute(stmt).scalars())

    def count_assets(self, *, agent_id: Optional[str] = None) -> int:
        stmt = select(func.count()).select_from(HardwareAsset)
        if agent_id:
            stmt = stmt.where(HardwareAsset.agent_id == agent_id)
        return int(self.session.execute(stmt).scalar_one())

    def update_risk(self, asset_id: str, *, score: int, level: str) -> None:
        row = self.get_asset(asset_id)
        if row is not None:
            row.risk_score = score
            row.risk_level = level
            self.session.flush()

    # ── event journal ─────────────────────────────────────────────────

    def append_event(self, event: dict[str, Any]) -> HardwareEventRow:
        row = HardwareEventRow(
            event_type=str(event.get("event_type") or ""),
            asset_id=str(event.get("asset_id") or ""),
            agent_id=event.get("agent_id"),
            source=str(event.get("source") or "unknown"),
            observed_at=_as_dt(event.get("observed_at")) or datetime.now(timezone.utc),
            change_class=event.get("change_class"),
            state_verdict=event.get("state_verdict"),
            payload=event.get("payload"),
            evidence_id=event.get("evidence_id"),
            chain_hash=event.get("chain_hash"),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_events(
        self,
        *,
        asset_id: Optional[str] = None,
        event_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        after: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> tuple[list[HardwareEventRow], int]:
        stmt = select(HardwareEventRow)
        count_stmt = select(func.count()).select_from(HardwareEventRow)
        if asset_id:
            stmt = stmt.where(HardwareEventRow.asset_id == asset_id)
            count_stmt = count_stmt.where(HardwareEventRow.asset_id == asset_id)
        if event_type:
            stmt = stmt.where(HardwareEventRow.event_type == event_type)
            count_stmt = count_stmt.where(HardwareEventRow.event_type == event_type)
        if agent_id:
            stmt = stmt.where(HardwareEventRow.agent_id == agent_id)
            count_stmt = count_stmt.where(HardwareEventRow.agent_id == agent_id)
        if after:
            stmt = stmt.where(HardwareEventRow.observed_at > after)
            count_stmt = count_stmt.where(HardwareEventRow.observed_at > after)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = stmt.order_by(desc(HardwareEventRow.observed_at))
        rows = list(self.session.execute(
            stmt.offset((max(page, 1) - 1) * page_size).limit(page_size)
        ).scalars())
        return rows, total

    def timeline(self, asset_id: str) -> list[HardwareEventRow]:
        """Full journal for one asset, oldest first (§16 reconstruction)."""
        stmt = (
            select(HardwareEventRow)
            .where(HardwareEventRow.asset_id == asset_id)
            .order_by(HardwareEventRow.observed_at)
        )
        return list(self.session.execute(stmt).scalars())

    def events_since(self, since: datetime) -> list[HardwareEventRow]:
        """Events after ``since`` (edge catch-up / central sync, §21)."""
        stmt = (
            select(HardwareEventRow)
            .where(HardwareEventRow.observed_at > since)
            .order_by(HardwareEventRow.observed_at)
        )
        return list(self.session.execute(stmt).scalars())

    # ── agents / heartbeats ───────────────────────────────────────────

    def upsert_agent(self, health: dict[str, Any]) -> HardwareAgentRow:
        agent_id = str(health.get("agent_id") or "")
        row = self.session.execute(
            select(HardwareAgentRow).where(HardwareAgentRow.agent_id == agent_id)
        ).scalar_one_or_none()
        if row is None:
            row = HardwareAgentRow(agent_id=agent_id)
            self.session.add(row)
        row.last_heartbeat = _as_dt(health.get("last_heartbeat"))
        row.last_successful_discovery = _as_dt(health.get("last_successful_discovery"))
        row.last_crypto_check = _as_dt(health.get("last_crypto_check"))
        row.last_firmware_check = _as_dt(health.get("last_firmware_check"))
        row.event_queue_depth = int(health.get("event_queue") or 0)
        row.event_lag_seconds = int(health.get("event_lag") or 0)
        row.agent_health = str(health.get("agent_health") or "HEALTHY")
        row.agent_status = str(health.get("agent_status") or "ONLINE")
        row.hardware_count = health.get("hardware_count")
        row.version = health.get("version")
        self.session.flush()
        return row

    def get_agent(self, agent_id: str) -> Optional[HardwareAgentRow]:
        return self.session.execute(
            select(HardwareAgentRow).where(HardwareAgentRow.agent_id == agent_id)
        ).scalar_one_or_none()

    def list_agents(self) -> list[HardwareAgentRow]:
        return list(self.session.execute(
            select(HardwareAgentRow).order_by(HardwareAgentRow.agent_id)
        ).scalars())
