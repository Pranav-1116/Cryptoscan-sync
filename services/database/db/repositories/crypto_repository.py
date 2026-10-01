"""Live crypto persistence — current state + immutable event journal.

Persistence for the §34/§35 live crypto scanner: ``crypto_live_states`` is
the current truth (including the versioned CycloneDX CBOM),
``crypto_live_events`` the immutable journal (timeline + point-in-time
reconstruction through ``LiveCryptoStateEngine.state_at``).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.models.crypto_live import CryptoLiveEventRow, CryptoLiveState
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


class CryptoRepository(BaseRepository[CryptoLiveState]):
    def __init__(self, session: Session):
        super().__init__(CryptoLiveState, session)

    # ── state ──────────────────────────────────────────────────────────

    def upsert_state(self, state: dict[str, Any]) -> CryptoLiveState:
        """Persist a LiveCryptoState.to_dict() as the current truth."""
        asset_id = str(state.get("asset_id") or "")
        tenant_id = state.get("tenant_id")
        if tenant_id is None:
            try:
                from db.tenancy import current_tenant

                tenant_id = current_tenant()
            except Exception:
                tenant_id = None
        predicates = [CryptoLiveState.asset_id == asset_id]
        if tenant_id is not None:
            predicates.append(CryptoLiveState.tenant_id == tenant_id)
        else:
            predicates.append(CryptoLiveState.tenant_id.is_(None))
        row = self.session.execute(
            select(CryptoLiveState).where(*predicates)
        ).scalar_one_or_none()
        if row is None:
            row = CryptoLiveState(asset_id=asset_id, tenant_id=tenant_id)
            self.session.add(row)
        row.tenant_id = tenant_id
        row.cbom_version = int(state.get("cbom_version") or 1)
        row.algorithms = state.get("algorithms")
        row.quantum_status = state.get("quantum_status")
        row.capabilities = state.get("capabilities")
        row.usage = state.get("usage")
        row.protocols = state.get("protocols")
        row.certificates = state.get("certificates")
        row.libraries = state.get("libraries")
        row.readiness = state.get("readiness")
        row.agility = state.get("agility")
        row.cbom = state.get("cbom")
        row.last_event = state.get("last_event")
        row.last_seen = _as_dt(state.get("last_seen")) or datetime.now(timezone.utc)
        self.session.flush()
        return row

    def get_state(self, asset_id: str) -> Optional[CryptoLiveState]:
        return self.session.execute(
            select(CryptoLiveState).where(CryptoLiveState.asset_id == asset_id)
        ).scalar_one_or_none()

    def list_states(self) -> list[CryptoLiveState]:
        return list(self.session.execute(
            select(CryptoLiveState).order_by(CryptoLiveState.updated_at)
        ).scalars())

    def update_risk(self, asset_id: str, *, score: int, level: str) -> None:
        row = self.get_state(asset_id)
        if row is not None:
            row.risk_score = score
            row.risk_level = level
            self.session.flush()

    # ── event journal ──────────────────────────────────────────────────

    def append_event(self, event: dict[str, Any]) -> CryptoLiveEventRow:
        tenant_id = event.get("tenant_id")
        if tenant_id is None:
            try:
                from db.tenancy import current_tenant

                tenant_id = current_tenant()
            except Exception:
                tenant_id = None
        row = CryptoLiveEventRow(
            tenant_id=tenant_id,
            event_type=str(event.get("event_type") or ""),
            asset_id=str(event.get("asset_id") or ""),
            source=str(event.get("source") or "live"),
            observed_at=_as_dt(event.get("observed_at")) or datetime.now(timezone.utc),
            cbom_version=int(event.get("cbom_version") or 1),
            risk_score=event.get("risk_score"),
            payload=event.get("payload"),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def list_events(
        self,
        *,
        asset_id: Optional[str] = None,
        event_type: Optional[str] = None,
        after: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> tuple[list[CryptoLiveEventRow], int]:
        stmt = select(CryptoLiveEventRow)
        count_stmt = select(func.count()).select_from(CryptoLiveEventRow)
        if asset_id:
            stmt = stmt.where(CryptoLiveEventRow.asset_id == asset_id)
            count_stmt = count_stmt.where(CryptoLiveEventRow.asset_id == asset_id)
        if event_type:
            stmt = stmt.where(CryptoLiveEventRow.event_type == event_type)
            count_stmt = count_stmt.where(CryptoLiveEventRow.event_type == event_type)
        if after:
            stmt = stmt.where(CryptoLiveEventRow.observed_at > after)
            count_stmt = count_stmt.where(CryptoLiveEventRow.observed_at > after)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = stmt.order_by(desc(CryptoLiveEventRow.observed_at))
        rows = list(self.session.execute(
            stmt.offset((max(page, 1) - 1) * page_size).limit(page_size)
        ).scalars())
        return rows, total

    def timeline(self, asset_id: str) -> list[CryptoLiveEventRow]:
        """Full journal for one asset, oldest first (§34 reconstruction)."""
        stmt = (
            select(CryptoLiveEventRow)
            .where(CryptoLiveEventRow.asset_id == asset_id)
            .order_by(CryptoLiveEventRow.observed_at)
        )
        return list(self.session.execute(stmt).scalars())

    def events_since(self, since: datetime) -> list[CryptoLiveEventRow]:
        stmt = (
            select(CryptoLiveEventRow)
            .where(CryptoLiveEventRow.observed_at > since)
            .order_by(CryptoLiveEventRow.observed_at)
        )
        return list(self.session.execute(stmt).scalars())
