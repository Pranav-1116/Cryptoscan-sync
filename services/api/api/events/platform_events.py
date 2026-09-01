"""Realtime platform events — every control-plane operation emits a
deterministic event that is (a) persisted to the monitor_events table
(the durable, DB-backed event log) and (b) published immediately onto the
in-process event bus so SSE subscribers see it with zero tailer latency.

The DB tailer (api.routers.events) keeps the same rows out of its own
publish path via the shared ``published_event_ids`` registry on app.state,
so one row is never delivered twice.

Latency contract (stated, not hidden):
- same-process subscribers: immediate (bus publish)
- cross-process subscribers (the monitor daemon, other API workers):
  within EVENT_TAILER_SECONDS (default 2s) via the DB tailer
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

#: max rows the dedup registry keeps (tailer + direct publishers share it)
_PUBLISHED_IDS_CAP = 4_000


def app_state() -> Any:
    from api.main import app

    return app.state


def published_event_ids() -> set[str]:
    """Shared dedup registry: row ids already delivered by direct publishers."""
    state = app_state()
    ids = getattr(state, "published_event_ids", None)
    if ids is None:
        ids = set()
        state.published_event_ids = ids
    return ids


def emit_platform_event(
    event_type: str,
    detail: str,
    payload: dict[str, Any] | None = None,
    *,
    target_name: str = "platform",
) -> dict[str, Any] | None:
    """Persist + publish one platform event (best-effort, never raises)."""
    row_id: str | None = None
    try:
        row_id = _persist(target_name=target_name, event_type=event_type,
                          detail=detail, payload=payload)
    except Exception as exc:  # DB unavailable — the bus still delivers
        logger.warning("platform_event_persist_failed: %s", exc)

    try:
        from api.events.bus import get_event_bus

        event = get_event_bus().publish(
            f"platform.{event_type.lower()}",
            {
                "row_id": row_id,
                "detail": detail,
                **(payload or {}),
            },
            source="platform",
        )
    except Exception as exc:  # never break a control-plane operation
        logger.warning("platform_event_publish_failed: %s", exc)
        return None

    if row_id is not None:
        ids = published_event_ids()
        ids.add(row_id)
        if len(ids) > _PUBLISHED_IDS_CAP:
            published_event_ids().clear()
    return event


def _persist(*, target_name: str, event_type: str, detail: str,
             payload: dict[str, Any] | None) -> str | None:
    from db.connection.session import SessionLocal
    from db.repositories.monitor_repository import MonitorRepository

    class _TargetShim:
        """Repository expects a MonitorTarget-like object; platform rows
        are target_name='platform' with no target row behind them."""

        def __init__(self, name: str) -> None:
            self.id: str | None = None
            self.name: str = name

    session = SessionLocal()
    try:
        repo = MonitorRepository(session)
        row = repo.add_event(
            target=_TargetShim(target_name),
            event_type=event_type,
            detail=detail,
            payload=payload,
        )
        session.commit()
        return row.id
    finally:
        session.close()


def prune_published_ids() -> None:
    """Called by the tailer — keeps the shared registry bounded."""
    try:
        ids = published_event_ids()
        if len(ids) > _PUBLISHED_IDS_CAP:
            ids.clear()
    except Exception:
        pass
