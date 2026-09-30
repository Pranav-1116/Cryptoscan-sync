"""Realtime platform events with separate audit and delivery authorities.

Every control-plane operation writes an audit row to ``monitor_events`` and
publishes to the EventBus. In production the EventBus writes a Redis Stream
journal with one shared event id, then uses Pub/Sub for immediate cross-replica
fan-out. The DB row remains the operator-facing audit/history record and the
DB tailer is a compatibility path for events written by monitor workers.

Latency contract (stated, not hidden):
- same-process subscribers: immediate (bus publish)
- cross-process subscribers: immediate Pub/Sub when Redis is ready, replayable
  from the Stream after disconnects/restarts
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


def _active_tenant_id(payload: dict[str, Any] | None = None) -> str | None:
    """Resolve event ownership without trusting caller-supplied tenant input.

    Request handlers run inside ``db.tenancy.tenant_scope``. Background workers
    pass an explicit tenant id through the function keyword after authorization;
    an unscoped event remains platform-wide and is only visible outside a
    tenant-owned stream.
    """
    try:
        from db.tenancy import current_tenant

        active = current_tenant()
        if active:
            return str(active)
    except Exception:  # database package is optional for pure bus tests
        pass
    # Only an internal, non-user-controlled marker is accepted outside a
    # request context (for an authorized worker carrying tenant metadata).
    explicit = (payload or {}).get("_authorized_tenant_id")
    return str(explicit) if explicit else None


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
    tenant_id: str | None = None,
) -> dict[str, Any] | None:
    """Persist + publish one platform event.

    The durable Redis journal is the realtime authority in production; the
    monitor row is the audit record. Ownership is attached to both so replay
    and live fan-out can enforce tenant isolation.
    """
    tenant_id = tenant_id or _active_tenant_id(payload)
    row_id: str | None = None
    try:
        row_id = _persist(target_name=target_name, event_type=event_type,
                          detail=detail, payload=payload, tenant_id=tenant_id)
    except Exception as exc:  # DB unavailable — the bus still delivers
        logger.warning("platform_event_persist_failed: %s", exc)

    try:
        from api.events.bus import get_event_bus

        event = get_event_bus().publish(
            f"platform.{event_type.lower()}",
            {
                **(payload or {}),
                "row_id": row_id,
                "detail": detail,
            },
            source="platform",
            tenant_id=tenant_id,
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


def persist_platform_event(
    event_type: str,
    detail: str,
    payload: dict[str, Any] | None = None,
    *,
    target_name: str = "platform",
    tenant_id: str | None = None,
) -> str | None:
    """Durable half of a real-time event: persist to the DB event log and mark
    the row as already-delivered so the tailer never double-delivers it.

    Use when the caller has ALREADY published to the in-process bus directly
    (preserving the exact event type for same-process SSE clients) and wants the
    event to also reach workers/browsers on other API processes and survive a
    restart via the tailer. The tailer republishes persisted rows to other
    workers as ``monitor.<event_type_lower>``. Best-effort; never raises.
    """
    tenant_id = tenant_id or _active_tenant_id(payload)
    try:
        row_id = _persist(target_name=target_name, event_type=event_type,
                          detail=detail, payload=payload, tenant_id=tenant_id)
    except Exception as exc:  # DB unavailable — in-process delivery still happened
        logger.warning("platform_event_persist_failed: %s", exc)
        return None
    if row_id is not None:
        ids = published_event_ids()
        ids.add(row_id)
        if len(ids) > _PUBLISHED_IDS_CAP:
            published_event_ids().clear()
    return row_id


def _persist(*, target_name: str, event_type: str, detail: str,
             payload: dict[str, Any] | None, tenant_id: str | None = None) -> str | None:
    from db.connection.session import SessionLocal
    from db.repositories.monitor_repository import MonitorRepository

    class _TargetShim:
        """Repository expects a MonitorTarget-like object; platform rows
        are target_name='platform' with no target row behind them."""

        def __init__(self, name: str, owner: str | None) -> None:
            self.id: str | None = None
            self.name: str = name
            self.tenant_id: str | None = owner

    session = SessionLocal()
    try:
        repo = MonitorRepository(session)
        row = repo.add_event(
            target=_TargetShim(target_name, tenant_id),
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
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
