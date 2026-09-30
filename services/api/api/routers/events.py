"""Real-time event stream: SSE for humans/tools, JSON recent for fallback.

- GET /events/stream  (text/event-stream; auth required; Last-Event-ID resume)
- GET /events/recent  (JSON history — polling fallback for proxies that
  buffer SSE)
- GET /events/stats   (bus health: subscribers, buffered events)

Production cross-process events use the Redis Stream/Pub/Sub federation
installed during app startup. The DB tailer remains for monitor-worker audit
rows and compatibility when a row has no Redis journal frame; it polls
``monitor_events`` every ``EVENT_TAILER_SECONDS`` and republishes new rows as
``monitor.*``. Redis Stream replay is the Last-Event-ID recovery authority.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from api.dependencies import get_current_user, get_tenant_context
from api.events import platform_events
from api.events.bus import get_event_bus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events", tags=["events"])

HEARTBEAT_SECONDS = 15.0
BACKLOG_DEFAULT = 25


def _event_tenant_id(event: dict) -> str | None:
    value = event.get("tenant_id")
    if value:
        return str(value)
    payload = event.get("payload") or {}
    return str(payload["tenant_id"]) if payload.get("tenant_id") else None


def _visible_to_tenant(event: dict, tenant_id: str | None, is_platform_admin: bool) -> bool:
    """Apply the same scope to replay and live delivery.

    Unowned events are platform events and are visible to a selected tenant as
    shared control-plane information, but never to a platform-admin connection
    that has explicitly selected another tenant. Owned events require an exact
    tenant match; no wildcard tenant is accepted from the client.
    """
    owner = _event_tenant_id(event)
    if owner is None:
        return True
    if is_platform_admin and tenant_id is None:
        return False
    return tenant_id is not None and owner == str(tenant_id)


def format_sse(event: dict) -> str:
    payload = json.dumps(
        {"id": event["id"], "ts": event["ts"], "type": event["type"],
         "source": event["source"], "tenant_id": event.get("tenant_id"),
         "payload": event["payload"]},
        default=str,
        separators=(",", ":"),
    )
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {payload}\n\n"


def _db_backlog(limit: int = 25) -> list[dict]:
    """Seed the stream from the durable monitor_events table when the
    in-memory bus has no history (e.g. right after an API restart)."""
    try:
        from api.events.platform_events import published_event_ids

        rows = _fetch_recent_monitor_events(limit=limit)
    except Exception as backlog_exc:
        logger.warning("event_backlog_unavailable", extra={"error_type": type(backlog_exc).__name__})
        return []
    already = published_event_ids()
    out: list[dict] = []
    for row in reversed(rows):  # oldest first
        if row["id"] in already:
            continue
        out.append(
            {
                "id": -len(out) - 1,  # negative: synthetic, never collides with bus ids
                "ts": row["created_at"] or "",
                "type": f"monitor.{row['event_type'].lower()}",
                "source": "monitor",
                "tenant_id": row.get("tenant_id"),
                "payload": {
                    "target": row["target_name"],
                    "row_id": row.get("id"),
                    "detail": row.get("detail"),
                    "data": row.get("payload") or {},
                    "occurred_at": row["created_at"],
                },
            }
        )
    return out


@router.get("/stream")
async def stream_events(
    request: Request,
    last_event_id: int | None = Query(None, ge=0),
    user: str = Depends(get_current_user),
    tenant=Depends(get_tenant_context),
) -> StreamingResponse:
    bus = get_event_bus()
    tenant_id = getattr(tenant, "tenant_id", None)
    is_platform_admin = bool(getattr(tenant, "is_platform_admin", False))
    visible = lambda event: _visible_to_tenant(event, tenant_id, is_platform_admin)
    requested_resume = last_event_id is not None
    resume_id = last_event_id if last_event_id is not None else 0
    if resume_id == 0:
        # fresh connection: start from the tail of history, not the dawn of time
        resume_id = max(0, bus.latest_id() - BACKLOG_DEFAULT)
    backlog = [event for event in bus.recent(since_id=resume_id, limit=BACKLOG_DEFAULT * 4)
               if visible(event)][: BACKLOG_DEFAULT * 2]
    if not backlog and bus.latest_id() == 0:
        backlog = [event for event in _db_backlog(limit=BACKLOG_DEFAULT) if visible(event)]

    oldest_id = bus.oldest_id()
    replay_gap = bool(requested_resume and oldest_id is not None and resume_id < oldest_id - 1)
    sub = bus.subscribe(event_filter=visible)
    bus.publish("events.subscribe", {"user": user}, source="events", tenant_id=tenant_id)

    async def gen():
        try:
            yield "retry: 3000\n\n"
            if replay_gap:
                yield (
                    "event: events.gap\n"
                    f"data: {{\"requested_after\": {resume_id}, "
                    f"\"oldest_replayable_id\": {oldest_id}, "
                    "\"advice\": \"perform a fresh snapshot or resync\"}}\n\n"
                )
            for event in backlog:
                yield format_sse(event)
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(sub.queue.get(), timeout=HEARTBEAT_SECONDS)
                except (asyncio.TimeoutError, TimeoutError):
                    yield f": ping {int(HEARTBEAT_SECONDS)}s\n\n"
                    continue
                if sub.dropped:
                    yield (
                        f"event: events.dropped\ndata: {{\"dropped\": {sub.dropped},"
                        f" \"advice\": \"reconnect with Last-Event-ID\"}}\n\n"
                    )
                    sub.dropped = 0
                yield format_sse(event)
        finally:
            bus.unsubscribe(sub)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # ask proxies not to buffer the stream
        },
    )


@router.get("/recent")
def recent_events(
    since_id: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    user: str = Depends(get_current_user),
    tenant=Depends(get_tenant_context),
) -> dict:
    tenant_id = getattr(tenant, "tenant_id", None)
    is_platform_admin = bool(getattr(tenant, "is_platform_admin", False))
    visible = lambda event: _visible_to_tenant(event, tenant_id, is_platform_admin)
    bus = get_event_bus()
    events = [event for event in bus.recent(since_id=since_id, limit=limit * 4) if visible(event)][:limit]
    if not events and bus.latest_id() == 0:
        events = [event for event in _db_backlog(limit=min(limit, BACKLOG_DEFAULT)) if visible(event)]
    oldest_id = bus.oldest_id()
    return {
        "events": events,
        "latest_id": bus.latest_id(),
        "oldest_replayable_id": oldest_id,
        "replay_gap": bool(oldest_id is not None and since_id < oldest_id - 1),
        "subscribers": bus.subscriber_count(),
    }


@router.get("/stats")
def event_stats(user: str = Depends(get_current_user)) -> dict:
    stats = get_event_bus().stats()
    stats["tailer_running"] = getattr(app_state(), "event_tailer_running", False)
    return stats


def app_state():
    from api.main import app

    return app.state


# ------------------------------------------------------------------- tailer

def _telecom_event_payload(ev: dict) -> dict:
    """Bus payload for one telecom drift event — full identity so automation
    rules can target plane/carrier (e.g. "plane == roaming")."""
    return {
        "nf_id": ev.get("target"),
        "nf_type": ev.get("nf_type"),
        "carrier_code": ev.get("carrier_code"),
        "plane": ev.get("plane"),
        "endpoint": ev.get("endpoint"),
        "kind": ev.get("kind"),
        "severity": ev.get("severity"),
        "message": ev.get("message"),
        "at": ev.get("at"),
        "origin": "snapshot-tailer",
    }


def _drain_telecom_events(seen: set[str], publish, snapshot: dict | None,
                          *, seed_only: bool = False) -> int:
    """Publish not-yet-seen telecom drift events from a snapshot (pure apart
    from the publish callback). ``seed_only=True`` learns history without
    publishing — the tailer's first read after boot, so a restart never
    floods the bus with old events."""
    if not snapshot:
        return 0
    published = 0
    for ev in snapshot.get("events") or []:
        key = (f"telecom:{ev.get('kind')}:{ev.get('target')}:"
               f"{ev.get('at')}:{ev.get('fingerprint')}")
        if key in seen:
            continue
        seen.add(key)
        if not seed_only:
            publish(ev)
            published += 1
    if len(seen) > 2_000:
        seen.clear()
        for ev in (snapshot.get("events") or [])[-1_000:]:
            seen.add(f"telecom:{ev.get('kind')}:{ev.get('target')}:"
                     f"{ev.get('at')}:{ev.get('fingerprint')}")
    return published


async def tail_monitor_events(interval: float = 2.0) -> None:
    """Federate monitor_events rows (written by the monitor process or by
    direct platform publishers) onto the in-process bus as `monitor.*`
    events. Rows that a direct publisher already delivered (shared
    ``published_event_ids`` registry) are skipped — one row, one delivery."""
    bus = get_event_bus()
    seen: set[str] = set()
    app_state().event_tailer_running = True
    try:
        while True:
            try:
                rows = _fetch_recent_monitor_events(limit=100)
            except Exception as rows_exc:  # DB not ready / mid-migration — retry
                logger.warning("event_tail_rows_unavailable", extra={"error_type": type(rows_exc).__name__})
                rows = []
            try:
                directly_published = platform_events.published_event_ids()
            except Exception as published_exc:
                logger.warning("event_tail_published_ids_unavailable", extra={"error_type": type(published_exc).__name__})
                directly_published = set()
            # A platform publisher writes the audit row and the Redis journal
            # in the same operation. On a different replica the DB tailer must
            # not emit a second event after the Redis Pub/Sub frame arrives.
            # The row id is carried in every journal payload for this durable
            # cross-process deduplication.
            journal_row_ids: set[str] = set()
            try:
                for event in bus.recent(since_id=0, limit=10_000):
                    row_id = (event.get("payload") or {}).get("row_id")
                    if row_id is not None:
                        journal_row_ids.add(str(row_id))
            except Exception as journal_exc:
                logger.warning("event_journal_dedup_unavailable", extra={"error_type": type(journal_exc).__name__})
            fresh = [
                r for r in rows
                if r["id"] not in seen
                and r["id"] not in directly_published
                and str(r["id"]) not in journal_row_ids
            ]
            if fresh:
                for row in fresh:
                    try:
                        bus.publish(
                            f"monitor.{row['event_type'].lower()}",
                            {
                                "target": row["target_name"],
                                "row_id": row.get("id"),
                                "detail": row.get("detail"),
                                "data": row.get("payload") or {},
                                "occurred_at": row["created_at"],
                            },
                            source="monitor",
                            tenant_id=row.get("tenant_id"),
                        )
                    except Exception as publish_exc:  # retry the row next tick
                        logger.error("event_tail_publish_failed", extra={"error_type": type(publish_exc).__name__})
                        continue
                    seen.add(row["id"])
                if len(seen) > 2_000:
                    seen = set(list(seen)[-1_000:])
            try:
                platform_events.prune_published_ids()
            except Exception as prune_exc:
                logger.warning("event_tail_prune_failed", extra={"error_type": type(prune_exc).__name__})
            await asyncio.sleep(interval)
    finally:
        with contextlib.suppress(Exception):
            app_state().event_tailer_running = False


def _fetch_recent_monitor_events(limit: int = 100) -> list[dict]:
    from db.connection.session import SessionLocal
    from db.models.monitor import MonitorEvent

    session = SessionLocal()
    try:
        rows = (
            session.query(MonitorEvent)
            .order_by(MonitorEvent.created_at.desc(), MonitorEvent.id.desc())
            .limit(limit)
            .all()
        )
        out = []
        for row in reversed(rows):  # oldest first for orderly publishing
            out.append(
                {
                    "id": row.id,
                    "target_name": row.target_name,
                    "event_type": row.event_type,
                    "tenant_id": row.tenant_id,
                    "detail": row.detail,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
            )
        return out
    finally:
        session.close()



async def tail_telecom_snapshot(interval: float = 2.0) -> None:
    """Federate telecom drift events written by OTHER processes (the monitor
    daemon's TELECOM passes, CLI runs) onto the bus as `telecom.event` — a
    daemon pass streams exactly like an API scan. Events this process already
    published directly (shared ``published_event_ids`` registry, ``telecom:``
    prefixed keys) are skipped: one event, one delivery."""
    bus = get_event_bus()
    seen: set[str] = set()
    seeded = False
    while True:
        try:
            from api.routers.telecom import _load_snapshot, _snapshot_file

            file = _snapshot_file()
            mtime = file.stat().st_mtime if file.is_file() else None
            if mtime is not None:
                snapshot = _load_snapshot()
                try:
                    directly = platform_events.published_event_ids()
                except Exception:
                    directly = set()

                def publish(ev: dict) -> None:
                    bus.publish("telecom.event", _telecom_event_payload(ev),
                                source="telecom-scanner")

                if not seeded:
                    # first read after boot: learn history, publish nothing
                    _drain_telecom_events(seen, publish, snapshot, seed_only=True)
                    seeded = True
                else:
                    fresh = [ev for ev in (snapshot or {}).get("events") or []
                             if (f"telecom:{ev.get('kind')}:{ev.get('target')}:"
                                 f"{ev.get('at')}:{ev.get('fingerprint')}") not in directly]
                    _drain_telecom_events(seen, publish, {"events": fresh})
        except Exception as snapshot_exc:  # snapshot unreadable / mid-write — retry
            logger.warning("telecom_event_snapshot_unavailable", extra={"error_type": type(snapshot_exc).__name__})
        await asyncio.sleep(interval)


def start_event_tailer(interval: float) -> asyncio.Task | None:
    try:
        task = asyncio.create_task(tail_monitor_events(interval))
        task.set_name("event-tailer")
        try:
            telecom_task = asyncio.create_task(tail_telecom_snapshot(interval))
            telecom_task.set_name("telecom-tailer")
        except RuntimeError:  # pragma: no cover — same loop, cannot happen
            pass
        return task
    except RuntimeError:  # no running loop (sync test contexts)
        return None


# ------------------------------------------------------ telemetry heartbeat

TELEMETRY_SECONDS = 15.0


async def publish_telemetry(interval: float = TELEMETRY_SECONDS) -> None:
    """Periodic `telemetry.snapshot` event so live subscribers get events/sec,
    subscriber count and buffer depth without polling."""
    bus = get_event_bus()
    prev = bus.published_total()
    while True:
        await asyncio.sleep(interval)
        now = bus.published_total()
        delta = now - prev
        prev = now
        bus.publish(
            "telemetry.snapshot",
            {
                "events_per_sec": round(delta / interval, 1),
                "published_total": now,
                "subscribers": bus.subscriber_count(),
                "events_buffered": len(bus.recent(limit=10_000)),
                "latest_id": bus.latest_id(),
            },
            source="telemetry",
        )


def start_telemetry_heartbeat(interval: float = TELEMETRY_SECONDS) -> asyncio.Task | None:
    try:
        task = asyncio.create_task(publish_telemetry(interval))
        task.set_name("telemetry-heartbeat")
        return task
    except RuntimeError:  # no running loop (sync test contexts)
        return None
