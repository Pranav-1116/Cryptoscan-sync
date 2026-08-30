"""Real-time event stream: SSE for humans/tools, JSON recent for fallback.

- GET /events/stream  (text/event-stream; auth required; Last-Event-ID resume)
- GET /events/recent  (JSON history — polling fallback for proxies that
  buffer SSE)
- GET /events/stats   (bus health: subscribers, buffered events)

Cross-process events (the monitor daemon runs as its own process) are
federated by a DB tailer started in the app lifespan: it polls monitor_events
every EVENT_TAILER_SECONDS (default 2s) and republishes new rows onto the bus
as `monitor.*`. That latency is stated, not hidden.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from api.dependencies import get_current_user
from api.events.bus import get_event_bus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events", tags=["events"])

HEARTBEAT_SECONDS = 15.0
BACKLOG_DEFAULT = 25


def format_sse(event: dict) -> str:
    payload = json.dumps(
        {"id": event["id"], "ts": event["ts"], "type": event["type"],
         "source": event["source"], "payload": event["payload"]},
        default=str,
        separators=(",", ":"),
    )
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {payload}\n\n"


@router.get("/stream")
async def stream_events(
    request: Request,
    last_event_id: int | None = Query(None, ge=0),
    user: str = Depends(get_current_user),
) -> StreamingResponse:
    bus = get_event_bus()
    resume_id = last_event_id if last_event_id is not None else 0
    if resume_id == 0:
        # fresh connection: start from the tail of history, not the dawn of time
        resume_id = max(0, bus.latest_id() - BACKLOG_DEFAULT)
    backlog = bus.recent(since_id=resume_id, limit=BACKLOG_DEFAULT * 2)

    sub = bus.subscribe()
    bus.publish("events.subscribe", {"user": user}, source="events")

    async def gen():
        try:
            yield "retry: 3000\n\n"
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
) -> dict:
    bus = get_event_bus()
    events = bus.recent(since_id=since_id, limit=limit)
    return {
        "events": events,
        "latest_id": bus.latest_id(),
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

async def tail_monitor_events(interval: float = 2.0) -> None:
    """Federate monitor_events rows (written by the separate monitor process)
    onto the in-process bus as `monitor.*` events."""
    bus = get_event_bus()
    seen: set[str] = set()
    app_state().event_tailer_running = True
    try:
        while True:
            try:
                rows = _fetch_recent_monitor_events(limit=100)
            except Exception:  # DB not ready / mid-migration — retry quietly
                rows = []
            fresh = [r for r in rows if r["id"] not in seen]
            if fresh:
                for row in fresh:
                    seen.add(row["id"])
                    bus.publish(
                        f"monitor.{row['event_type'].lower()}",
                        {
                            "target": row["target_name"],
                            "detail": row.get("detail"),
                            "data": row.get("payload") or {},
                            "occurred_at": row["created_at"],
                        },
                        source="monitor",
                    )
                if len(seen) > 2_000:
                    seen = set(list(seen)[-1_000:])
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
                    "detail": row.detail,
                    "payload": row.payload,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
            )
        return out
    finally:
        session.close()


def start_event_tailer(interval: float) -> asyncio.Task | None:
    try:
        task = asyncio.create_task(tail_monitor_events(interval))
        task.set_name("event-tailer")
        return task
    except RuntimeError:  # no running loop (sync test contexts)
        return None
