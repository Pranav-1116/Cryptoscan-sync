"""Channel-scoped realtime: what the console can watch, and the stream that carries it.

Two endpoints and one stream:

* ``GET /realtime/catalog`` — every channel, its kinds, the resource to refetch, whether
  anything has ever arrived on it, and the event types that carry no channel at all. A
  screen that wants to stop polling starts by asking this what to subscribe to;
* ``GET /realtime/channels/{name}`` — one channel, so a client can validate a name before
  opening a socket;
* ``GET /realtime/stream?channels=a,b`` — SSE, filtered to the caller's channels *and* to
  the caller's estate. Filtering happens in the bus subscription, not in the HTTP
  generator: a shared Pub/Sub channel must never put another estate's event in this
  subscriber's queue.

The stream is a **delivery path**, deliberately distinct from ``/events/stream``, which is
the audit path with estate cursors, retention gaps and replay authority. This one resumes
from the in-process ring by numeric id, sends a heartbeat every 15s, and tells a client
that cannot be resumed to refetch rather than pretending it caught up. Saying which is
which is the whole reason it is a separate endpoint.
"""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from api import realtime
from api.events.bus import get_event_bus
from api.routers.events import _checkpoint, stream_grant
from api.security.socket_history import SocketRefused

router = APIRouter(prefix="/realtime", tags=["realtime"])

HEARTBEAT_SECONDS = 15.0
#: how long a connection waits for one frame before re-checking authority. Short in tests,
#: because a grant that is withdrawn must close a socket without waiting for traffic.
RECHECK_SECONDS = 5.0
#: how much ring history a resume may ask for in one page
REPLAY_LIMIT = 200


def _parse_channels(raw: str | None) -> list[str] | None:
    if not raw:
        return None
    names = [part.strip() for part in raw.split(",") if part.strip()]
    if not names:
        return None
    try:
        realtime.channels(names)
    except ValueError as exc:
        raise HTTPException(422, detail={"error": "bad_channel", "reason": str(exc)}) from exc
    return names


@router.get("/catalog")
def realtime_catalog(grant=Depends(stream_grant)) -> dict:
    """The channels, whether anything arrived on each, and what is emitting off-contract."""
    from api.security.socket_history import visible_event

    bus = get_event_bus()
    try:
        recent = bus.recent(0, REPLAY_LIMIT)
    except Exception:  # noqa: BLE001 — history unavailable is not "no channels"
        recent = []
    visible = [event for event in recent if visible_event(event, grant.tenant_id)]
    return realtime.catalog(recent_events=visible, stats=bus.stats())


@router.get("/channels/{name}")
def realtime_channel(name: str, grant=Depends(stream_grant)) -> dict:
    """One channel's contract: kinds, resource, screens, and its last event."""
    try:
        channel = realtime.channels([name])[0]
    except ValueError as exc:
        raise HTTPException(404, detail={"error": "unknown_channel", "reason": str(exc)}) from exc
    body = realtime.catalog()
    row = next(item for item in body["channels"] if item["channel"] == channel.name)
    return {
        "schema": realtime.SCHEMA,
        "channel": row,
        "stream": f"/api/v1/realtime/stream?channels={channel.name}",
        "limits": body["limits"],
    }


def format_sse(event: dict) -> str:
    payload = json.dumps(event, default=str, separators=(",", ":"))
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {payload}\n\n"


@router.get("/stream")
async def realtime_stream(
    request: Request,
    channels: str | None = Query(None, max_length=400),
    last_event_id: str | None = Query(None, max_length=64),
) -> StreamingResponse:
    """SSE for one or more channels, scoped to one estate.

    ``channels`` omitted means every routable channel. ``last_event_id`` returns what the
    ring still holds after that id; if the ring no longer reaches back that far the stream
    says so once and carries on live, because a client that silently missed a window would
    keep a stale screen and believe it.
    """
    from api.security.socket_history import visible_event

    grant = await stream_grant(request)
    names = _parse_channels(channels)
    bus = get_event_bus()

    cursor = last_event_id or request.headers.get("last-event-id")
    try:
        since = int(cursor) if cursor else 0
    except (TypeError, ValueError):
        raise HTTPException(422, detail={"error": "bad_cursor", "reason": "last_event_id must be an event id"})

    sub = bus.subscribe(
        event_filter=realtime.event_filter(
            names, visible=lambda event: visible_event(event, grant.tenant_id)
        )
    )

    async def gen():
        next_heartbeat = asyncio.get_running_loop().time() + HEARTBEAT_SECONDS
        try:
            yield "retry: 3000\n\n"
            yield (
                f'event: realtime.ready\ndata: {json.dumps({"channels": names, "from": since})}\n\n'
            )

            # Replay what the ring still holds. A gap is stated, never smoothed over.
            if since:
                try:
                    backlog = await run_in_threadpool(bus.recent, since, REPLAY_LIMIT)
                except Exception:  # noqa: BLE001
                    backlog = []
                visible = [
                    event for event in backlog
                    if visible_event(event, grant.tenant_id) and realtime.wants(names, event)
                ]
                oldest = None
                try:
                    oldest = await run_in_threadpool(bus.oldest_id)
                except Exception:  # noqa: BLE001
                    oldest = None
                if oldest is not None and since < oldest - 1:
                    yield (
                        'event: realtime.gap\ndata: {"advice":"this channel stream cannot replay '
                        'that far back; refetch the resource rather than assuming no change"}\n\n'
                    )
                for event in visible:
                    yield format_sse(event)
                if visible:
                    yield f'event: realtime.checkpoint\ndata: {{"from": {visible[-1]["id"]}}}\n\n'

            while True:
                if await request.is_disconnected():
                    return
                now = asyncio.get_running_loop().time()
                wait = min(RECHECK_SECONDS, max(0.01, next_heartbeat - now))
                batch: list[dict] = []
                try:
                    # take the frame we were woken for, then everything already queued: a
                    # burst is one repaint, not one repaint per event
                    batch.append(await asyncio.wait_for(sub.queue.get(), wait))
                except asyncio.TimeoutError:
                    pass
                # authority is re-checked on every wake, carrying or not: a revoked grant must
                # not keep a socket open just because its channel is quiet
                await _checkpoint(request, grant)
                while not sub.queue.empty():
                    batch.append(sub.queue.get_nowait())
                for event in batch:
                    if realtime.wants(names, event) and visible_event(event, grant.tenant_id):
                        yield format_sse(event)
                if asyncio.get_running_loop().time() >= next_heartbeat:
                    yield ": ping\n\n"
                    next_heartbeat = asyncio.get_running_loop().time() + HEARTBEAT_SECONDS
        except SocketRefused:
            # the credential or estate behind this socket changed: say so and stop, rather
            # than leaving a client that believes it is still authorised
            yield 'event: realtime.refused\ndata: {"advice":"reconnect with current credentials"}\n\n'
        except Exception:  # noqa: BLE001 — a dead bus, never a stack trace to a client
            yield 'event: realtime.unavailable\ndata: {"advice":"reconnect; refetch the resource on connect"}\n\n'
        finally:
            bus.unsubscribe(sub)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )
