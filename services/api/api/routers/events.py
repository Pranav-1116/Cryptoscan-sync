"""Exact-estate SSE, paginated retained replay and selected-estate metadata.

Pub/Sub is a wakeup path. The owner-partitioned journal is replay/live authority;
no synthetic DB backlog, filtered global windows or local outage fallback.
Monitor/telecom tailers below remain separate compatibility publishers.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from api.events.estate_replay import ReplayError
from api.security.socket_history import SocketRefused, resolve_socket, visible_event
from api.events import platform_events
from api.events.bus import get_event_bus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/events", tags=["events"])

HEARTBEAT_SECONDS = 15.0


AUTH_RECHECK_SECONDS = 5.0


async def stream_grant(request: Request):
    try:
        return await run_in_threadpool(resolve_socket, request, admit=True, query_credentials=False)
    except SocketRefused as exc:
        raise HTTPException(
            503 if exc.code == 1011 else exc.status_code,
            detail="Stream authority unavailable" if exc.code == 1011 else str(exc),
        ) from exc


async def _checkpoint(request, grant):
    current = await run_in_threadpool(resolve_socket, request, query_credentials=False)
    if current != grant:
        raise SocketRefused("Selected estate or credential changed")


def _page(bus, owner, cursor, limit):
    try:
        page = bus.estate_page(owner, cursor, limit)
        if page["retention_gap"]:
            from api.observability.operational_counters import incr

            incr("event_replay_gap")
        return page
    except ReplayError as exc:
        raise HTTPException(409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, detail="Estate replay backend unavailable") from exc


def format_sse(event: dict) -> str:
    payload = json.dumps(event, default=str, separators=(",", ":"))
    # Wire resume tokens and public event IDs are estate-local, never global counters.
    return f"id: {event['replay_cursor']}\nevent: {event['type']}\ndata: {payload}\n\n"


class EstateStreamResponse(StreamingResponse):
    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.cleanup()


@router.get("/stream")
async def stream_events(
    request: Request,
    last_event_id: str | None = Query(None, max_length=1024),
    grant=Depends(stream_grant),
) -> StreamingResponse:
    bus = get_event_bus()
    cursor = last_event_id if last_event_id is not None else request.headers.get("last-event-id")
    # Subscribe before capturing the journal watermark. Queue frames are only
    # wakeups: ordered replay is authoritative, also when Pub/Sub misses a
    # message, the queue overflows or publishers finish out of order.
    sub = bus.subscribe(event_filter=lambda event: visible_event(event, grant.tenant_id))
    try:
        first = await run_in_threadpool(_page, bus, grant.tenant_id, cursor, 100)
        await _checkpoint(request, grant)
    except BaseException:
        bus.unsubscribe(sub)
        raise

    async def gen():
        page = first
        next_heartbeat = asyncio.get_running_loop().time() + HEARTBEAT_SECONDS
        try:
            yield "retry: 3000\n\n"
            while True:
                await _checkpoint(request, grant)
                if page["retention_gap"]:
                    yield 'event: events.gap\ndata: {"advice":"retained history lost; resynchronize application state"}\n\n'
                for event in page["events"]:
                    await _checkpoint(request, grant)
                    if visible_event(event, grant.tenant_id):
                        yield format_sse(event)
                cursor = page["next_cursor"]
                if page["has_more"]:
                    page = await run_in_threadpool(_page, bus, grant.tenant_id, cursor, 100)
                    continue
                # Advance the client checkpoint only AFTER all events in the
                # page have been yielded. Metadata contains selected-estate
                # sequences, never global counts/subscriber activity.
                await _checkpoint(request, grant)
                metadata = {k: v for k, v in page.items() if k != "events"}
                yield f"id: {cursor}\nevent: events.checkpoint\ndata: {json.dumps(metadata)}\n\n"
                while True:
                    if await request.is_disconnected():
                        return
                    try:
                        await asyncio.wait_for(sub.queue.get(), timeout=AUTH_RECHECK_SECONDS)
                        while not sub.queue.empty():
                            sub.queue.get_nowait()
                    except asyncio.TimeoutError:
                        pass
                    await _checkpoint(request, grant)
                    page = await run_in_threadpool(_page, bus, grant.tenant_id, cursor, 100)
                    if page["events"] or page["retention_gap"]:
                        break
                    if asyncio.get_running_loop().time() >= next_heartbeat:
                        yield ": ping\n\n"
                        next_heartbeat = asyncio.get_running_loop().time() + HEARTBEAT_SECONDS
        except SocketRefused as exc:
            name = "events.unavailable" if exc.code == 1011 else "events.refused"
            advice = "backend unavailable; reconnect later" if exc.code == 1011 else "reauthenticate; stream closed"
            yield f"event: {name}\ndata: {json.dumps({'advice': advice})}\n\n"
        except Exception:  # noqa: BLE001 — do not leak backend/auth exception contents
            yield 'event: events.unavailable\ndata: {"advice":"reconnect with last acknowledged cursor"}\n\n'
        finally:
            bus.unsubscribe(sub)

    response = EstateStreamResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )
    response.cleanup = lambda: bus.unsubscribe(sub)
    return response


@router.get("/recent")
def recent_events(
    cursor: str | None = Query(None, max_length=1024),
    since_id: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    grant=Depends(stream_grant),
) -> dict:
    if since_id:
        raise HTTPException(409, detail="Global numeric event IDs cannot resume estate history; use next_cursor")
    return _page(get_event_bus(), grant.tenant_id, cursor, limit)


@router.get("/stats")
def event_stats(grant=Depends(stream_grant)) -> dict:
    page = _page(get_event_bus(), grant.tenant_id, None, 1)
    return {k: v for k, v in page.items() if k not in ("events", "next_cursor", "has_more", "complete")}


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


def _drain_telecom_events(seen: set[str], publish, snapshot: dict | None, *, seed_only: bool = False) -> int:
    """Publish not-yet-seen telecom drift events from a snapshot (pure apart
    from the publish callback). ``seed_only=True`` learns history without
    publishing — the tailer's first read after boot, so a restart never
    floods the bus with old events."""
    if not snapshot:
        return 0
    published = 0
    for ev in snapshot.get("events") or []:
        key = f"telecom:{ev.get('kind')}:{ev.get('target')}:{ev.get('at')}:{ev.get('fingerprint')}"
        if key in seen:
            continue
        seen.add(key)
        if not seed_only:
            publish(ev)
            published += 1
    if len(seen) > 2_000:
        seen.clear()
        for ev in (snapshot.get("events") or [])[-1_000:]:
            seen.add(f"telecom:{ev.get('kind')}:{ev.get('target')}:{ev.get('at')}:{ev.get('fingerprint')}")
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
                # Off the event loop. _fetch_recent_monitor_events is a
                # synchronous SQLAlchemy query, and this coroutine runs on
                # the loop that serves every request. While PostgreSQL
                # answers in milliseconds nobody notices; when it stops
                # answering the call blocks until the socket times out and
                # the whole API freezes with it -- /healthz included, so
                # Kubernetes kills a pod whose only problem is that the
                # database is briefly away. That turns a recoverable blip
                # into a restart storm exactly when the database is already
                # struggling.
                #
                # Same defect class PRODUCTION-READINESS.md records for the
                # auth middleware's session-revocation check, in a different
                # place.
                rows = await run_in_threadpool(_fetch_recent_monitor_events, 100)
            except Exception as rows_exc:  # DB not ready / mid-migration — retry
                logger.warning("event_tail_rows_unavailable", extra={"error_type": type(rows_exc).__name__})
                rows = []
            try:
                directly_published = platform_events.published_event_ids()
            except Exception as published_exc:
                logger.warning(
                    "event_tail_published_ids_unavailable", extra={"error_type": type(published_exc).__name__}
                )
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
                r
                for r in rows
                if r["id"] not in seen and r["id"] not in directly_published and str(r["id"]) not in journal_row_ids
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
                    bus.publish("telecom.event", _telecom_event_payload(ev), source="telecom-scanner")

                if not seeded:
                    # first read after boot: learn history, publish nothing
                    _drain_telecom_events(seen, publish, snapshot, seed_only=True)
                    seeded = True
                else:
                    fresh = [
                        ev
                        for ev in (snapshot or {}).get("events") or []
                        if (f"telecom:{ev.get('kind')}:{ev.get('target')}:{ev.get('at')}:{ev.get('fingerprint')}")
                        not in directly
                    ]
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
    """Only platform-estate telemetry belongs on a NULL-owned event.

    Deployment-wide subscriber/rate counters are operator observability, not
    private history metadata. Tenant streams never inherit these NULL events.
    """
    bus = get_event_bus()
    previous = None
    while True:
        await asyncio.sleep(interval)
        try:
            page = await run_in_threadpool(bus.estate_page, None, None, 1)
            now = page["latest_sequence"]
            delta = now - previous[1] if previous and previous[0] == page["epoch"] else 0
            previous = (page["epoch"], now)
            await run_in_threadpool(
                bus.publish,
                "telemetry.snapshot",
                {
                    "events_per_sec": round(delta / interval, 1),
                    "events_buffered": max(0, now - page["oldest_sequence"] + 1),
                    "latest_sequence": now,
                    "epoch": page["epoch"],
                    "scope": "PLATFORM_ESTATE_ONLY",
                },
                source="telemetry",
                tenant_id=None,
            )
        except Exception as exc:
            logger.warning("estate_telemetry_unavailable", extra={"error_type": type(exc).__name__})


def start_telemetry_heartbeat(interval: float = TELEMETRY_SECONDS) -> asyncio.Task | None:
    try:
        task = asyncio.create_task(publish_telemetry(interval))
        task.set_name("telemetry-heartbeat")
        return task
    except RuntimeError:  # no running loop (sync test contexts)
        return None
