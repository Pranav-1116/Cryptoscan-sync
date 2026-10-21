"""WebSocket surface: live job progress and the platform event stream.

Two sockets, both read-only:

* ``WS /ws/binary/jobs/{job_id}`` — a scan's progress as it moves. It sends a
  snapshot on connect, then a frame whenever the job row changes, and closes with
  ``final`` when the job reaches a terminal state. The mechanism is stated in the
  first frame: the server **polls the job row** (default every 1s) rather than
  receiving pushes from the worker — the worker is a separate process and the
  in-process event bus does not cross that boundary. A WebSocket that claimed
  otherwise would be the same polling with a nicer name.
* ``WS /ws/events`` — the same event bus the SSE stream uses, with ``topics``
  filters and ``since``/``last_event_id`` resume, so a client that prefers one
  socket for everything can have it.

Both authenticate at connect: a session cookie (browsers send it), ``X-API-Key``
(non-browser clients), or ``?api_key=``/``?token=`` for clients that cannot set a
header on the upgrade. Refusals close with a code and a reason *before* any data
is sent — an unauthenticated socket never sees a frame.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import asyncio
import contextlib
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.job_view import changed, job_card
from api.security.socket_history import READER_ROLES, SocketRefused, resolve_socket, visible_event

router = APIRouter(tags=["websocket"])

#: how often the progress socket re-reads the job row
POLL_SECONDS = 1.0
#: how long a progress socket may stay open without the job moving
IDLE_TIMEOUT_SECONDS = 1800.0
#: heartbeat cadence for the event socket (keeps proxies from reaping an idle socket)
PING_SECONDS = 25.0
AUTH_RECHECK_SECONDS = 5.0

WS_READER_ROLES = READER_ROLES

#: close codes: 1008 = policy violation (auth/roles), 1011 = the server could not look
CLOSE_UNAUTHORIZED = 1008
CLOSE_SERVER_ERROR = 1011
CLOSE_NOT_FOUND = 4404
CLOSE_BUDGET = 4429


async def _close(websocket: WebSocket, reason: str, *, code: int = CLOSE_UNAUTHORIZED) -> None:
    with contextlib.suppress(Exception):
        await websocket.close(code=code, reason=reason[:120])


async def _accept_or_refuse(websocket: WebSocket):
    try:
        return await asyncio.to_thread(resolve_socket, websocket, admit=True)
    except SocketRefused as exc:
        await _close(websocket, str(exc), code=exc.code)
        return None


async def _checkpoint(websocket, grant):
    fresh = await asyncio.to_thread(resolve_socket, websocket)
    if fresh != grant:
        raise SocketRefused("Socket principal or selected estate changed")


# --------------------------------------------------------------------------- #
# binary job progress
# --------------------------------------------------------------------------- #


@router.websocket("/ws/binary/jobs/{job_id}")
async def binary_job_stream(websocket: WebSocket, job_id: str) -> None:
    """Stream one binary scan's progress until it finishes.

    Frames are JSON: ``snapshot`` (on connect), ``update`` (something moved),
    ``final`` (terminal state, then the socket closes), ``error`` (the job could not
    be read), ``ping`` (idle heartbeat). Every frame carries ``job_id`` and ``ts`` so
    a client can multiplex and order without tracking state itself.
    """
    grant = await _accept_or_refuse(websocket)
    if grant is None:
        return
    await websocket.accept()
    interval = _interval(websocket)
    deadline = asyncio.get_running_loop().time() + IDLE_TIMEOUT_SECONDS
    previous: dict[str, Any] | None = None
    sent_anything = False
    try:
        await websocket.send_json(
            {
                "type": "hello",
                "job_id": job_id,
                "poll_seconds": interval,
                "mechanism": (
                    "the job row is re-read on this interval; the worker runs in "
                    "another process, so progress arrives by polling, not by push"
                ),
                "closes_on": "a terminal status sends 'final' and closes the socket",
            }
        )
        while True:
            await _checkpoint(websocket, grant)
            card = await asyncio.to_thread(_read_job, job_id, grant.tenant_id)
            now = asyncio.get_running_loop().time()
            if card is None:
                await websocket.send_json(
                    {
                        "type": "error",
                        "job_id": job_id,
                        "message": "no job with that id — it may have been pruned",
                    }
                )
                await _close(websocket, "job not found", code=CLOSE_NOT_FOUND)
                return
            if changed(previous, card):
                frame = "snapshot" if previous is None else "update"
                await websocket.send_json({"type": frame, **_frame(card)})
                sent_anything = True
                deadline = now + IDLE_TIMEOUT_SECONDS
            # every read is the new baseline: without this the socket would call
            # the next read a snapshot too, and a client could not tell "it moved"
            # from "here it is again"
            previous = card
            if card["terminal"]:
                await websocket.send_json({"type": "final", **_frame(card)})
                await _close(websocket, "job reached a terminal state", code=1000)
                return
            if now > deadline:
                await websocket.send_json(
                    {
                        "type": "error",
                        "job_id": job_id,
                        "message": (
                            f"no progress for {int(IDLE_TIMEOUT_SECONDS)}s; closing. Reconnect "
                            "with this job id to resume — the row is the state"
                        ),
                    }
                )
                await _close(websocket, "idle timeout", code=CLOSE_BUDGET)
                return
            if not sent_anything:
                await websocket.send_json({"type": "ping", "job_id": job_id})
            await asyncio.sleep(interval)
    except SocketRefused as exc:
        await _close(websocket, str(exc), code=exc.code)
        return
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001 — never return database exception content
        with contextlib.suppress(Exception):
            await websocket.send_json({"type": "error", "job_id": job_id, "message": "Job progress could not be read"})
        await _close(websocket, "stream failed", code=CLOSE_SERVER_ERROR)


def _interval(websocket: WebSocket) -> float:
    raw = websocket.query_params.get("interval")
    try:
        value = float(raw) if raw is not None else POLL_SECONDS
    except (TypeError, ValueError):
        value = POLL_SECONDS
    return max(0.25, min(value, 10.0))


def _frame(card: dict[str, Any]) -> dict[str, Any]:
    from datetime import datetime, timezone

    return {"job_id": card["jobId"], "ts": datetime.now(timezone.utc).isoformat(), "job": card}


def _read_job(job_id: str, owner: str | None) -> dict[str, Any] | None:
    from db.connection.session import SessionLocal

    session = SessionLocal()
    try:
        from db.repositories.job_repository import JobRepository

        job = JobRepository(session).get_by_id(job_id, owner=owner)
        return job_card(job) if job is not None else None
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# the platform event stream
# --------------------------------------------------------------------------- #


@router.websocket("/ws/events")
async def event_stream(websocket: WebSocket) -> None:
    """The in-process event bus over a socket, with topic filters and resume.

    ``topics=scan.,binary.,runtime.`` filters by prefix; ``since=<id>`` (or the
    ``last_event_id`` query parameter) replays the bus history after that id. The
    honesty note from the SSE stream carries over: this bus is **in-process**, so
    events published in the worker or the monitor daemon are not here until the DB
    tailer federates them.
    """
    grant = await _accept_or_refuse(websocket)
    if grant is None:
        return
    await websocket.accept()
    from api.events.bus import get_event_bus

    bus = get_event_bus()
    topics = tuple(part.strip() for part in (websocket.query_params.get("topics") or "").split(",") if part.strip())
    raw_since = websocket.query_params.get("since") or websocket.query_params.get("last_event_id")
    try:
        since = int(raw_since) if raw_since is not None else 0
    except (TypeError, ValueError):
        since = 0
    visible = lambda event: visible_event(event, grant.tenant_id) and _matches(event, topics)
    subscription = bus.subscribe(event_filter=visible)
    dropped_seen = 0
    try:
        replay = [event for event in bus.recent(since_id=since, limit=200) if visible(event)]
        await _checkpoint(websocket, grant)
        latest_visible = max([since] + [int(e["id"]) for e in replay])
        next_ping = asyncio.get_running_loop().time() + PING_SECONDS
        await websocket.send_json(
            {
                "type": "hello",
                "topics": list(topics),
                "replayed": len(replay),
                "since": since,
                "latest_id": latest_visible,
                "note": (
                    "in-process bus: events published by other processes (worker, monitor "
                    "daemon) reach here only after the DB tailer federates them; bounded global "
                    "replay window filtered by selected estate, not complete tenant history"
                ),
            }
        )
        for event in replay:
            if visible(event):
                await websocket.send_json({"type": "event", **_event(event)})
        while True:
            try:
                event = await asyncio.wait_for(
                    subscription.queue.get(), timeout=min(PING_SECONDS, AUTH_RECHECK_SECONDS)
                )
            except asyncio.TimeoutError:
                await _checkpoint(websocket, grant)
                now = asyncio.get_running_loop().time()
                if now >= next_ping:
                    await websocket.send_json({"type": "ping", "latest_id": latest_visible})
                    next_ping = now + PING_SECONDS
                continue
            await _checkpoint(websocket, grant)
            if subscription.dropped > dropped_seen:
                lost = subscription.dropped - dropped_seen
                dropped_seen = subscription.dropped
                await websocket.send_json(
                    {
                        "type": "warning",
                        "dropped": lost,
                        "total_dropped": dropped_seen,
                        "message": (
                            "this socket fell behind and the bus dropped the oldest events; "
                            "reconnect with since=<the last id you saw> to request retained history; "
                            "bounded replay does not guarantee recovery"
                        ),
                    }
                )
            if visible(event):
                latest_visible = max(latest_visible, int(event["id"]))
                await websocket.send_json({"type": "event", **_event(event)})
    except SocketRefused as exc:
        await _close(websocket, str(exc), code=exc.code)
    except WebSocketDisconnect:
        return
    except Exception as _handler_exc:  # noqa: BLE001
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        await _close(websocket, "Event stream unavailable", code=CLOSE_SERVER_ERROR)
        return
    finally:
        bus.unsubscribe(subscription)


def _matches(event: dict[str, Any], topics: tuple[str, ...]) -> bool:
    if not topics:
        return True
    name = str(event.get("type") or "")
    return any(name == topic or name.startswith(topic) for topic in topics)


def _event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": event.get("id"),
        "ts": event.get("ts"),
        "event_type": event.get("type"),
        "source": event.get("source"),
        "payload": event.get("payload") or {},
    }


def dumps(frame: dict[str, Any]) -> str:
    """Frame as compact JSON — used by tests and by non-FastAPI clients."""
    return json.dumps(frame, default=str, separators=(",", ":"))
