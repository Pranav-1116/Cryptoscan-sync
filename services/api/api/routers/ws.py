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

from api.job_view import changed, job_snapshot

router = APIRouter(tags=["websocket"])

#: how often the progress socket re-reads the job row
POLL_SECONDS = 1.0
#: how long a progress socket may stay open without the job moving
IDLE_TIMEOUT_SECONDS = 1800.0
#: heartbeat cadence for the event socket (keeps proxies from reaping an idle socket)
PING_SECONDS = 25.0

WS_READER_ROLES = ("admin", "superadmin", "security_analyst", "auditor", "readonly")

#: close codes: 1008 = policy violation (auth/roles), 1011 = the server could not look
CLOSE_UNAUTHORIZED = 1008
CLOSE_SERVER_ERROR = 1011
CLOSE_NOT_FOUND = 4404
CLOSE_BUDGET = 4429


async def _principal(websocket: WebSocket) -> tuple[str | None, list[str], str]:
    """Who is on the other end: (principal, roles, how it authenticated).

    Tried in the order a client would expect: an explicit API key (header, then
    query), then a session/bearer token (query, then cookie). Returns
    ``(None, [], reason)`` when nothing checks out.
    """
    import inspect

    query = websocket.query_params
    raw_key = websocket.headers.get("x-api-key") or query.get("api_key")
    if raw_key:
        try:
            from db.connection.session import SessionLocal
            from db.repositories.api_key_repository import ApiKeyRepository

            session = SessionLocal()
            try:
                row = ApiKeyRepository(session).get_by_raw(str(raw_key).strip())
                if row is None:
                    return None, [], "that API key is unknown or revoked"
                return f"apikey:{row.name}", list(row.role_list), "api key"
            finally:
                session.close()
        except Exception as exc:  # noqa: BLE001 — an auth lookup failure is a refusal
            return None, [], f"the API key could not be checked ({type(exc).__name__})"

    token = query.get("token") or query.get("access_token")
    if not token:
        token = (websocket.cookies.get("cryptoscan_session")
                 or websocket.cookies.get("session_token"))
    if not token:
        header = websocket.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
    if not token:
        return None, [], "no credentials: send an API key, a session token or a cookie"
    try:
        from api.dependencies import _session_store_allows
        from api.security.session_manager import SessionManager

        username = SessionManager().validate_session(token)
        if inspect.isawaitable(username):
            username = await username
        if not username:
            return None, [], "that session token is not valid"
        if not _session_store_allows(token, username):
            return None, [], "that session was revoked or has expired"
        return username, _roles_for(username), "session"
    except Exception as exc:  # noqa: BLE001
        return None, [], f"the session could not be checked ({type(exc).__name__})"


def _roles_for(username: str) -> list[str]:
    """Roles of a session principal, from the user row (never from the token)."""
    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository

        session = SessionLocal()
        try:
            user = UserRepository(session).get_by_username(username)
            if user is None:
                return []
            roles = getattr(user, "role_list", None)
            if roles:
                return list(roles)
            return [role for role in (getattr(user, "roles", "") or "").split(",") if role]
        finally:
            session.close()
    except Exception:  # noqa: BLE001 — an unreadable user row is a refusal downstream
        return []


def _allowed(roles: list[str], how: str) -> bool:
    """Reader roles, with the same asymmetry the REST gate documents.

    A *session* with no known role is a legacy env-admin and is allowed; an API key
    with no roles is not — key roles are explicit by design, and a machine
    credential that lists none must not inherit the human fallback.
    """
    from api.security.rbac import normalize_roles

    normalized = set(normalize_roles(list(roles) or []))
    if not normalized:
        return how == "session"
    return bool(normalized & set(normalize_roles(list(WS_READER_ROLES))))


async def _close(websocket: WebSocket, reason: str, *, code: int = CLOSE_UNAUTHORIZED) -> None:
    with contextlib.suppress(Exception):
        await websocket.close(code=code, reason=reason[:120])


async def _accept_or_refuse(websocket: WebSocket) -> tuple[str, str] | None:
    """(principal, how) for an allowed socket, else close and return None."""
    principal, roles, how = await _principal(websocket)
    if principal is None:
        await _close(websocket, how)
        return None
    if not _allowed(roles, how):
        await _close(websocket, f"this socket needs one of: {', '.join(WS_READER_ROLES)} "
                                f"(this credential has: {', '.join(roles) or 'none'})")
        return None
    return principal, how


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
    if await _accept_or_refuse(websocket) is None:
        return
    await websocket.accept()
    interval = _interval(websocket)
    deadline = asyncio.get_running_loop().time() + IDLE_TIMEOUT_SECONDS
    previous: dict[str, Any] | None = None
    sent_anything = False
    try:
        await websocket.send_json({
            "type": "hello", "job_id": job_id, "poll_seconds": interval,
            "mechanism": ("the job row is re-read on this interval; the worker runs in "
                          "another process, so progress arrives by polling, not by push"),
            "closes_on": "a terminal status sends 'final' and closes the socket",
        })
        while True:
            card = await asyncio.to_thread(_read_job, job_id)
            now = asyncio.get_running_loop().time()
            if card is None:
                await websocket.send_json({
                    "type": "error", "job_id": job_id,
                    "message": "no job with that id — it may have been pruned",
                })
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
                await websocket.send_json({
                    "type": "error", "job_id": job_id,
                    "message": (f"no progress for {int(IDLE_TIMEOUT_SECONDS)}s; closing. Reconnect "
                                "with this job id to resume — the row is the state"),
                })
                await _close(websocket, "idle timeout", code=CLOSE_BUDGET)
                return
            if not sent_anything:
                await websocket.send_json({"type": "ping", "job_id": job_id})
            await asyncio.sleep(interval)
    except WebSocketDisconnect:
        return
    except Exception as exc:  # noqa: BLE001 — a broken socket is not a server error
        with contextlib.suppress(Exception):
            await websocket.send_json({"type": "error", "job_id": job_id,
                                       "message": f"{type(exc).__name__}: {exc}"})
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

    return {"job_id": card["jobId"], "ts": datetime.now(timezone.utc).isoformat(),
            "job": card}


def _read_job(job_id: str) -> dict[str, Any] | None:
    from db.connection.session import SessionLocal

    session = SessionLocal()
    try:
        return job_snapshot(session, job_id)
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
    if await _accept_or_refuse(websocket) is None:
        return
    await websocket.accept()
    from api.events.bus import get_event_bus

    bus = get_event_bus()
    topics = tuple(part.strip() for part in (websocket.query_params.get("topics") or "").split(",")
                   if part.strip())
    raw_since = websocket.query_params.get("since") or websocket.query_params.get("last_event_id")
    try:
        since = int(raw_since) if raw_since is not None else 0
    except (TypeError, ValueError):
        since = 0
    subscription = bus.subscribe()
    replay = bus.recent(since_id=since, limit=200)
    dropped_seen = 0
    try:
        await websocket.send_json({
            "type": "hello", "topics": list(topics), "replayed": len(replay),
            "since": since, "latest_id": bus.latest_id(),
            "note": ("in-process bus: events published by other processes (worker, monitor "
                     "daemon) reach here only after the DB tailer federates them"),
        })
        for event in replay:
            if _matches(event, topics):
                await websocket.send_json({"type": "event", **_event(event)})
        while True:
            try:
                event = await asyncio.wait_for(subscription.queue.get(), timeout=PING_SECONDS)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping", "latest_id": bus.latest_id()})
                continue
            if subscription.dropped > dropped_seen:
                lost = subscription.dropped - dropped_seen
                dropped_seen = subscription.dropped
                await websocket.send_json({
                    "type": "warning", "dropped": lost, "total_dropped": dropped_seen,
                    "message": ("this socket fell behind and the bus dropped the oldest events; "
                                "reconnect with since=<the last id you saw> to fill the gap"),
                })
            if _matches(event, topics):
                await websocket.send_json({"type": "event", **_event(event)})
    except WebSocketDisconnect:
        return
    except Exception as _handler_exc:  # noqa: BLE001
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return
    finally:
        bus.unsubscribe(subscription)


def _matches(event: dict[str, Any], topics: tuple[str, ...]) -> bool:
    if not topics:
        return True
    name = str(event.get("type") or "")
    return any(name == topic or name.startswith(topic) for topic in topics)


def _event(event: dict[str, Any]) -> dict[str, Any]:
    return {"id": event.get("id"), "ts": event.get("ts"), "event_type": event.get("type"),
            "source": event.get("source"), "payload": event.get("payload") or {}}


def dumps(frame: dict[str, Any]) -> str:
    """Frame as compact JSON — used by tests and by non-FastAPI clients."""
    return json.dumps(frame, default=str, separators=(",", ":"))
