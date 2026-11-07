"""Shared helpers for pure-ASGI middleware.

BaseHTTPMiddleware wraps every request in an anyio task group + memory
streams (to support ``call_next`` and mutable ``Response`` objects). That is
correct but expensive: under concurrency it cost ~7x p50 latency with 8 such
layers on the API (measured with py-spy — the event loop spent >40% of its
time in starlette.middleware.base coroutines). Pure ASGI middleware wraps
``send`` instead and is the zero-overhead equivalent.

These helpers build the raw ASGI messages so middleware does not depend on
Starlette's ``Response`` (which cannot be constructed without an active
request/response context in the ASGI world).
"""

from __future__ import annotations

import json
from typing import Any


def json_response_bytes(payload: Any) -> bytes:
    return json.dumps(payload).encode("utf-8")


def request_id_from_scope(scope: dict) -> str | None:
    """Correlation id minted by RequestIDMiddleware (never invented here)."""
    state = scope.get("state") or {}
    return state.get("request_id")


async def send_json(send, status: int, payload: Any,
                    extra_headers: dict[str, str] | None = None,
                    request_id: str | None = None) -> None:
    """Emit a complete JSON response directly through the ASGI ``send``.

    Error bodies (status >= 400) always carry the request id when one is
    known, so a client can quote it in a support request (gap analysis §B:
    "Request IDs are propagated through error responses")."""
    if status >= 400 and isinstance(payload, dict) and request_id:
        payload = {**payload, "request_id": request_id}
    body = json_response_bytes(payload)
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    for k, v in (extra_headers or {}).items():
        headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def capture_status(send):
    """Return (send_wrapper, status_box). The wrapper records the response
    status from ``http.response.start`` while passing every message through."""
    status_box: dict[str, int] = {"code": 500}

    async def send_wrapper(message):
        if message["type"] == "http.response.start":
            status_box["code"] = message["status"]
        await send(message)

    return send_wrapper, status_box


def make_send_with_headers(send, headers: dict[str, str]):
    """Return a ``send`` wrapper that injects ``headers`` into the response
    start message (setdefault semantics — never overrides app-set headers)."""

    async def send_wrapper(message):
        if message["type"] == "http.response.start":
            existing = list(message.get("headers") or [])
            present = {k.lower() for k, _ in existing}
            for k, v in headers.items():
                key = k.lower().encode("latin-1")
                if key not in present:
                    existing.append((key, v.encode("latin-1")))
            message["headers"] = existing
        await send(message)

    return send_wrapper
