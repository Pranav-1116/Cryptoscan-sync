"""Control-plane activity → real-time event bus.

One cross-cutting middleware gives *every* service's mutating endpoint a
presence on the SSE stream without touching dozens of routers. After a
successful write (2xx) to ``/api/v1/...`` it publishes an ``api.<segment>.<method>``
event carrying only safe metadata — actor, path, status, request id, and the
target entity id parsed from the URL. No request/response bodies are read or
emitted, so this can never leak secret material.

Event design:
- type:    ``api.scans.post`` / ``api.drift.patch`` / ``api.auth-users.delete``
- source:  ``api``
- payload: {actor, method, path, segment, action, entity, status, request_id}

Segments that already emit their own rich domain events (auth, api-keys,
runtime ingestion) are skipped to avoid double-counting; the streaming and
webhook endpoints are skipped too (they are not user-driven mutations).

Pure ASGI implementation (see asgi_utils.py for why): post-response only.
"""

from __future__ import annotations

import logging
from urllib.parse import unquote

from starlette.requests import Request

logger = logging.getLogger(__name__)

#: HTTP verbs that change state.
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

#: Segments with their own first-class event publishers — the middleware does
#: not double-emit for these (the domain event is richer and already emitted).
_SELF_PUBLISHING_SEGMENTS = {"auth", "api-keys", "events", "platform", "webhooks", "metrics"}

#: Paths that must never generate a control event (streams, probes, or
#: ingestion/action endpoints that already publish their own richer domain
#: event — listing them here avoids double-counting on the live feed).
_SKIP_PATH_FRAGMENTS = (
    "/events/stream",
    "/events/recent",
    "/healthz",
    "/readyz",
    "/meta",
    "/metrics",
    "/scans/runtime-findings",  # runtime ingest -> publishes "runtime.finding"
    "/scans/trigger",           # scan trigger -> publishes scan lifecycle events
)


def _segment_action_entity(path: str, method: str) -> tuple[str, str, str | None]:
    """Split ``/api/v1/<segment>/<entity>/...`` into (segment, action, entity).

    segment drives the event namespace; action is the verb; entity is the last
    non-trivial path component (an id) when present.
    """
    parts = [p for p in path.split("/") if p]
    # drop the "api" / "v1" prefix
    if len(parts) >= 2 and parts[0] == "api" and parts[1] == "v1":
        parts = parts[2:]
    segment = parts[0].replace("-", "_") if parts else "root"
    verb = method.lower()
    # entity: the last path segment if it looks like an id/name, not a verb path
    entity = None
    if len(parts) >= 2:
        tail = unquote(parts[-1])
        # bare collection verbs (e.g. /scans/trigger) are actions, not entities
        if tail not in {"trigger", "gate", "export", "report", "bulk", "discover", "redeploy"}:
            entity = tail[:120]
    return segment, verb, entity


class ControlEventMiddleware:
    """Pure ASGI: publish an api.* realtime event for each successful mutating call."""

    def __init__(self, app, *, enabled: bool = True):
        self.app = app
        self.enabled = enabled

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        from api.middleware.asgi_utils import capture_status
        send_wrapper, status_box = capture_status(send)
        await self.app(scope, receive, send_wrapper)

        # post-response: emit for successful mutating calls only
        try:
            request = Request(scope, receive)
            self._maybe_emit(request, status_box["code"])
        except Exception:  # pragma: no cover - events must never break a response
            logger.debug("control_event_emit_failed", exc_info=True)

    def _maybe_emit(self, request, status_code: int) -> None:
        method = request.method.upper()
        if method not in _MUTATING:
            return
        path = request.url.path
        if not path.startswith("/api/v1/"):
            return
        if any(frag in path for frag in _SKIP_PATH_FRAGMENTS):
            return
        if status_code < 200 or status_code >= 300:
            return  # only surface actions that actually succeeded

        segment, action, entity = _segment_action_entity(path, method)
        if segment in _SELF_PUBLISHING_SEGMENTS:
            return

        actor = getattr(request.state, "user_id", None) or "anonymous"
        request_id = getattr(request.state, "request_id", None)

        from api.events.bus import get_event_bus

        get_event_bus().publish(
            f"api.{segment}.{action}",
            {
                "actor": actor,
                "method": method,
                "path": path,
                "segment": segment,
                "action": action,
                "entity": entity,
                "status": status_code,
                "request_id": request_id,
            },
            source="api",
        )
