from __future__ import annotations

import time
import uuid

from api.middleware.trace import push_trace, reset_trace


class RequestIDMiddleware:
    """Pure ASGI: correlate by inbound X-Request-ID (or mint one) and
    propagate a trace id matching the OpenTelemetry-style W3C traceparent
    (or a fresh one).

    State is written to ``scope["state"]`` so ``request.state.<key>`` keeps
    working for the rest of the stack (Starlette wraps scope["state"] in a
    State object when the route builds its Request).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        raw = headers.get(b"x-request-id")
        request_id = raw.decode("latin-1") if raw else str(uuid.uuid4())
        raw = headers.get(b"x-trace-id")
        trace_id = raw.decode("latin-1") if raw else str(uuid.uuid4())
        span_id = uuid.uuid4().hex[:16]
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["trace_id"] = trace_id
        state["span_id"] = span_id
        started = time.perf_counter()
        push_trace(trace_id, span_id)
        try:
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers") or [])
                    headers.append((b"x-request-id", request_id.encode("utf-8")))
                    headers.append((b"x-trace-id", trace_id.encode("utf-8")))
                    # a truthful end-to-end latency header for any front/proxy
                    headers.append((
                        b"x-request-duration-ms",
                        str(round((time.perf_counter() - started) * 1000, 1)).encode("utf-8"),
                    ))
                    message["headers"] = headers
                await send(message)

            await self.app(scope, receive, send_wrapper)
        finally:
            reset_trace()
