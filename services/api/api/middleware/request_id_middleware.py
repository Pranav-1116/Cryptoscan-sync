from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware

from api.middleware.trace import push_trace, reset_trace


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # correlate by inbound X-Request-ID (or mint one) and propagate a trace id
        # that matches the OpenTelemetry-style W3C traceparent (or a fresh one).
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
        span_id = uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        request.state.trace_id = trace_id
        request.state.span_id = span_id
        request.state.started_at = time.perf_counter()
        push_trace(trace_id, span_id)
        try:
            response = await call_next(request)
        finally:
            reset_trace()
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Trace-Id"] = trace_id
        # a truthful end-to-end latency header for any front/proxy to read
        started = getattr(request.state, "started_at", None)
        if started is not None:
            response.headers["X-Request-Duration-ms"] = str(
                round((time.perf_counter() - started) * 1000, 1)
            )
        return response
