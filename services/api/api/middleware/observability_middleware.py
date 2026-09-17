"""Request observability middleware: W3C trace-context + Prometheus metrics.

One hot-path pass: parses/creates the traceparent, times the request, feeds
the metrics registry (counters + latency histogram) and finishes a span into
the trace store. Heavy export (OTLP/JSON) is best-effort and never blocks.
"""

from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware


def _path_class(path: str) -> str:
    if path.rstrip("/") == "/api/v1/auth/login":
        return "login"
    if path.startswith("/api/v1/stream") or path.startswith("/api/v1/attacks"):
        return "stream"
    if path.startswith("/api/"):
        return "api"
    return "static"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, registry, traces):
        super().__init__(app)
        self.registry = registry
        self.traces = traces

    async def dispatch(self, request, call_next):
        started = time.time()
        seed = f"{uuid.uuid4()}:{started}"
        span = self.traces.start_span(
            method=request.method, path=request.url.path,
            traceparent=request.headers.get("traceparent"), seed=seed)
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["traceparent"] = (
                f"00-{span['trace_id']}-{span['span_id']}-01")
        except Exception:
            status = 500
            dur = (time.time() - started) * 1000
            self.registry.inc("http_requests_total",
                              method=request.method, status=str(status))
            self.registry.observe_latency(_path_class(request.url.path),
                                          request.method, status, dur)
            self.traces.finish_span(span, status)
            raise
        dur = (time.time() - started) * 1000
        pclass = _path_class(request.url.path)
        self.registry.inc("http_requests_total",
                          method=request.method, status=str(status))
        if status >= 500:
            self.registry.inc("http_server_errors_total",
                              method=request.method)
        self.registry.observe_latency(pclass, request.method, status, dur)
        self.traces.finish_span(span, status)
        return response
