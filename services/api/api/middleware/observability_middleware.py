"""Request observability middleware: W3C trace-context + Prometheus metrics.

One hot-path pass: parses/creates the traceparent, times the request, feeds
the metrics registry (counters + latency histogram) and finishes a span into
the trace store. Heavy export (OTLP/JSON) is best-effort and never blocks.

Pure ASGI implementation — see security_headers.py for why.
"""

from __future__ import annotations

import time
import uuid


def _path_class(path: str) -> str:
    if path.rstrip("/") == "/api/v1/auth/login":
        return "login"
    if path.startswith("/api/v1/stream") or path.startswith("/api/v1/attacks"):
        return "stream"
    if path.startswith("/api/"):
        return "api"
    return "static"


class ObservabilityMiddleware:
    def __init__(self, app, registry, traces):
        self.app = app
        self.registry = registry
        self.traces = traces

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "")
        path = scope.get("path", "")
        started = time.time()
        headers = dict(scope.get("headers") or {})
        raw_tp = headers.get(b"traceparent")
        seed = f"{uuid.uuid4()}:{started}"
        span = self.traces.start_span(
            method=method, path=path,
            traceparent=raw_tp.decode("latin-1") if raw_tp else None, seed=seed)
        status = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                headers = list(message.get("headers") or [])
                headers.append((
                    b"traceparent",
                    f"00-{span['trace_id']}-{span['span_id']}-01".encode("utf-8"),
                ))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception:
            status["code"] = 500
            dur = (time.time() - started) * 1000
            self.registry.inc("http_requests_total",
                              method=method, status=str(status["code"]))
            self.registry.observe_latency(_path_class(path),
                                          method, status["code"], dur)
            self.traces.finish_span(span, status["code"])
            raise
        dur = (time.time() - started) * 1000
        pclass = _path_class(path)
        self.registry.inc("http_requests_total",
                          method=method, status=str(status["code"]))
        if status["code"] >= 500:
            self.registry.inc("http_server_errors_total",
                              method=method)
        self.registry.observe_latency(pclass, method, status["code"], dur)
        self.traces.finish_span(span, status["code"])
