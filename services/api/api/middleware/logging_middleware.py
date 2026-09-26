from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


class LoggingMiddleware:
    """Pure ASGI: one structured log line per request with method/path,
    status, duration and the correlation/trace ids (set by
    RequestIDMiddleware in scope["state"]).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = {"code": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            extra = {
                "method": scope.get("method", ""),
                "path": scope.get("path", ""),
                "status": status["code"],
                "duration_ms": round((time.perf_counter() - start) * 1000, 1),
            }
            state = scope.get("state") or {}
            # include the correlation/trace ids so a request can be traced
            # across every structured log line (and shipped to any
            # APM/log backend).
            for key in ("request_id", "trace_id", "span_id"):
                val = state.get(key)
                if val:
                    extra[key] = val
            logger.info("http_request", extra=extra)
