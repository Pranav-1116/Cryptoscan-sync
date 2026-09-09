from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        extra = {
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "duration_ms": round(duration_ms, 1),
        }
        # include the correlation/trace ids so a request can be traced across
        # every structured log line (and shipped to any APM/log backend).
        for key in ("request_id", "trace_id", "span_id"):
            val = getattr(request.state, key, None)
            if val:
                extra[key] = val
        logger.info("http_request", extra=extra)
        return response
