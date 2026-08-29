"""Rate limiting middleware (W57-58): per-identity sliding windows per endpoint class.

In-process sliding window — honest scope: single-process API deployments (the
topology this product ships today). For multi-replica setups, front the API with
a shared limiter (ingress/WAF) and keep these limits as the inner defense.

Windows are keyed by identity (session user when known, else client IP) and by
endpoint class, so a busy scanner cannot lock out the whole org and login
brute-force is throttled per source.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# endpoint class -> (limit, window_seconds)
DEFAULT_RULES: dict[str, tuple[int, int]] = {
    "login": (5, 60),        # /api/v1/auth/login — 5 req/min per IP
    "scan_submit": (100, 60),  # POST /api/v1/scans — 100 req/min per user
    "api": (600, 60),        # everything else under /api — 600 req/min per identity
}


def _endpoint_class(method: str, path: str) -> str:
    if path.rstrip("/") == "/api/v1/auth/login":
        return "login"
    if method == "POST" and (path == "/api/v1/scans" or path.startswith("/api/v1/scans")):
        return "scan_submit"
    return "api"


def _identity(request) -> str:
    """Prefer the session user (Authorization header subject), fall back to client IP."""
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        try:
            from api.security.session_manager import SessionManager

            username = SessionManager().validate_api_token(token)
            if username:
                return f"user:{username}"
        except Exception:
            pass  # unauthenticated token falls through to IP bucket
    ip = request.client.host if request.client else "unknown"
    return f"ip:{ip}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, rules: dict[str, tuple[int, int]] | None = None, clock=time.monotonic):
        super().__init__(app)
        self.rules = rules or DEFAULT_RULES
        self.clock = clock
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def _take(self, key: tuple[str, str], limit: int, window: float) -> tuple[bool, int, float]:
        now = self.clock()
        bucket = self._hits[key]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(0.0, window - (now - bucket[0]))
            return False, limit - len(bucket), retry_after
        bucket.append(now)
        return True, limit - len(bucket), 0.0

    async def dispatch(self, request, call_next):
        path = request.url.path
        if not path.startswith("/api/"):
            return await call_next(request)
        if path.startswith(("/api/v1/healthz", "/api/v1/meta", "/health", "/ready", "/metrics")):
            return await call_next(request)  # liveness probes are never throttled

        endpoint_class = _endpoint_class(request.method, path)
        limit, window = self.rules.get(endpoint_class, self.rules["api"])
        identity = _identity(request)
        allowed, remaining, retry_after = self._take((identity, endpoint_class), limit, window)
        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(max(0, remaining)),
        }
        if not allowed:
            headers["Retry-After"] = str(max(1, int(retry_after) + 1))
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "rate limit exceeded",
                    "limit": limit,
                    "window_seconds": window,
                    "scope": endpoint_class,
                },
                headers=headers,
            )
        response = await call_next(request)
        for name, value in headers.items():
            response.headers[name] = value
        return response
