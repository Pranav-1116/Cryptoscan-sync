"""Rate limiting middleware (W57-58): per-identity sliding windows per endpoint class.

In-process sliding window — honest scope: single-process API deployments (the
topology this product ships today). For multi-replica setups, front the API with
a shared limiter (ingress/WAF) and keep these limits as the inner defense.

Windows are keyed by identity (API key or session user when known, else client
IP) and by endpoint class, so a busy scanner cannot lock out the whole org and
login brute-force is throttled per source.

Pure ASGI implementation (see asgi_utils.py for why): the decision needs only
path + headers + identity, never the body.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict, deque

from starlette.requests import Request

from api.middleware.asgi_utils import request_id_from_scope

from api.middleware.asgi_utils import make_send_with_headers, send_json

logger = logging.getLogger(__name__)

# endpoint class -> (limit, window_seconds)
DEFAULT_RULES: dict[str, tuple[int, int]] = {
    "login": (5, 60),          # /api/v1/auth/login — 5 req/min per IP
    "register": (10, 3600),    # /api/v1/auth/register — 10 accounts/hour per IP (open endpoint)
    "scan_submit": (100, 60),  # POST /api/v1/scans — 100 req/min per user
    "host_write": (10, 60),   # bounded offline approval/intake, not remote execution
    "host_read": (60, 60),    # integrity-checked metadata/export
    "api": (600, 60),          # everything else under /api — 600 req/min per identity
}


def _endpoint_class(method: str, path: str) -> str:
    if path.rstrip("/") == "/api/v1/auth/login":
        return "login"
    if method == "POST" and path.rstrip("/") == "/api/v1/auth/register":
        return "register"
    if method == "POST" and (path == "/api/v1/scans" or path.startswith("/api/v1/scans")):
        return "scan_submit"
    if path.startswith("/api/v1/collection/"):
        return "host_read" if method in {"GET", "HEAD"} else "host_write"
    if path.startswith("/api/v1/host-evidence/"):
        return "host_write" if method == "POST" else "host_read"
    return "api"


def _identity(request) -> str:
    """Prefer the API key or session user, fall back to client IP."""
    api_key = request.headers.get("x-api-key")
    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
        return f"apikey:{digest}"  # per-key bucket, no DB read on the hot path
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        try:
            from api.security.session_manager import SessionManager

            username = SessionManager().validate_api_token(token)
            if username:
                return f"user:{username}"
        except Exception as exc:
            logger.warning("rate_limit_session_identity_unavailable", extra={"error_type": type(exc).__name__})
            # An invalid/unavailable session identity falls through to IP bucket.
    # per-IP bucket under the same proxy-trust boundary as the API-key
    # allowlist: honoring X-Forwarded-For without the boundary would let a
    # client mint unlimited buckets; ignoring it behind a real proxy would
    # lump every user into one. The boundary resolves both honestly.
    from api.security.client_ip import client_ip

    ip = client_ip(request) or "unknown"
    return f"ip:{ip}"


class RateLimitMiddleware:
    def __init__(self, app, rules: dict[str, tuple[int, int]] | None = None, clock=time.monotonic,
                 redis_client=None, fail_closed: bool = False):
        self.app = app
        self.rules = rules or DEFAULT_RULES
        self.clock = clock
        self.redis = redis_client  # None -> in-process windows in development
        self.fail_closed = fail_closed
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def _take(self, key: tuple[str, str], limit: int, window: float) -> tuple[bool, int, float]:
        if self.redis is None and self.fail_closed:
            # A production deployment configured for a shared limiter must not
            # silently downgrade to per-process quotas during Redis outage.
            return False, 0, 1.0
        if self.redis is not None:
            shared = self._take_shared(key, limit, window)
            if shared is not None:
                return shared
        now = self.clock()
        bucket = self._hits[key]
        while bucket and now - bucket[0] >= window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry_after = max(0.0, window - (now - bucket[0]))
            return False, limit - len(bucket), retry_after
        bucket.append(now)
        return True, limit - len(bucket), 0.0

    def _take_shared(self, key: tuple[str, str], limit: int, window: float):
        """Cluster-wide fixed window. None -> Redis unavailable, caller falls back."""
        identity, endpoint_class = key
        epoch = int(self.clock() // window)
        bucket_key = f"rl:{endpoint_class}:{identity}:{epoch}"
        try:
            count = self.redis.incr(bucket_key)
            if count == 1:
                self.redis.expire(bucket_key, int(window) + 1)
            retry_after = window - (self.clock() % window)
            return count <= limit, max(0, limit - count), retry_after
        except Exception as exc:
            logger.exception("rate_limit_redis_unavailable", extra={"error_type": type(exc).__name__})
            if self.fail_closed:
                return False, 0, 1.0
            return None  # development-only degrade to in-process limits

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        path = request.url.path
        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return
        if path.startswith(("/api/v1/healthz", "/api/v1/meta", "/health", "/ready", "/metrics")):
            await self.app(scope, receive, send)  # liveness probes are never throttled
            return

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
            await send_json(send, 429, {
                "detail": "rate limit exceeded",
                "error_code": "RATE_LIMITED",
                "limit": limit,
                "window_seconds": window,
                "scope": endpoint_class,
            }, extra_headers=headers,
               request_id=request_id_from_scope(request.scope))
            return
        await self.app(scope, receive, make_send_with_headers(send, headers))
