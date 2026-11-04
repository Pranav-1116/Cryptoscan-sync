"""Baseline HTTP security headers for every response.

Pure ASGI middleware (not BaseHTTPMiddleware): BaseHTTPMiddleware wraps
each request in an anyio task group + memory streams, which under
concurrency costs several ms per layer per request (measured: ~7x p50
degradation at 8-way load with 8 such layers). Wrapping ``send`` is the
zero-overhead equivalent for response-header middleware.
"""

from __future__ import annotations


# Restrictive content security policy for the SPA + API. The console is a
# self-contained React bundle (no third-party CDNs, no inline event handlers,
# no <object>/<embed>); API responses are JSON and never rendered as HTML.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)

_BASE_HEADERS = [
    ("x-content-type-options", b"nosniff"),
    ("x-frame-options", b"DENY"),
    ("referrer-policy", b"no-referrer"),
    ("permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    ("content-security-policy", _CSP.encode("utf-8")),
]


def _in_production() -> bool:
    from shared_config import environment as platform_environment

    return platform_environment.environment_name() in {"production", "staging"}


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_production = _in_production()
        wants_no_store = scope.get("path", "").startswith("/api/")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                # setdefault semantics: never override headers the app set.
                headers = list(message.get("headers") or [])
                # header names on the wire are lowercase bytes; compare as str
                present = {k.decode("latin-1").lower() for k, _ in headers}
                for name, value in _BASE_HEADERS:
                    if name not in present:
                        headers.append((name.encode("utf-8"), value))
                if is_production and "strict-transport-security" not in present:
                    headers.append((
                        b"strict-transport-security",
                        b"max-age=63072000; includeSubDomains",
                    ))
                if wants_no_store and "cache-control" not in present:
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
