"""Baseline HTTP security headers for every response."""

from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware

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


def _in_production() -> bool:
    return os.environ.get("ENVIRONMENT", "").strip().lower() in {"production", "prod", "staging", "stage"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        response.headers.setdefault("Content-Security-Policy", _CSP)
        # HSTS is only meaningful over HTTPS; emit it in production deploys
        # that terminate TLS (two years, include subdomains).
        if _in_production():
            response.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=63072000; includeSubDomains",
            )
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response
