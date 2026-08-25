"""Optional JWT/session gate. Login, health, webhooks, and static assets stay open."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from api.security.session_manager import SessionManager


UNPROTECTED_PREFIXES = (
    "/health",
    "/ready",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/meta",
    "/api/v1/healthz",
    "/api/v1/webhooks",
    "/assets",
    "/favicon",
)


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
        request.state.user_id = username
        return await call_next(request)
