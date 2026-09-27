"""Session gate middleware.

Login, health, webhooks, and static assets stay open. Every other /api route
requires a valid HMAC token that has NOT been revoked in the session store
(production-strict; dev/test degrade gracefully when the store is missing).

Pure ASGI implementation (see asgi_utils.py for why): the gate needs only
path + cookies + headers, never the body.
"""

from __future__ import annotations

import logging

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from api.middleware.asgi_utils import send_json
from api.security.session_manager import SessionManager

logger = logging.getLogger(__name__)


# Matched as an exact path or as a path segment prefix (p + "/"), never as a
# bare string prefix: a bare prefix would silently exempt any future sibling
# route that merely starts with the same characters (e.g. "/api/v1/metadata"
# inheriting the "/api/v1/meta" exemption).
UNPROTECTED_PREFIXES = (
    "/health",
    "/ready",
    "/metrics",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/api/v1/auth/login",
    "/api/v1/auth/register",  # self-service registration (role pick from the 8-role catalog)
    "/api/v1/saas/signup",  # self-serve tenant provisioning (verifies its own credentials)
    "/api/v1/saas/invites/accept",  # invite token IS the credential for new identities; existing ones still require a session (enforced in the route)
    "/api/v1/auth/oidc",
    "/api/v1/auth/saml",   # SAML metadata/login/ACS (ACS verifies the IdP signature itself)
    "/api/v1/auth/ldap",   # LDAP bind login (credential checked by directory)
    "/api/v1/auth/sso",    # unified capability flags for the login screen (booleans only)
    "/api/v1/meta",
    "/api/v1/healthz",
    "/api/v1/readyz",  # LB readiness probes must work without credentials
    "/api/v1/discovery",
    "/api/v1/webhooks",
)

# Static assets are served under hashed filenames, so these DO match as bare
# string prefixes ("/favicon.ico", "/assets/index-a1b2c3.js"). They are inert
# files, never API surface.
UNPROTECTED_LITERAL_PREFIXES = (
    "/assets",
    "/favicon",
)


def _is_unprotected(path: str) -> bool:
    for p in UNPROTECTED_PREFIXES:
        base = p.rstrip("/")
        if path == base or path.startswith(base + "/"):
            return True
    return any(path.startswith(p) for p in UNPROTECTED_LITERAL_PREFIXES)


def _store_allows(token: str, username: str) -> bool:
    """True unless the token is revoked/expired or the user is disabled.

    Fails CLOSED in production: if the session store cannot be reached we
    cannot prove the token is still valid, and treating "unknown" as "allowed"
    would keep honouring revoked sessions for the whole duration of an outage.
    Dev/test (where the store is often absent by design) still degrade open.
    """
    try:
        from api.dependencies import _session_store_allows

        return _session_store_allows(token, username)
    except Exception:  # pragma: no cover - defensive
        try:
            from api.config.settings import get_settings

            production = get_settings().is_production
        except Exception:
            production = True  # cannot tell -> assume production, fail closed
        logger.exception(
            "session revocation check failed; %s",
            "denying request (production)" if production else "allowing request (non-production)",
        )
        return not production


class AuthMiddleware:
    def __init__(self, app, settings=None):
        self.app = app
        self.settings = settings

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        path = request.url.path
        if path == "/" or path.startswith("/login") or path.startswith("/static"):
            await self.app(scope, receive, send)
            return
        if _is_unprotected(path):
            await self.app(scope, receive, send)
            return
        if not path.startswith("/api/"):
            await self.app(scope, receive, send)
            return

        token = request.cookies.get("cryptoscan_session") or request.cookies.get("session_token")
        header = request.headers.get("Authorization")
        if header and header.lower().startswith("bearer "):
            token = header[7:].strip()
        if request.headers.get("x-api-key"):
            # Machine keys are validated (SHA-256 lookup + RBAC + revocation)
            # at the route dependencies — pass through to that enforcement.
            await self.app(scope, receive, send)
            return
        if not token:
            await send_json(send, 401, {"detail": "Missing Authorization header",
                                        "error_code": "MISSING_AUTH_HEADER"})
            return
        username = SessionManager().validate_session(token)
        if not username:
            await send_json(send, 401, {"detail": "Invalid token",
                                        "error_code": "INVALID_TOKEN"})
            return
        # The revocation check is a synchronous DB read. Awaiting it on a worker
        # thread keeps the event loop free: done inline it blocked the loop while
        # waiting for a pool connection, so >pool_size concurrent session-authenticated
        # requests stalled for the 30 s pool timeout (measured: 20 VUs on one session,
        # every request 30 081 ms).
        if not await run_in_threadpool(_store_allows, token, username):
            await send_json(send, 401, {"detail": "Session revoked",
                                        "error_code": "SESSION_REVOKED"})
            return
        # scope["state"] is the shared dict backing request.state for every
        # Request built from this scope (starlette wraps it in a State view).
        scope.setdefault("state", {})["user_id"] = username
        await self.app(scope, receive, send)
