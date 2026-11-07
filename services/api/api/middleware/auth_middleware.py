"""Session gate middleware.

Login, health, webhooks, and static assets stay open. Every other /api route
requires either a valid HMAC session token that has NOT been revoked in the
session store or a valid, policy-authorized X-API-Key. Session validation is
production-strict; machine-key lookup/policy is fail-closed in production.

Pure ASGI implementation (see asgi_utils.py for why): the gate needs only
path + cookies + headers, never the body. The machine-key branch validates
before routing so API-key coverage cannot depend on a future route remembering
a dependency.
"""

from __future__ import annotations

import logging

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from api.middleware.asgi_utils import request_id_from_scope, send_json
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
    # Stripe calls this with a signature header, never a session: the
    # HMAC in stripe-signature IS the credential (verified in the route).
    # Without this exemption the session gate 401'd every production
    # billing callback — found by the 2026-10 route-auth inventory.
    "/api/v1/saas/billing/webhook",
    # Threat-intel feed serving (round 38): machine-consumed by another
    # deployment's sync_feeds, which sends no session. The credential is
    # the feed token (THREAT_INTEL_FEED_TOKEN, required when set) and the
    # HMAC bundle signature — the integrity boundary either way. Same
    # shape as the billing webhook exemption.
    "/api/v1/threat-intel/feed",
    # ChatOps slash commands (round 38): the workspace calls this with
    # no session; the HMAC signature (+ optional token) IS the credential
    # — verified in the route, same shape as the feed exemption.
    "/api/v1/chatops/command",
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


def _write_denial(username: str, method: str, path: str) -> str | None:
    """Durable-role lookup for the write gate; never raises into the request."""
    from api.security.write_authority import refusal

    try:
        from db.connection.session import SessionLocal
        from db.repositories.user_repository import UserRepository
        from db.tenancy import platform_scope

        with platform_scope(), SessionLocal() as session:
            user = UserRepository(session).get_by_username(username) if username else None
            roles = user.role_list if user is not None else []
        return refusal(roles, method, path)
    except Exception:  # noqa: BLE001 — storage failure must not become a write
        logger.exception("write_authority_lookup_failed")
        from api.config.settings import get_settings

        try:
            production = get_settings().is_production
        except Exception:  # noqa: BLE001
            production = True
        if production:
            return "role lookup unavailable"
        # Development/test has no durable role store in many suites; the write
        # gate is enforced where roles actually exist.
        return None


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
            # Validate machine credentials before routing. Previously this was
            # a pass-through and depended on every router remembering a
            # dependency; one new route could therefore become an API-key
            # bypass. The resolver is cached on request.state so route-level
            # dependencies do not charge quota or policy twice.
            try:
                from api.dependencies import _API_KEY_INVALID, _resolve_api_key

                api_key = await run_in_threadpool(_resolve_api_key, request)
            except Exception as exc:
                status_code = getattr(exc, "status_code", 503)
                detail = getattr(exc, "detail", "API key authorization unavailable")
                logger.exception("api_key_middleware_authorization_failed")
                await send_json(send, status_code, {"detail": detail}, {"WWW-Authenticate": "ApiKey"},
                            request_id=request_id_from_scope(scope))
                return
            if api_key is _API_KEY_INVALID or not isinstance(api_key, tuple):
                await send_json(send, 401, {"detail": "Invalid or revoked API key",
                                            "error_code": "INVALID_API_KEY"},
                                {"WWW-Authenticate": "ApiKey"},
                                request_id=request_id_from_scope(scope))
                return
            scope.setdefault("state", {})["user_id"] = api_key[0]
            scope.setdefault("state", {})["api_key_auth"] = api_key
            await self._authenticated(scope, receive, send, request, key_id=api_key[2])
            return
        if not token:
            await send_json(send, 401, {"detail": "Missing Authorization header",
                                        "error_code": "MISSING_AUTH_HEADER"},
                            request_id=request_id_from_scope(scope))
            return
        username = SessionManager().validate_session(token)
        if not username:
            await send_json(send, 401, {"detail": "Invalid token",
                                        "error_code": "INVALID_TOKEN"},
                            request_id=request_id_from_scope(scope))
            return
        # The revocation check is a synchronous DB read. Awaiting it on a worker
        # thread keeps the event loop free: done inline it blocked the loop while
        # waiting for a pool connection, so >pool_size concurrent session-authenticated
        # requests stalled for the 30 s pool timeout (measured: 20 VUs on one session,
        # every request 30 081 ms).
        if not await run_in_threadpool(_store_allows, token, username):
            await send_json(send, 401, {"detail": "Session revoked",
                                        "error_code": "SESSION_REVOKED"},
                            request_id=request_id_from_scope(scope))
            return
        # scope["state"] is the shared dict backing request.state for every
        # Request built from this scope (starlette wraps it in a State view).
        scope.setdefault("state", {})["user_id"] = username
        await self._authenticated(scope, receive, send, request, username=username, token=token)

    async def _authenticated(self, scope, receive, send, request, **identity):
        from db.repositories.execution_control import authenticated_principal, request_principal, required, ExecutionDenied
        from db.connection.session import SessionLocal
        from db.tenancy import platform_scope
        from api.security.client_ip import client_ip
        import uuid

        def resolve():
            with platform_scope(), SessionLocal() as session:
                return authenticated_principal(session, **identity, path=request.url.path, method=request.method,
                    request_id=str(uuid.uuid4()), client_ip=client_ip(request))
        try:
            principal = await run_in_threadpool(resolve)
            principal["correlation_id"] = str(getattr(request.state, "request_id", ""))[:128]
        except Exception as exc:
            if required():
                code = 401 if isinstance(exc, ExecutionDenied) else 503
                await send_json(send, code, {"detail": "Typed authentication provenance unavailable"})
                return
            principal = None  # Legacy development/test authentication only.
        # Write authority for human sessions. Resolved from durable roles, not
        # from token claims, and applied before the route runs so a new router
        # cannot become writable for a read-only role by forgetting a dependency.
        if identity.get("key_id") is None:
            username = identity.get("username")
            denial = await run_in_threadpool(_write_denial, username, request.method,
                                             request.url.path)
            if denial:
                logger.info("write_denied_without_mutation_role",
                            extra={"user": username, "method": request.method,
                                   "path": request.url.path, "reason": denial})
                await send_json(send, 403,
                                {"detail": "This account has read-only access; the operation "
                                           "changes state and requires a role that may write",
                                 "error_code": "WRITE_FORBIDDEN"})
                return
        with request_principal(principal):
            await self.app(scope, receive, send)
