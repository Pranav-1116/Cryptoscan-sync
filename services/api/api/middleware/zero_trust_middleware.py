"""Zero-trust PDP enforcement middleware (advanced/82, round 31).

Runs inside the auth gate on every ``/api/v1`` request when
``ZERO_TRUST_ENFORCED`` is set, mirroring the ABAC middleware's
deployment gate: an unconfigured deployment keeps a zero-overhead
pass-through, a configured one is fail-closed.

Composition (the whole point): this layer can only RESTRICT —
``security.pdp.zero_trust_decision`` returns DENY for any matching deny
rule, and that 403 happens BEFORE the route runs, even for admins.
An ALLOW from the PDP does not bypass RBAC: the route's own RBAC
dependencies still run afterwards.

Principal/roles are resolved from the same request the auth middleware
already authenticated (header token -> session store), so the PDP sees
real identities, not client claims.
"""

from __future__ import annotations

import logging

from starlette.requests import Request

from api.middleware.asgi_utils import send_json

logger = logging.getLogger(__name__)

_UNPROTECTED_FRAGMENTS = (
    "/healthz", "/readyz", "/meta", "/metrics", "/docs", "/openapi.json",
)


def _principal_and_roles(request: Request) -> tuple[str, list[str]]:
    """Best-effort identity from the already-authenticated request."""
    from api.security.rbac import _caller_roles

    try:
        return _caller_roles(request)
    except Exception:  # noqa: BLE001 — unauthenticated: PDP sees anonymous
        return "", []


class ZeroTrustMiddleware:
    """Pure ASGI middleware (see asgi_utils for the pattern)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self._enforced():
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if any(fragment in path for fragment in _UNPROTECTED_FRAGMENTS):
            await self.app(scope, receive, send)
            return
        from api.config.settings import get_settings

        settings = get_settings()
        request = Request(scope)
        principal, roles = _principal_and_roles(request)
        method = scope.get("method", "GET")
        from api.security.pdp import zero_trust_decision

        decision = zero_trust_decision(
            principal=principal, roles=roles, method=method, path=path,
            policy_file=settings.ZERO_TRUST_POLICY_FILE,
            opa_url=settings.OPA_URL,
            opa_policy_path=settings.OPA_POLICY_PATH,
            enforced=True,
        )
        if decision["decision"] == "DENY":
            logger.warning(
                "zero_trust_denied",
                extra={"principal": principal, "method": method, "path": path,
                       "rules": decision.get("matched_rules"),
                       "reason": decision.get("reason")},
            )
            await send_json(send, 403, {
                "detail": {
                    "message": "denied by zero-trust policy",
                    "decision": decision,
                },
            })
            return
        await self.app(scope, receive, send)

    @staticmethod
    def _enforced() -> bool:
        from api.config.settings import get_settings

        settings = get_settings()
        if not settings.ZERO_TRUST_ENFORCED:
            return False
        return bool((settings.ZERO_TRUST_POLICY_FILE or "").strip()
                    or (settings.OPA_URL or "").strip())
