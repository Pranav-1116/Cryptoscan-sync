"""Refuse an ingestion request whose certificate proves no registered agent.

Runs only for the ingestion surface and only when
``CRYPTOSCAN_REQUIRE_AGENT_IDENTITY`` is on, so a deployment that terminates TLS
elsewhere keeps working until it declares a terminator or moves TLS into the
process.

What it changes: the identity the certificate proved is attached to the request
as ``request.state.agent_identity``; the ingestion route then refuses an
observation whose signature is not the key registered for that agent. Without
this middleware the route sees only "someone with a valid client certificate",
which is precisely the gap guide 119 recorded.
"""

from __future__ import annotations

import json
import logging

from api.security import agent_identity as identity

logger = logging.getLogger(__name__)

#: Only the ingest surface carries machine identity today.
ENFORCED_PREFIX = "/api/v1/ingestion"


class AgentIdentityMiddleware:
    """Pure ASGI, so it can look at the TLS extension the request arrived on."""

    def __init__(self, app, *, registry: identity.AgentRegistry | None = None):
        self.app = app
        self._registry = registry
        self._registry_error: str | None = None

    def _load(self) -> identity.AgentRegistry:
        if self._registry is not None:
            return self._registry
        try:
            self._registry = identity.AgentRegistry.from_env()
        except identity.AgentIdentityError as exc:
            # Fail closed and say why: an unreadable registry must not become
            # "every certificate is acceptable".
            self._registry_error = str(exc)
            logger.error("agent_registry_unreadable: %s", exc)
            return identity.AgentRegistry()
        return self._registry

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not identity.enforcement_enabled():
            await self.app(scope, receive, send)
            return
        if not str(scope.get("path", "")).startswith(ENFORCED_PREFIX):
            await self.app(scope, receive, send)
            return

        registry = self._load()
        agent, reason = identity.resolve_identity(scope, registry)
        state = scope.setdefault("state", {})
        state["agent_identity_reason"] = reason
        if agent is None:
            detail = self._registry_error if self._registry_error else reason
            logger.warning("agent_identity_refused: %s", detail)
            await self._refuse(send, detail)
            return
        state["agent_identity"] = agent
        logger.info("agent_identity_resolved: agent=%s", agent.agent_id)
        await self.app(scope, receive, send)

    async def _refuse(self, send, reason: str) -> None:
        body = json.dumps({
            "detail": {
                "error": "agent_identity_unregistered",
                "reason": reason,
                "note": ("this deployment requires a client certificate registered to a "
                         "collector agent; no identity was proved, so nothing was stored"),
            }
        }).encode()
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode())],
        })
        await send({"type": "http.response.body", "body": body})
