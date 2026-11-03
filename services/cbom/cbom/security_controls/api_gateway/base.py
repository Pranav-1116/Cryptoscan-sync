"""API gateway: APIs, routes, TLS and mTLS, certificates, policy presence, security events.

The gateway owns the API surface: which route is exposed, whether it terminates TLS, whether
it requires a client certificate, and which policy applies. The collector reads that surface
and, importantly, reads *presence* — an mTLS flag, a policy id — without ever holding a
credential, a token or a client secret. It does not add or revoke a route and does not issue
a token.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, DeviceCollector

CONTROL = "API_GATEWAY"

COLLECTS: tuple[str, ...] = (
    "apis", "routes", "tls_and_mtls", "certificates", "policy_presence", "security_events",
)
MUST_NOT: tuple[str, ...] = (
    "add_or_revoke_a_route", "change_mtls_trust", "issue_or_revoke_a_token",
    "read_api_secrets_or_client_credentials", "read_request_bodies",
)


class ApiGatewayCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def apis(self) -> list[dict[str, Any]]:
        return [{"api": self._field(raw, "api") or self._field(raw, "name"),
                 "version": self._field(raw, "version"),
                 "exposure": str(self._field(raw, "exposure") or "PUBLIC").upper(),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("API", index, raw)}
                for index, raw in enumerate(self._section_rows("apis"), start=1)]

    def routes(self) -> list[dict[str, Any]]:
        return [{"route": self._field(raw, "route") or self._field(raw, "name"),
                 "api": self._field(raw, "api"),
                 "methods": list(self._field(raw, "methods") or []),
                 "upstream": self._field(raw, "upstream") or self._field(raw, "target"),
                 "tls": str(self._field(raw, "tls") or "TERMINATE").upper(),
                 "mtls": bool(self._field(raw, "mtls", False)),
                 "policy": self._field(raw, "policy"),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("ROUTE", index, raw)}
                for index, raw in enumerate(self._section_rows("routes"), start=1)]

    def mtls_summary(self) -> dict[str, Any]:
        routes = self.routes()
        return {
            "control": CONTROL,
            "vendor": self.spec.vendor,
            "routes": len(routes),
            "mtls_routes": sorted(row["route"] for row in routes if row["mtls"]),
            "plaintext_routes": sorted(row["route"] for row in routes
                                       if row["tls"] in {"NONE", "PLAINTEXT"}),
            "fact": CONFIGURED,
        }

    def certificates(self) -> list[dict[str, Any]]:
        return [{"asset": self._field(raw, "asset") or self._field(raw, "route"),
                 "certificate": {key: value for key, value in raw.items()
                                 if key not in {"private_key", "key", "pem", "asset"}},
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("CERTIFICATE", index, raw)}
                for index, raw in enumerate(self._section_rows("certificates"), start=1)]

    def exposed_claims(self) -> list[dict[str, Any]]:
        """Routes that reach an upstream, as claims for the projection to type-check."""
        claims: list[dict[str, Any]] = []
        for route in self.routes():
            if not route["upstream"]:
                continue
            claims.append({
                "from": self.evidence.system,
                "relation": "ROUTES_TO",
                "to": route["upstream"],
                "basis": "config-parse",
                "fact": CONFIGURED,
                "evidence_ids": [route["evidence_id"]],
                "facts": {"route": route["route"], "mtls": route["mtls"]},
            })
        return claims


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> ApiGatewayCollector:
    from .vendors import spec_for

    return ApiGatewayCollector(spec_for(vendor), feed)
