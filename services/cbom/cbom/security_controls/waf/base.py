"""WAF: policies, TLS, certificates and the routes behind it — read, never edited.

The WAF is where an application's public face and its certificate meet: it presents a
certificate, terminates TLS, inspects a request and routes to a backend. This collector reads
all four. It never edits a policy, never reads a request body, and never stores a cookie or
an authorization header — the contract drops those fields before the row is normalized, and
the redaction record names the field it refused.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONFIGURED, DeviceCollector

CONTROL = "WAF"

COLLECTS: tuple[str, ...] = (
    "policies", "tls_settings", "certificates_presented", "routes", "security_events",
)
MUST_NOT: tuple[str, ...] = (
    "change_a_policy", "read_request_bodies", "store_cookies",
    "store_authorization_headers", "block_traffic",
)


class WafCollector(DeviceCollector):
    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    def policies(self) -> list[dict[str, Any]]:
        return [{"policy": self._field(raw, "policy") or self._field(raw, "name"),
                 "mode": str(self._field(raw, "mode") or "BLOCKING").upper(),
                 "paranoia": self._field(raw, "paranoia"),
                 "ruleset_version": self._field(raw, "ruleset_version"),
                 "enabled": bool(self._field(raw, "enabled", True)),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("POLICY", index, raw)}
                for index, raw in enumerate(self._section_rows("policies"), start=1)]

    def routes(self) -> list[dict[str, Any]]:
        return [{"route": self._field(raw, "route") or self._field(raw, "name"),
                 "hostname": self._field(raw, "hostname") or self._field(raw, "host"),
                 "backend": self._field(raw, "backend"),
                 "policy": self._field(raw, "policy"),
                 "tls": str(self._field(raw, "tls") or "TERMINATE").upper(),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("ROUTE", index, raw)}
                for index, raw in enumerate(self._section_rows("routes"), start=1)]

    def presented_certificates(self) -> list[dict[str, Any]]:
        """Certificate metadata only: never a private key, even if the export carries one."""
        return [{"asset": self._field(raw, "asset") or self._field(raw, "hostname"),
                 "certificate": {key: value for key, value in
                                 (self._field(raw, "certificate") or {}).items()
                                 if key not in {"private_key", "key", "pem"}}
                 if isinstance(self._field(raw, "certificate"), Mapping)
                 else self._field(raw, "certificate"),
                 "fact": CONFIGURED,
                 "evidence_id": self.evidence.id_for("CERTIFICATE", index, raw)}
                for index, raw in enumerate(self._section_rows("certificates"), start=1)]

    def security_events(self) -> list[dict[str, Any]]:
        return [row for row in self.collect_security_events()
                if row["kind"] in {"ALERT", "EVENT", "BLOCK"}]


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> WafCollector:
    from .vendors import spec_for

    return WafCollector(spec_for(vendor), feed)
