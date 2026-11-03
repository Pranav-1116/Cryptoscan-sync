"""Firewalls: rules, zones, interfaces, VPN and TLS inspection — read, never rewritten.

The firewall is the bank's packet filter. This package reads what it decided and turns each
decision into a claim with an evidence id (``FW-001 ALLOWS INTERNET → PAYMENTS-API TCP/443
evidence=EVID-FIREWALL-…``). It does not push a rule, open a port, change NAT or sit on the
path: the adapter declares only ``EXPORT_CONFIG`` / ``API_GET`` / ``CLI_SHOW`` and a mutating
operation is refused when the spec is built.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import CONTROL_TYPES, CONFIGURED, DeviceCollector

CONTROL = "FIREWALL"

#: every vendor spells "let it through" its own way; the model has three verbs
ACTIONS: dict[str, str] = {
    "ACCEPT": "ALLOW", "PERMIT": "ALLOW", "ALLOW": "ALLOW", "PASS": "ALLOW",
    "DENY": "DENY", "DROP": "DENY", "BLOCK": "DENY", "REJECT": "REJECT", "RESET": "REJECT",
}
assert CONTROL in CONTROL_TYPES

#: the collection table from the guide, as code so it can be asserted
COLLECTS: tuple[str, ...] = (
    "rules", "zones", "interfaces", "vpn", "tls_inspection", "objects", "policies",
)
MUST_NOT: tuple[str, ...] = (
    "push_or_modify_a_rule", "open_or_close_a_port", "change_nat",
    "act_as_the_packet_filter", "read_packet_payload",
)


class FirewallCollector(DeviceCollector):
    """One firewall's policy, as evidence rather than as a config file dump."""

    def capabilities(self) -> dict[str, Any]:
        return {**super().capabilities(), "collects": list(COLLECTS),
                "must_not": list(MUST_NOT)}

    # -- policy, per rule --------------------------------------------------- #
    def rules(self) -> list[dict[str, Any]]:
        """Every rule, normalized to one shape regardless of vendor spelling.

        ``action`` is ``ALLOW``/``DENY``/``REJECT``; ``service`` keeps the port and protocol
        together, because a rule that says ``443`` and a rule that says ``tcp`` are not the
        same permission. A rule with no source, destination or service is kept as
        ``INCOMPLETE`` rather than skipped: an unreadable rule is a finding about the export.
        """
        rows = self._section_rows("rules")
        rules: list[dict[str, Any]] = []
        for index, raw in enumerate(rows, start=1):
            source = self._field(raw, "source")
            destination = self._field(raw, "destination")
            port = self._field(raw, "port")
            protocol = self._field(raw, "protocol") or "tcp"
            rules.append({
                "rule": f"FW-{index:03d}",
                "action": ACTIONS.get(str(self._field(raw, "action") or "ALLOW").upper(),
                                      str(self._field(raw, "action") or "ALLOW").upper()),
                "source": source,
                "destination": destination,
                "protocol": str(protocol).lower(),
                "port": port,
                "service": f"{str(protocol).lower()}/{port}" if port else None,
                "state": ("COMPLETE" if source and destination and port else "INCOMPLETE"),
                "fact": CONFIGURED,
                "evidence_id": self.evidence.id_for("RULE", f"FW-{index:03d}", raw),
            })
        return rules

    def zones(self) -> list[dict[str, Any]]:
        return [{"zone": self._field(raw, "zone") or self._field(raw, "name"),
                 "interfaces": list(self._field(raw, "interfaces") or []),
                 "evidence_id": self.evidence.id_for("ZONE", index, raw)}
                for index, raw in enumerate(self._section_rows("zones"), start=1)]

    def tls_inspection(self) -> list[dict[str, Any]]:
        """Whether the firewall decrypts TLS, and where — never the decrypted bytes."""
        return [{"profile": self._field(raw, "profile") or self._field(raw, "name"),
                 "mode": str(self._field(raw, "mode") or "NONE").upper(),
                 "ca": self._field(raw, "ca"),
                 "evidence_id": self.evidence.id_for("TLS_INSPECTION", index, raw)}
                for index, raw in enumerate(self._section_rows("tls_inspection"), start=1)]

    def egress_claims(self) -> list[dict[str, Any]]:
        """The rules that permit traffic, as claims, for the projection to type-check."""
        claims: list[dict[str, Any]] = []
        for rule in self.rules():
            if rule["action"] != "ALLOW" or rule["state"] != "COMPLETE":
                continue
            claims.append({
                "from": rule["source"],
                "relation": "FORWARDS_TO",
                "to": rule["destination"],
                "basis": "config-parse",
                "fact": CONFIGURED,
                "evidence_ids": [rule["evidence_id"]],
                "facts": {"port": rule["port"], "protocol": rule["protocol"],
                          "rule": rule["rule"]},
            })
        return claims


def collector(vendor: str, feed: Mapping[str, Any] | None = None) -> FirewallCollector:
    from .vendors import spec_for  # local import keeps the package import cheap

    return FirewallCollector(spec_for(vendor), feed)
