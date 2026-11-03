"""Firewall dialects. A vendor is a row here, not a subclass.

Each entry says: which read-only operations the vendor's interface allows, what the vendor
calls each section, how its fields are spelled, and which endpoints a live driver would call.
That is the whole difference between a FortiGate, a PAN-OS box, a Check Point management
server and an unknown appliance — the contract, the evidence ids and the graph are shared.

``endpoints`` is documentation *and* an allow-list: :class:`AdapterSpec` refuses a spec whose
endpoint list contains a mutating verb, so the read-only promise is checkable before anything
connects.
"""

from __future__ import annotations

from typing import Any, Mapping

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "fortigate": AdapterSpec(
        key="firewall.fortigate",
        control="FIREWALL",
        vendor="Fortinet",
        product="FortiGate",
        operations=("API_GET", "CLI_SHOW"),
        sections={"firewall_policy": "rules", "system_zone": "zones",
                  "system_interface": "interfaces", "vpn_ipsec_phase1": "vpn",
                  "firewall_ssl_ssh_profile": "tls_inspection",
                  "firewall_address": "objects"},
        aliases={"source": ("srcintf", "srcaddr"), "destination": ("dstintf", "dstaddr"),
                 "port": ("service",), "protocol": ("protocol",),
                 "action": ("action",), "zone": ("name",), "interfaces": ("interface",),
                 "mode": ("ssl-ssh-profile",)},
        endpoints=("GET /api/v2/cmdb/firewall/policy",
                   "GET /api/v2/cmdb/system/zone",
                   "GET /api/v2/cmdb/vpn.ipsec/phase1-interface"),
        notes="policy rows carry srcintf/dstintf names, not addresses: the zone is the node",
    ),
    "paloalto": AdapterSpec(
        key="firewall.paloalto",
        control="FIREWALL",
        vendor="Palo Alto Networks",
        product="PAN-OS",
        operations=("API_GET", "CLI_SHOW"),
        sections={"security_rules": "rules", "zones": "zones",
                  "interfaces": "interfaces", "ipsec_tunnels": "vpn",
                  "decryption_policy": "tls_inspection", "address_objects": "objects"},
        aliases={"source": ("source", "source-zone"), "destination": ("destination",),
                 "port": ("service", "destination-port"), "protocol": ("protocol",),
                 "action": ("action",), "zone": ("zone",), "mode": ("type",)},
        endpoints=("GET /api/?type=config&action=show&xpath=/config/devices/entry"
                   "/vsys/entry/rulebase/security/rules",),
        notes="a PAN-OS rule is zone-based; the address object is the node, the zone the scope",
    ),
    "checkpoint": AdapterSpec(
        key="firewall.checkpoint",
        control="FIREWALL",
        vendor="Check Point",
        product="Quantum Security Gateway",
        operations=("API_GET",),
        sections={"access_rules": "rules", "zones": "zones",
                  "interfaces": "interfaces", "vpn_communities": "vpn",
                  "https_inspection": "tls_inspection"},
        aliases={"source": ("source",), "destination": ("destination",),
                 "port": ("service",), "protocol": ("protocol",),
                 "action": ("action",), "zone": ("name",)},
        endpoints=("GET /web_api/show-access-rulebase",
                   "GET /web_api/show-gateways-and-servers"),
        notes="the management server is the readable device; gateways are read through it",
    ),
    "generic": AdapterSpec(
        key="firewall.generic",
        control="FIREWALL",
        vendor="(declared by the operator)",
        product="Firewall",
        operations=("EXPORT_CONFIG", "READ_CONFIG_FILE"),
        sections={"rules": "rules", "zones": "zones", "interfaces": "interfaces",
                  "vpn": "vpn", "tls_inspection": "tls_inspection"},
        aliases={},
        endpoints=("EXPORT_CONFIG",),
        notes="an appliance with no API: a config export is the only evidence, and it is "
              "IMPORTED-grade until an operator confirms the version",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not a firewall dialect this integration speaks; add a row to "
        f"vendors.py ({', '.join(sorted(SPECS))}) rather than a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}


def _feed_example() -> Mapping[str, Any]:  # documentation, exercised by the tests
    return {
        "system": "FW-EDGE-01",
        "assets": [{"kind": "FIREWALL", "name": "FW-EDGE-01", "version": "7.4.3"}],
        "sections": {"firewall_policy": [
            {"srcintf": "wan1", "dstintf": "payments", "service": "HTTPS",
             "action": "accept"}]},
    }
