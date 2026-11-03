"""VPN dialects: StrongSwan, Palo Alto GlobalProtect, and an operator-declared gateway."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "strongswan": AdapterSpec(
        key="vpn.strongswan",
        control="VPN",
        vendor="strongX509 / strongSwan",
        product="strongSwan",
        operations=("SHOW", "READ_CONFIG_FILE", "CLI_SHOW"),
        sections={"ipsec_conf": "tunnels", "swanctl_connections": "tunnels",
                  "swanctl_certs": "certificates"},
        aliases={"tunnel": ("conn", "name"), "peer": ("right",), "local": ("left",),
                 "ike_version": ("version",), "encryption": ("esp", "proposals"),
                 "hash": ("hash",), "dh_group": ("dh-group", "modp1024")},
        endpoints=("SHOW ipsec statusall", "CLI_SHOW swanctl --list-conns",
                   "READ_CONFIG_FILE /etc/ipsec.conf"),
        notes="proposals are strings like 'aes256-sha256-modp2048'; parsing them is the "
              "only place a vendor string becomes three crypto facts",
    ),
    "globalprotect": AdapterSpec(
        key="vpn.globalprotect",
        control="VPN",
        vendor="Palo Alto Networks",
        product="GlobalProtect",
        operations=("API_GET", "CLI_SHOW"),
        sections={"global_protect": "tunnels", "ike_gateway": "tunnels",
                  "certificates": "certificates"},
        aliases={"tunnel": ("name",), "peer": ("peer_address",),
                 "ike_version": ("ikev2",), "encryption": ("ipsec_crypto_profile",),
                 "dh_group": ("dh_group",), "pfs": ("perfect_forward_secrecy",)},
        endpoints=("GET /api/?type=op&cmd=<show><vpn><ike-sa>",),
        notes="the operational command is a show; the same endpoint family also accepts "
              "configuration writes, which the adapter never names",
    ),
    "vendor": AdapterSpec(
        key="vpn.vendor",
        control="VPN",
        vendor="(declared by the operator)",
        product="VPN gateway",
        operations=("API_GET", "EXPORT_CONFIG"),
        sections={"tunnels": "tunnels", "peers": "tunnels",
                  "certificates": "certificates"},
        aliases={},
        endpoints=("GET /",),
        notes="an appliance with an export: the export is the evidence",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not a VPN dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
