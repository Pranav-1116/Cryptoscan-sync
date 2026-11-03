"""IPS dialects. Same shape as IDS plus an action, because that is the only difference."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "suricata_inline": AdapterSpec(
        key="ips.suricata_inline",
        control="IPS",
        vendor="OISF",
        product="Suricata (IPS mode)",
        operations=("TAIL_EVENTS", "LIST", "READ_CONFIG_FILE"),
        sections={"eve": "events", "rules": "signatures", "inline": "policy"},
        aliases={"signature": ("signature_id", "sid"), "action": ("verdict", "action"),
                 "src": ("src_ip",), "dst": ("dest_ip",), "port": ("dest_port",)},
        event_kinds=("ALERT", "BLOCK", "DROP"),
        endpoints=("TAIL_EVENTS /var/log/suricata/eve.json",),
        notes="in IPS mode the verdict is in the event; reading it is not applying it",
    ),
    "cisco": AdapterSpec(
        key="ips.cisco",
        control="IPS",
        vendor="Cisco",
        product="Firepower / Snort IPS",
        operations=("API_GET", "TAIL_EVENTS"),
        sections={"intrusion_events": "events", "policies": "policy"},
        aliases={"signature": ("generator_id", "signature_id"), "action": ("action",),
                 "src": ("source_ip",), "dst": ("destination_ip",)},
        event_kinds=("ALERT", "BLOCK", "DROP"),
        endpoints=("GET /api/fmc_config/v1/domain/{domain}/policy/intrusionpolicies",),
        notes="FMC exposes policy text and events; neither path is used to edit a policy",
    ),
    "vendor": AdapterSpec(
        key="ips.vendor",
        control="IPS",
        vendor="(declared by the operator)",
        product="IPS",
        operations=("SYSLOG_READ",),
        sections={"events": "events", "policy": "policy"},
        aliases={"signature": ("signature", "rule"), "action": ("action", "verdict")},
        event_kinds=("ALERT", "BLOCK", "DROP"),
        endpoints=("SYSLOG_READ udp/514",),
        notes="syslog-only sensor: blocks are visible, policy coverage is not, and the "
              "report says which is which",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not an IPS dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
