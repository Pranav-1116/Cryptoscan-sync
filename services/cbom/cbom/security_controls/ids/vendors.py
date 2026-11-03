"""IDS dialects: Snort, Suricata, and any syslog-emitting sensor."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "snort": AdapterSpec(
        key="ids.snort",
        control="IDS",
        vendor="Cisco",
        product="Snort",
        operations=("TAIL_EVENTS", "READ_CONFIG_FILE", "PCAP_READ"),
        sections={"alert_fast": "alerts", "rules": "signatures"},
        aliases={"signature": ("sid", "signature_id"), "signature_revision": ("rev",),
                 "src": ("src_ip",), "dst": ("dst_ip",), "protocol": ("proto",),
                 "port": ("dst_port",), "classification": ("classification",),
                 "enabled": ("enabled",)},
        event_kinds=("ALERT", "EVENT"),
        endpoints=("TAIL_EVENTS /var/log/snort/alert_fast",
                   "READ_CONFIG_FILE /etc/snort/snort.conf"),
        notes="alert_fast carries no payload; the unified2 log is deliberately not read",
    ),
    "suricata": AdapterSpec(
        key="ids.suricata",
        control="IDS",
        vendor="OISF",
        product="Suricata",
        operations=("TAIL_EVENTS", "LIST", "READ_CONFIG_FILE", "PCAP_READ"),
        sections={"eve": "alerts", "rules": "signatures"},
        aliases={"signature": ("signature_id", "sid"), "signature_revision": ("rev",),
                 "src": ("src_ip",), "dst": ("dest_ip", "dst_ip"),
                 "protocol": ("proto",), "port": ("dest_port",),
                 "tls_version": ("tls_version",), "cipher_suite": ("cipher_suite",),
                 "sni": ("sni",), "alpn": ("alpn",)},
        event_kinds=("ALERT", "EVENT", "DROP"),
        endpoints=("TAIL_EVENTS /var/log/suricata/eve.json",
                   "QUERY suricatasc -c dump-counters"),
        notes="eve.json already carries tls/flow metadata, which is the whole correlation "
              "input; the payload field is dropped by the contract",
    ),
    "vendor": AdapterSpec(
        key="ids.vendor",
        control="IDS",
        vendor="(declared by the operator)",
        product="IDS",
        operations=("SYSLOG_READ", "QUERY"),
        sections={"alerts": "alerts", "signatures": "signatures"},
        aliases={"signature": ("signature", "rule"), "src": ("source", "src"),
                 "dst": ("destination", "dst")},
        event_kinds=("ALERT", "EVENT"),
        endpoints=("SYSLOG_READ udp/514",),
        notes="a sensor with no query API: syslog alerts only, and coverage is declared "
              "partial rather than assumed complete",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not an IDS dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
