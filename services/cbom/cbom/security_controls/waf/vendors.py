"""WAF dialects: ModSecurity/CRS, F5 ASM, and an operator-declared proxy."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "modsecurity": AdapterSpec(
        key="waf.modsecurity",
        control="WAF",
        vendor="OWASP",
        product="ModSecurity + CRS",
        operations=("READ_CONFIG_FILE", "TAIL_EVENTS"),
        sections={"policies": "policies", "routes": "routes",
                  "certificates": "certificates", "audit_log": "events"},
        aliases={"policy": ("SecRuleEngine",), "mode": ("mode",),
                 "ruleset_version": ("crs_version",), "signature": ("rule_id",),
                 "src": ("client_ip",), "hostname": ("host",)},
        event_kinds=("ALERT", "EVENT", "BLOCK"),
        endpoints=("READ_CONFIG_FILE /etc/modsecurity/modsecurity.conf",
                   "TAIL_EVENTS /var/log/modsec_audit.log"),
        notes="the audit log's request/response bodies are dropped by the contract before "
              "normalization, and the drop is recorded",
    ),
    "f5_asm": AdapterSpec(
        key="waf.f5_asm",
        control="WAF",
        vendor="F5",
        product="BIG-IP ASM",
        operations=("API_GET",),
        sections={"policies": "policies", "routes": "routes",
                  "certificates": "certificates", "requests": "events"},
        aliases={"policy": ("name",), "mode": ("enforcementMode",),
                 "ruleset_version": ("signatureVersion",), "hostname": ("host",),
                 "cipher_suite": ("cipher",)},
        event_kinds=("ALERT", "EVENT", "BLOCK"),
        endpoints=("GET /mgmt/tm/asm/policies",
                   "GET /mgmt/tm/asm/events/requests"),
        notes="ASM request events include headers; cookies and authorization are redacted",
    ),
    "vendor": AdapterSpec(
        key="waf.vendor",
        control="WAF",
        vendor="(declared by the operator)",
        product="WAF",
        operations=("API_GET", "READ_CONFIG_FILE"),
        sections={"policies": "policies", "routes": "routes",
                  "certificates": "certificates", "events": "events"},
        aliases={},
        event_kinds=("ALERT", "EVENT", "BLOCK"),
        endpoints=("GET /",),
        notes="an unknown WAF is described by the operator's section names, not guessed",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not a WAF dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
