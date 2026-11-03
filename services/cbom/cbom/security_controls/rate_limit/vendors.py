"""Rate limiter dialects: NGINX limit_req/limit_conn, Kong rate-limiting, gateway-native."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "nginx": AdapterSpec(
        key="rate_limit.nginx",
        control="RATE_LIMIT",
        vendor="F5 (NGINX)",
        product="NGINX limit_req",
        operations=("READ_CONFIG_FILE",),
        sections={"limit_req_zone": "limits", "location": "mappings",
                  "limit_req_status": "violations"},
        aliases={"limit": ("rate",), "window_seconds": ("window",), "api": ("location",),
                 "policy": ("zone",), "scope": ("key",)},
        endpoints=("READ_CONFIG_FILE /etc/nginx/nginx.conf",),
        notes="limit_req_zone declares the zone; the location block is the attachment, and "
              "a zone with no location is the orphan this audit looks for",
    ),
    "kong": AdapterSpec(
        key="rate_limit.kong",
        control="RATE_LIMIT",
        vendor="Kong",
        product="Kong rate-limiting plugin",
        operations=("API_GET",),
        sections={"plugins": "limits", "routes": "mappings", "logs": "violations"},
        aliases={"limit": ("config.minute", "config.hour"), "policy": ("name",),
                 "api": ("route",), "observed": ("count",)},
        endpoints=("GET /plugins?name=rate-limiting", "GET /routes"),
        notes="the plugin's config map is the limit; its consumer/service scope decides "
              "whether two APIs share one counter",
    ),
    "gateway": AdapterSpec(
        key="rate_limit.gateway",
        control="RATE_LIMIT",
        vendor="(the API gateway's own limiter)",
        product="Gateway quota policy",
        operations=("API_GET",),
        sections={"quotas": "limits", "apis": "mappings", "events": "violations"},
        aliases={"limit": ("quota", "rate"), "policy": ("quota_id", "name"),
                 "api": ("api_id", "route")},
        endpoints=("GET /quotas", "GET /apis"),
        notes="the common case: the limiter is a feature of the gateway, read through the "
              "same read-only API as the routes",
    ),
    "vendor": AdapterSpec(
        key="rate_limit.vendor",
        control="RATE_LIMIT",
        vendor="(declared by the operator)",
        product="Rate limiter",
        operations=("API_GET", "EXPORT_CONFIG"),
        sections={"limits": "limits", "mappings": "mappings", "violations": "violations"},
        aliases={},
        endpoints=("GET /",),
        notes="a standalone appliance; the operator names its sections",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not a rate limiter dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
