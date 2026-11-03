"""API gateway dialects: Kong, NGINX, Envoy, and an operator-declared gateway."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "kong": AdapterSpec(
        key="api_gateway.kong",
        control="API_GATEWAY",
        vendor="Kong",
        product="Kong Gateway",
        operations=("API_GET",),
        sections={"services": "apis", "routes": "routes",
                  "certificates": "certificates", "plugins": "policies"},
        aliases={"api": ("service", "name"), "route": ("name", "paths"),
                 "upstream": ("upstream_url", "host"), "policy": ("plugin",),
                 "mtls": ("client_certificate",), "methods": ("methods",)},
        endpoints=("GET /services", "GET /routes", "GET /certificates", "GET /plugins"),
        notes="plugins carry config maps that can hold credentials; redaction runs over "
              "every plugin row before it is kept",
    ),
    "nginx": AdapterSpec(
        key="api_gateway.nginx",
        control="API_GATEWAY",
        vendor="F5 (NGINX)",
        product="NGINX as an API gateway",
        operations=("READ_CONFIG_FILE",),
        sections={"server": "apis", "location": "routes", "ssl": "certificates"},
        aliases={"route": ("location",), "upstream": ("proxy_pass",),
                 "tls": ("ssl",), "mtls": ("ssl_verify_client",)},
        endpoints=("READ_CONFIG_FILE /etc/nginx/conf.d/",),
        notes="ssl_verify_client is the mTLS fact; the client CA is a name, not a secret",
    ),
    "envoy": AdapterSpec(
        key="api_gateway.envoy",
        control="API_GATEWAY",
        vendor="Envoy Project",
        product="Envoy",
        operations=("API_GET",),
        sections={"listeners": "apis", "routes": "routes",
                  "tls_context": "certificates", "http_filters": "policies"},
        aliases={"route": ("name", "prefix"), "upstream": ("cluster",),
                 "mtls": ("require_client_certificate",), "tls": ("transport_socket",)},
        endpoints=("GET /config_dump", "GET /clusters"),
        notes="config_dump is the whole effective configuration, including secrets by "
              "reference only; the adapter never resolves a secret reference",
    ),
    "vendor": AdapterSpec(
        key="api_gateway.vendor",
        control="API_GATEWAY",
        vendor="(declared by the operator)",
        product="API gateway",
        operations=("API_GET", "EXPORT_CONFIG"),
        sections={"apis": "apis", "routes": "routes", "certificates": "certificates"},
        aliases={},
        endpoints=("GET /",),
        notes="unknown gateway: the operator names its sections, the contract stays the same",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not an API gateway dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
