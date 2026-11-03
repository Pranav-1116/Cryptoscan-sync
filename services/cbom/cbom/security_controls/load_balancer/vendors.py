"""Load balancer dialects: F5 BIG-IP, NGINX, HAProxy, Avi (NSX ALB)."""

from __future__ import annotations

from typing import Any

from ..base import AdapterSpec, ControlRefused

SPECS: dict[str, AdapterSpec] = {
    "f5": AdapterSpec(
        key="load_balancer.f5",
        control="LOAD_BALANCER",
        vendor="F5",
        product="BIG-IP LTM",
        operations=("API_GET",),
        sections={"virtual": "vips", "pool": "pools", "ssl_profile": "tls_profiles",
                  "client_ssl_profile": "certificates"},
        aliases={"vip": ("name",), "address": ("destination",), "pool": ("pool",),
                 "certificate": ("cert",), "members": ("membersReference",),
                 "cipher_suites": ("ciphers",)},
        endpoints=("GET /mgmt/tm/ltm/virtual", "GET /mgmt/tm/ltm/pool",
                   "GET /mgmt/tm/ltm/profile/client-ssl"),
        notes="a BIG-IP destination is 'address:port'; the address becomes the endpoint node",
    ),
    "nginx": AdapterSpec(
        key="load_balancer.nginx",
        control="LOAD_BALANCER",
        vendor="F5 (NGINX)",
        product="NGINX Plus",
        operations=("API_GET", "READ_CONFIG_FILE"),
        sections={"upstreams": "pools", "server": "vips", "ssl": "tls_profiles"},
        aliases={"vip": ("server_name",), "address": ("listen",), "pool": ("proxy_pass",),
                 "members": ("servers",), "certificate": ("ssl_certificate",),
                 "cipher_suites": ("ssl_ciphers",)},
        endpoints=("GET /api/9/http/upstreams", "READ_CONFIG_FILE /etc/nginx/nginx.conf"),
        notes="the config file is the authoritative source; the API is the observed half",
    ),
    "haproxy": AdapterSpec(
        key="load_balancer.haproxy",
        control="LOAD_BALANCER",
        vendor="HAProxy Technologies",
        product="HAProxy",
        operations=("API_GET", "READ_CONFIG_FILE", "SHOW"),
        sections={"frontend": "vips", "backend": "pools", "bind_ssl": "tls_profiles"},
        aliases={"vip": ("frontend",), "address": ("bind",), "pool": ("default_backend",),
                 "members": ("server",), "certificate": ("crt",),
                 "cipher_suites": ("ciphers",)},
        endpoints=("SHOW stat", "READ_CONFIG_FILE /etc/haproxy/haproxy.cfg"),
        notes="the runtime socket is read-only for stat and info; it also accepts commands, "
              "so the adapter names only the read queries",
    ),
    "avi": AdapterSpec(
        key="load_balancer.avi",
        control="LOAD_BALANCER",
        vendor="Broadcom",
        product="Avi Load Balancer (NSX ALB)",
        operations=("API_GET",),
        sections={"virtualservice": "vips", "pool": "pools",
                  "sslprofile": "tls_profiles", "sslkeyandcertificate": "certificates"},
        aliases={"vip": ("name",), "pool": ("pool_ref",), "members": ("servers",),
                 "cipher_suites": ("cipher_enums",)},
        endpoints=("GET /api/virtualservice", "GET /api/pool",
                   "GET /api/sslkeyandcertificate"),
        notes="sslkeyandcertificate returns metadata; the certificate body is not key material",
    ),
}


def spec_for(vendor: Any) -> AdapterSpec:
    key = str(vendor or "").strip().lower()
    if key in SPECS:
        return SPECS[key]
    raise ControlRefused(
        "UNKNOWN_VENDOR",
        f"{key or '(none)'} is not a load balancer dialect here; add a row to vendors.py "
        f"({', '.join(sorted(SPECS))}) instead of a new architecture")


def dialects() -> dict[str, dict[str, Any]]:
    return {key: spec.capabilities() for key, spec in sorted(SPECS.items())}
