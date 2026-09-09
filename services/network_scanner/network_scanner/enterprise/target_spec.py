"""Global Network Target Discovery — target spec parsing and expansion.

Supports every target kind an enterprise scanner must take as input:

- single IP (v4/v6), hostname, FQDN, domain, subdomain scope (``*.example.com``)
- IPv4 range ``10.0.0.1-10.0.0.254``, IPv6 range, CIDR ``10.0.0.0/24``
- internal DNS zones, data-center / branch-office / cloud-VPC / VPN / SD-WAN /
  MPLS networks, Kubernetes networks

Every input normalizes into a :class:`TargetSpec` carrying a ``scope`` from
the enterprise taxonomy and an expandable host list (the engine decides how
much to actually probe per scan mode).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

SCOPES = (
    "SINGLE_HOST",
    "IP_RANGE",
    "CIDR_RANGE",
    "DOMAIN",
    "SUBDOMAIN_SCOPE",
    "NETWORK_ZONE",
    "DATA_CENTER",
    "BRANCH_OFFICE",
    "CLOUD_NETWORK",
    "VPN_NETWORK",
    "SD_WAN",
    "KUBERNETES_CLUSTER",
    "GLOBAL_ENTERPRISE_SCOPE",
)

SUPPORTED_TARGET_TYPES = (
    "ipv4",
    "ipv6",
    "ipv4_range",
    "ipv6_range",
    "cidr",
    "single_ip",
    "hostname",
    "fqdn",
    "domain",
    "subdomain",
    "dns_zone",
    "network_zone",
    "data_center",
    "dc",
    "branch_office",
    "branch",
    "cloud_network",
    "cloud_vpc",
    "vpc",
    "cloud_vnet",
    "vnet",
    "vpn_network",
    "vpn",
    "mpls_network",
    "mpls",
    "sd_wan",
    "sdwan_network",
    "sdwan",
    "kubernetes",
    "kubernetes_cluster",
    "k8s",
    "global_enterprise_scope",
)

# aliases -> canonical target type
_TARGET_TYPE_ALIASES = {
    "dc": "data_center",
    "branch": "branch_office",
    "cloud_vpc": "cloud_network",
    "vpc": "cloud_network",
    "cloud_vnet": "cloud_network",
    "vnet": "cloud_network",
    "vpn": "vpn_network",
    "mpls_network": "vpn_network",
    "mpls": "vpn_network",
    "sdwan_network": "sd_wan",
    "sdwan": "sd_wan",
    "kubernetes_cluster": "kubernetes",
    "k8s": "kubernetes",
    "single_ip": "hostname",
}

# kinds that map to the umbrella global scope
_GLOBAL_SCOPE_KINDS = {"global_enterprise_scope"}

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
SUBDOMAIN_RE = re.compile(r"^\*\.(.+)$")


@dataclass
class TargetSpec:
    """A normalized discovery target."""

    value: str
    scope: str = "SINGLE_HOST"
    target_type: str = "hostname"
    name: str | None = None  # zone / network name (e.g. 'Dubai-DC', 'branch-12')
    zones: list[str] = field(default_factory=list)  # component zones/networks
    hosts: list[str] = field(default_factory=list)  # pre-expanded hosts (small ranges)
    networks: list[str] = field(default_factory=list)  # CIDRs / ranges (kept as ranges)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "scope": self.scope,
            "target_type": self.target_type,
            "name": self.name,
            "zones": list(self.zones),
            "hosts": list(self.hosts),
            "networks": list(self.networks),
            "metadata": dict(self.metadata),
        }

    def expand_hosts(self, *, cap: int = 4096) -> list[str]:
        """Expand small address sets; large ranges stay as networks (caller
        decides sweeping strategy per scan mode). Never silently exceeds cap."""
        out: list[str] = []
        for net in self.networks:
            try:
                network = ipaddress.ip_network(net, strict=False)
            except ValueError:
                continue
            if network.num_addresses > cap:
                out.append(str(network))
                continue
            for host in network.hosts():
                out.append(str(host))
                if len(out) >= cap:
                    return out
        out.extend(self.hosts)
        return out[:cap]


def classify_target(value: str) -> str:
    """Classify an arbitrary target string into a scope."""
    value = value.strip()
    if not value:
        return "SINGLE_HOST"
    try:
        _ip = ipaddress.ip_address(value)
        return "SINGLE_HOST"
    except ValueError:
        pass
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return "CIDR_RANGE"
        except ValueError:
            pass
    if "-" in value and not SUBDOMAIN_RE.match(value):
        left, right = value.split("-", 1)
        try:
            a = ipaddress.ip_address(left.strip())
            b = ipaddress.ip_address(right.strip())
            if a.version == b.version:
                return "IP_RANGE"
        except ValueError:
            pass
    if SUBDOMAIN_RE.match(value):
        return "SUBDOMAIN_SCOPE"
    if HOSTNAME_RE.match(value) and "." in value:
        # domain (no labels like www) vs FQDN — heuristic: a bare domain has
        # 2 labels (example.com); deeper names are FQDNs/hostnames.
        return "DOMAIN" if len(value.split(".")) <= 2 else "SINGLE_HOST"
    if HOSTNAME_RE.match(value):
        return "SINGLE_HOST"
    return "SINGLE_HOST"


def parse_target_spec(value: str, *, name: str | None = None) -> TargetSpec:
    """Parse one target string into a TargetSpec with scope + expansion data."""
    value = value.strip()
    if not value:
        raise ValueError("empty target spec")
    scope = classify_target(value)

    if scope == "SINGLE_HOST":
        try:
            ip = ipaddress.ip_address(value)
            return TargetSpec(value, "SINGLE_HOST", f"ipv{ip.version}", name=name, hosts=[str(ip)],
                              metadata={"address_family": f"ipv{ip.version}"})
        except ValueError:
            pass
        return TargetSpec(value, "SINGLE_HOST", "fqdn" if "." in value else "hostname", name=name, hosts=[value])

    if scope == "CIDR_RANGE":
        network = ipaddress.ip_network(value, strict=False)
        return TargetSpec(value, "CIDR_RANGE", f"ipv{network.version}_cidr", name=name,
                          networks=[str(network)],
                          metadata={"cidr": str(network), "address_family": f"ipv{network.version}",
                                    "num_addresses": int(network.num_addresses)})

    if scope == "IP_RANGE":
        left, right = (part.strip() for part in value.split("-", 1))
        a = ipaddress.ip_address(left)
        b = ipaddress.ip_address(right)
        hosts: list[str] = []
        networks: list[str] = []
        current = a
        while current <= b:
            hosts.append(str(current))
            if len(hosts) > 1024:
                networks.append(f"{a}/{a.max_prefixlen - (int(b) - int(a)).bit_length()}")
                break
            current += 1
        return TargetSpec(value, "IP_RANGE", f"ipv{a.version}_range", name=name, hosts=hosts, networks=networks)

    if scope == "SUBDOMAIN_SCOPE":
        zone = SUBDOMAIN_RE.match(value).group(1)
        return TargetSpec(value, "SUBDOMAIN_SCOPE", "subdomain", name=name,
                          metadata={"zone": zone}, zones=[zone])

    if scope == "DOMAIN":
        return TargetSpec(value, "DOMAIN", "domain", name=name, metadata={"domain": value})

    return TargetSpec(value, scope, "hostname", name=name)


_SCOPE_BY_KIND = {
    "dns_zone": "NETWORK_ZONE",
    "network_zone": "NETWORK_ZONE",
    "data_center": "DATA_CENTER",
    "branch_office": "BRANCH_OFFICE",
    "cloud_network": "CLOUD_NETWORK",
    "vpn_network": "VPN_NETWORK",
    "sd_wan": "SD_WAN",
    "kubernetes": "KUBERNETES_CLUSTER",
}


def parse_scope_spec(spec: dict[str, Any] | str) -> TargetSpec:
    """Parse a structured scope spec (dict) or a bare target string.

    Structured form::

        {"kind": "data_center", "name": "Dubai-DC",
         "networks": ["10.10.0.0/16"], "zones": ["DXB-DC-1", "DXB-DC-2"]}

    ``kind`` is one of the SUPPORTED_TARGET_TYPES; unknown kinds raise.
    """
    if isinstance(spec, str):
        return parse_target_spec(spec)
    if not isinstance(spec, dict):
        raise TypeError("scope spec must be a string or dict")
    kind = str(spec.get("kind") or "network_zone")
    if kind not in SUPPORTED_TARGET_TYPES:
        raise ValueError(f"unsupported scope kind '{kind}' (supported: {', '.join(SUPPORTED_TARGET_TYPES)})")
    canonical = _TARGET_TYPE_ALIASES.get(kind, kind)
    if kind in _GLOBAL_SCOPE_KINDS:
        scope = "GLOBAL_ENTERPRISE_SCOPE"
    else:
        scope = _SCOPE_BY_KIND.get(canonical, "NETWORK_ZONE")
    name = str(spec.get("name") or spec.get("value") or "unnamed")
    networks = [str(n) for n in (spec.get("networks") or []) if str(n).strip()]
    zones = [str(z) for z in (spec.get("zones") or []) if str(z).strip()]
    hosts = [str(h) for h in (spec.get("hosts") or []) if str(h).strip()]
    metadata = {k: v for k, v in (spec.get("metadata") or {}).items()}
    return TargetSpec(str(spec.get("value") or name), scope, canonical, name=name,
                      networks=networks, zones=zones, hosts=hosts, metadata=metadata)


def parse_many(values: Iterable[str | dict[str, Any]]) -> list[TargetSpec]:
    return [parse_scope_spec(v) for v in values]


def scope_label(scope: str) -> str:
    return scope.replace("_", " ").title()
