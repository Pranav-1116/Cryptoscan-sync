"""SD-WAN discovery — controllers, edges, tunnels, crypto profiles.

Model:

    SD-WAN Controller ── Edge A / Edge B / Edge C
    each Edge ── Tunnel Crypto Profile ── Certificate / Key Infrastructure

Control-plane trust (certificate-based authentication between controller and
edges) and per-tunnel crypto (encryption algorithm, key exchange, DH group)
are the crypto surface the scanner reports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any



@dataclass
class SdwanTunnel:
    tunnel_id: str
    edge: str
    peer_edge: str
    protocol: str = "IPsec"
    encryption_algorithm: str | None = None
    integrity_algorithm: str | None = None
    key_exchange: str | None = None
    dh_group: int | None = None
    certificate_reference: str | None = None
    status: str = "up"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tunnel_id": self.tunnel_id,
            "edge": self.edge,
            "peer_edge": self.peer_edge,
            "protocol": self.protocol,
            "encryption_algorithm": self.encryption_algorithm,
            "integrity_algorithm": self.integrity_algorithm,
            "key_exchange": self.key_exchange,
            "dh_group": self.dh_group,
            "certificate_reference": self.certificate_reference,
            "status": self.status,
        }


@dataclass
class SdwanTopology:
    controller: str
    edges: list[str] = field(default_factory=list)
    tunnels: list[SdwanTunnel] = field(default_factory=list)
    control_plane_trust: str = "UNKNOWN"  # CERTIFICATE / PSK / UNKNOWN
    controller_certificate: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "controller": self.controller,
            "edges": list(self.edges),
            "tunnels": [t.to_dict() for t in self.tunnels],
            "control_plane_trust": self.control_plane_trust,
            "controller_certificate": self.controller_certificate,
        }


WEAK_TUNNEL_ENCR = {"des", "3des", "aes128"}


def discover_sdwan(controller_client: Any, *, controller_name: str = "sdwan-controller") -> SdwanTopology:
    """Discover SD-WAN topology + crypto from an injected controller client.

    The client duck-types: ``list_edges()``, ``list_tunnels()``,
    ``control_plane_trust()`` and ``controller_certificate()`` — implement
    them against vManage / Catalyst SD-WAN or any controller API.
    """
    topo = SdwanTopology(controller=controller_name)
    if hasattr(controller_client, "list_edges"):
        topo.edges = [str(e) for e in (controller_client.list_edges() or [])]
    if hasattr(controller_client, "list_tunnels"):
        for raw in controller_client.list_tunnels() or []:
            topo.tunnels.append(SdwanTunnel(**{k: v for k, v in raw.items() if k in SdwanTunnel.__dataclass_fields__}))
    if hasattr(controller_client, "control_plane_trust"):
        topo.control_plane_trust = str(controller_client.control_plane_trust() or "UNKNOWN").upper()
    if hasattr(controller_client, "controller_certificate"):
        topo.controller_certificate = controller_client.controller_certificate()
    return topo


def sdwan_crypto_issues(topo: SdwanTopology) -> list[str]:
    issues: list[str] = []
    if topo.control_plane_trust == "PSK":
        issues.append("SDWAN_CONTROL_PLANE_PSK")
    for tunnel in topo.tunnels:
        if (tunnel.encryption_algorithm or "").lower() in WEAK_TUNNEL_ENCR:
            issues.append(f"WEAK_SDWAN_TUNNEL_ENCRYPTION:{tunnel.tunnel_id}:{tunnel.encryption_algorithm}")
        if tunnel.dh_group in (1, 2, 5):
            issues.append(f"WEAK_SDWAN_TUNNEL_DH:{tunnel.tunnel_id}:{tunnel.dh_group}")
    return sorted(set(issues))


def sdwan_protocol_observations(topo: SdwanTopology) -> list[dict[str, Any]]:
    obs: list[dict[str, Any]] = []
    for edge in topo.edges:
        obs.append({"protocol": "IPsec", "status": "CRYPTOGRAPHY_CONFIGURED", "detail": f"sd-wan edge {edge}"})
    obs.append({"protocol": "TLS", "status": "CRYPTOGRAPHY_CONFIGURED",
                "detail": "controller control-plane"})
    return obs
