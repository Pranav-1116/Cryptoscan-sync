"""VPN and secure tunnel discovery — unified tunnel model.

Supports IPsec (IKEv1/IKEv2), SSL VPN, OpenVPN, WireGuard and enterprise
remote-access VPN metadata. Every tunnel records the schema:

    tunnel_id, endpoint_a, endpoint_b, protocol, encryption_algorithm,
    integrity_algorithm, key_exchange, dh_group, certificate_reference,
    status, environment

Each tunnel gets a PQC migration impact assessment via the shared quantum
risk engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from network_scanner.enterprise.protocols.engine import ProtocolObservation

TUNNEL_PROTOCOLS = ("IPsec", "IKEv1", "IKEv2", "SSL-VPN", "OpenVPN", "WireGuard", "SSTP")


@dataclass
class Tunnel:
    tunnel_id: str
    endpoint_a: str
    endpoint_b: str
    protocol: str = "IPsec"
    encryption_algorithm: str | None = None
    integrity_algorithm: str | None = None
    key_exchange: str | None = None
    dh_group: int | None = None
    certificate_reference: str | None = None
    status: str = "unknown"
    environment: str | None = None
    pre_shared_key_used: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.protocol not in TUNNEL_PROTOCOLS and not self.protocol.startswith("IPsec"):
            raise ValueError(f"unsupported tunnel protocol '{self.protocol}' (choose from {TUNNEL_PROTOCOLS})")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tunnel_id": self.tunnel_id,
            "endpoint_a": self.endpoint_a,
            "endpoint_b": self.endpoint_b,
            "protocol": self.protocol,
            "encryption_algorithm": self.encryption_algorithm,
            "integrity_algorithm": self.integrity_algorithm,
            "key_exchange": self.key_exchange,
            "dh_group": self.dh_group,
            "certificate_reference": self.certificate_reference,
            "status": self.status,
            "environment": self.environment,
            "pre_shared_key_used": self.pre_shared_key_used,
            "extra": dict(self.extra),
        }


WEAK_ENCRYPTION = {"des", "3des", "rc4", "null"}
WEAK_INTEGRITY = {"md5", "sha1"}
WEAK_DH = {1, 2, 5}


def tunnel_issues(tunnel: Tunnel) -> list[str]:
    issues: list[str] = []
    enc = (tunnel.encryption_algorithm or "").lower()
    if enc in WEAK_ENCRYPTION:
        issues.append(f"WEAK_TUNNEL_ENCRYPTION:{tunnel.tunnel_id}:{enc}")
    integ = (tunnel.integrity_algorithm or "").lower()
    if integ in WEAK_INTEGRITY:
        issues.append(f"WEAK_TUNNEL_INTEGRITY:{tunnel.tunnel_id}:{integ}")
    if tunnel.dh_group in WEAK_DH:
        issues.append(f"WEAK_TUNNEL_DH:{tunnel.tunnel_id}:{tunnel.dh_group}")
    if tunnel.pre_shared_key_used and not tunnel.certificate_reference:
        issues.append(f"TUNNEL_PSK_ONLY:{tunnel.tunnel_id}")
    return issues


def pqc_migration_impact(tunnel: Tunnel) -> dict[str, Any]:
    """PQC impact via the shared quantum risk classifier."""
    try:
        from quantum.risk import classify  # type: ignore
    except Exception:
        return {"computable": False, "reason": "quantum engine unavailable"}
    results = {}
    for name, value in (("encryption", tunnel.encryption_algorithm),
                        ("key_exchange", tunnel.key_exchange),
                        ("integrity", tunnel.integrity_algorithm)):
        if not value:
            continue
        info = classify(value)
        results[name] = {
            "algorithm": value,
            "vulnerable": info.get("vulnerable"),
            "threat_type": info.get("threat_type"),
            "recommended_replacement": info.get("recommended_replacement"),
            "hybrid_mode_recommended": info.get("hybrid_mode_recommended"),
        }
    vulnerable = any(v.get("vulnerable") for v in results.values())
    return {
        "computable": bool(results),
        "pqc_status": "MIGRATION_REQUIRED" if vulnerable else ("COMPATIBLE" if results else "UNKNOWN"),
        "impacted_algorithms": list(results),
        "details": results,
    }


def tunnel_protocol_observations(tunnel: Tunnel) -> list[ProtocolObservation]:
    status = "CRYPTOGRAPHY_VERIFIED" if tunnel.status == "up" else "CRYPTOGRAPHY_CONFIGURED"
    return [
        ProtocolObservation(
            tunnel.endpoint_a, tunnel.protocol, status, method="tunnel-model",
            detail=f"{tunnel.encryption_algorithm}/{tunnel.integrity_algorithm} dh={tunnel.dh_group}",
            confidence=0.8,
            extra={"tunnel_id": tunnel.tunnel_id, "peer": tunnel.endpoint_b},
        )
    ]


def tunnels_from_ike_probe(probe_results: Iterable[dict[str, Any]]) -> list[Tunnel]:
    """Turn IKE probe findings into tunnel records (single-endpoint view)."""
    tunnels: list[Tunnel] = []
    for probe in probe_results:
        if probe.get("status") != "OK":
            continue
        proposals = probe.get("proposals") or []
        encr = integ = dh = None
        for proposal in proposals:
            for transform in proposal.get("transforms") or []:
                ttype = transform.get("type")
                if ttype == 1:  # ENCR
                    encr = encr or transform.get("name")
                elif ttype in (2, 3):  # PRF/INTEG
                    integ = integ or transform.get("name")
                elif ttype == 4:  # DH
                    dh = transform.get("id")
        tunnels.append(Tunnel(
            tunnel_id=f"ike-{probe.get('endpoint')}",
            endpoint_a="<local>",
            endpoint_b=probe.get("endpoint"),
            protocol="IPsec",
            encryption_algorithm=encr,
            integrity_algorithm=integ,
            dh_group=dh,
            status="observed",
            environment="probed",
            extra={"probe_issues": probe.get("issues") or []},
        ))
    return tunnels
