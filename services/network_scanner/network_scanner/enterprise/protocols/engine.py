"""Universal protocol fingerprinting engine.

Classification is strict — these statuses are NOT equivalent:

- ``PROTOCOL_PRESENT``        — the endpoint speaks the protocol (banner/port)
- ``CRYPTOGRAPHY_OBSERVED``   — a live crypto exchange was observed
- ``CRYPTOGRAPHY_CONFIGURED`` — configuration/API says what crypto is set
- ``CRYPTOGRAPHY_VERIFIED``   — an independent check confirmed the config

The engine combines probe observations, passive metadata and vendor config
into one protocol record per asset/protocol pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from network_scanner.enterprise.protocols.probes import probe_udp_protocols, probe_tcp_banners

ENCRYPTION_PROTOCOLS = ("TLS", "DTLS", "QUIC", "SSH", "IPsec", "IKE", "WireGuard",
                        "OpenVPN", "SSTP")
APPLICATION_PROTOCOLS = ("HTTP/HTTPS", "SMTP/STARTTLS", "IMAP/STARTTLS", "POP3/STARTTLS",
                         "LDAP/LDAPS", "FTPS", "MQTT", "AMQP", "DB-TLS", "RDP-TLS",
                         "K8S-API-TLS")
ENTERPRISE_PROTOCOLS = ("SAML", "OAuth", "OIDC", "Kerberos", "AD-CS")

ALL_PROTOCOLS = ENCRYPTION_PROTOCOLS + APPLICATION_PROTOCOLS + ENTERPRISE_PROTOCOLS

STATUSES = ("PROTOCOL_PRESENT", "CRYPTOGRAPHY_OBSERVED",
            "CRYPTOGRAPHY_CONFIGURED", "CRYPTOGRAPHY_VERIFIED")

_ORDER = {status: idx for idx, status in enumerate(STATUSES)}


def merge_status(a: str, b: str) -> str:
    """The stronger of two classification statuses."""
    return a if _ORDER.get(a, 0) >= _ORDER.get(b, 0) else b


@dataclass
class ProtocolObservation:
    asset: str
    protocol: str
    status: str = "PROTOCOL_PRESENT"
    method: str = "probe"
    detail: str | None = None
    confidence: float = 0.5
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "protocol": self.protocol,
            "status": self.status,
            "method": self.method,
            "detail": self.detail,
            "confidence": round(self.confidence, 3),
            "extra": dict(self.extra),
        }


def status_from_findings(protocol: str, findings: Iterable[dict[str, Any]]) -> str:
    """Derive a classification from existing scan findings (TLS/SSH/IPsec…).

    ``CRYPTOGRAPHY_VERIFIED`` requires an actual handshake observation with a
    negotiated cipher — never inferred from port state alone.
    """
    status = "PROTOCOL_PRESENT"
    crypto_seen = False
    for finding in findings:
        crypto = finding.get("crypto") or {}
        if finding.get("status") == "OK":
            status = "CRYPTOGRAPHY_OBSERVED"
        if crypto.get("cipher_suite") or crypto.get("tls_version"):
            crypto_seen = True
        if crypto.get("algorithm"):
            crypto_seen = True
        issues = finding.get("policy_issues") or []
        if "VERIFIED" in " ".join(issues).upper():
            status = "CRYPTOGRAPHY_VERIFIED"
    if crypto_seen and status in ("PROTOCOL_PRESENT", "CRYPTOGRAPHY_OBSERVED"):
        status = "CRYPTOGRAPHY_OBSERVED" if status == "PROTOCOL_PRESENT" else status
    return status


class ProtocolDetectionEngine:
    """Combines active probes, passive metadata and config into observations."""

    def __init__(self, *, allow_udp_init: bool = False) -> None:
        self.allow_udp_init = allow_udp_init
        self._observations: dict[tuple[str, str], ProtocolObservation] = {}

    def record(self, observation: ProtocolObservation) -> ProtocolObservation:
        key = (observation.asset, observation.protocol)
        existing = self._observations.get(key)
        if existing is None:
            self._observations[key] = observation
            return observation
        existing.status = merge_status(existing.status, observation.status)
        existing.method = existing.method if existing.status == observation.status else "mixed"
        existing.confidence = max(existing.confidence, observation.confidence)
        if observation.detail:
            existing.detail = observation.detail
        return existing

    def record_many(self, observations: Iterable[ProtocolObservation]) -> int:
        count = 0
        for observation in observations:
            self.record(observation)
            count += 1
        return count

    def from_probe_results(self, asset: str, findings: Iterable[dict[str, Any]]) -> int:
        """Ingest scan_hosts / scan_ipsec / scan_ssh results."""
        count = 0
        for finding in findings:
            crypto = finding.get("crypto") or {}
            tls_version = crypto.get("tls_version")
            cipher = crypto.get("cipher_suite")
            if tls_version or cipher:
                obs = ProtocolObservation(
                    asset, "TLS",
                    "CRYPTOGRAPHY_VERIFIED" if tls_version and cipher else "CRYPTOGRAPHY_OBSERVED",
                    method="tls-handshake",
                    detail=f"{tls_version} {cipher}".strip(),
                    confidence=0.95 if tls_version and cipher else 0.8,
                )
                self.record(obs)
                count += 1
        return count

    def from_active_probes(self, host: str, ports: Iterable[int] = (443, 22, 500, 4500)) -> int:
        """Run lightweight probes (safe, single packet / banner read)."""
        count = 0
        udp = probe_udp_protocols(host, ports=[p for p in ports if p in (500, 4500, 51820, 1194, 443, 784)],
                                  allow_init=self.allow_udp_init)
        for protocol, detected in udp.items():
            if detected:
                self.record(ProtocolObservation(host, protocol, "PROTOCOL_PRESENT",
                                                method="udp-probe", confidence=0.7))
                count += 1
        tcp = probe_tcp_banners(host, ports=[p for p in ports if p not in (500, 4500, 51820, 1194, 784)])
        for protocol, detected in tcp.items():
            if detected:
                self.record(ProtocolObservation(host, protocol, "PROTOCOL_PRESENT",
                                                method="tcp-banner", confidence=0.7))
                count += 1
        return count

    def from_passive_metadata(self, asset: str, protocols: Iterable[str]) -> int:
        count = 0
        for protocol in protocols:
            if protocol in ALL_PROTOCOLS:
                self.record(ProtocolObservation(asset, protocol, "CRYPTOGRAPHY_OBSERVED"
                                                if protocol in ENCRYPTION_PROTOCOLS else "PROTOCOL_PRESENT",
                                                method="passive", confidence=0.6))
                count += 1
        return count

    def from_vendor_config(self, asset: str, protocols: Iterable[dict[str, Any]]) -> int:
        count = 0
        for entry in protocols:
            name = entry.get("protocol") or entry.get("name")
            if not name:
                continue
            status = entry.get("status") or "CRYPTOGRAPHY_CONFIGURED"
            if status not in STATUSES:
                status = "CRYPTOGRAPHY_CONFIGURED"
            self.record(ProtocolObservation(asset, name, status, method="vendor-config",
                                            detail=entry.get("detail"), confidence=0.85))
            count += 1
        return count

    def observations(self) -> list[ProtocolObservation]:
        return list(self._observations.values())

    def to_dicts(self) -> list[dict[str, Any]]:
        return [obs.to_dict() for obs in self.observations()]

    def for_asset(self, asset: str) -> list[ProtocolObservation]:
        return [obs for obs in self.observations() if obs.asset == asset]

    def count(self) -> int:
        return len(self._observations)
