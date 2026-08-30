"""Passive network discovery — discover without probing.

Banks and critical infrastructure often forbid active scanning. This engine
consumes whatever metadata is already flowing (SPAN/TAP captures, flow
metadata, firewall / load-balancer / VPN / proxy / DNS logs, TLS handshake
metadata) and produces the same CryptoObservation records the active path
does — with method="passive" and an honest confidence.

Existing passive sources (Envoy / Istio telemetry) plug in here too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from network_scanner.enterprise.protocols.engine import ProtocolObservation

SOURCE_KINDS = ("SPAN", "TAP", "FLOW", "FIREWALL_LOG", "LB_LOG", "VPN_LOG",
                "PROXY_LOG", "DNS_LOG", "TLS_HANDSHAKE", "ENVOY", "ISTIO")

# key=value / tokenized log line extractors
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_FQDN_RE = re.compile(r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_TLS_RE = re.compile(
    r"(?i)(?:tls|ssl)[^ ]*[=:](\S+)"          # tls=TLSv1.3 / ssl-version:TLSv1.2
    r"|version[=:](TLSv?[0-9.]+)"              # version=TLSv1.2 (firewall logs)
    r"|\b(TLSv?1\.[0-9])\b"                    # bare "TLS1.3 negotiated"
)
_CIPHER_RE = re.compile(r"(?i)(cipher|ciphersuite|cipher_suite)[=:](\S+)")


@dataclass
class PassiveSource:
    kind: str
    name: str
    lines: list[str] = field(default_factory=list)
    parser: Callable[[str], dict[str, Any] | None] | None = None


@dataclass
class PassiveObservation:
    """One crypto-relevant observation extracted from passive metadata."""

    asset: str
    source_kind: str
    protocol: str | None = None
    tls_version: str | None = None
    cipher_suite: str | None = None
    certificate_fingerprint: str | None = None
    detail: str | None = None
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "source_kind": self.source_kind,
            "protocol": self.protocol,
            "tls_version": self.tls_version,
            "cipher_suite": self.cipher_suite,
            "certificate_fingerprint": self.certificate_fingerprint,
            "detail": self.detail,
            "confidence": round(self.confidence, 3),
            "method": "passive",
        }


def _pick_ip(line: str) -> str | None:
    match = _IP_RE.search(line)
    return match.group(1) if match else None


def _pick_fqdn(line: str) -> str | None:
    match = _FQDN_RE.search(line)
    return match.group(0) if match else None


def extract_tls_from_line(line: str, *, source_kind: str, default_asset: str | None = None) -> PassiveObservation | None:
    """Parse one log line into a TLS/crypto observation (best effort)."""
    ip = _pick_ip(line)
    fqdn = _pick_fqdn(line)
    asset = fqdn or ip or default_asset
    if not asset:
        return None
    tls_match = _TLS_RE.search(line)
    cipher_match = _CIPHER_RE.search(line)
    protocol = "TLS" if tls_match or cipher_match else None
    fingerprint = None
    fp_match = re.search(r"(?i)(sha256|fingerprint)[=:]([0-9a-f]{64})", line)
    if fp_match:
        fingerprint = fp_match.group(2).lower()
    if protocol is None and fingerprint is None:
        return None
    tls_version = None
    if tls_match:
        tls_version = next((g for g in (tls_match.group(1), tls_match.group(2),
                                        tls_match.group(3)) if g), None)
    return PassiveObservation(
        asset=asset,
        source_kind=source_kind,
        protocol=protocol or ("TLS" if fingerprint else None),
        tls_version=tls_version,
        cipher_suite=cipher_match.group(2) if cipher_match else None,
        certificate_fingerprint=fingerprint,
        detail=line.strip()[:200],
        confidence=0.6 if source_kind in ("TLS_HANDSHAKE", "ENVOY", "ISTIO") else 0.5,
    )


class PassiveDiscoveryEngine:
    """Consumes passive sources and emits observations + protocol records."""

    def __init__(self) -> None:
        self._observations: list[PassiveObservation] = []
        self._assets: dict[str, str] = {}  # asset -> zone hint if found

    def ingest(self, source: PassiveSource) -> int:
        count = 0
        for line in source.lines:
            obs = extract_tls_from_line(line, source_kind=source.kind)
            if obs is None and source.parser is not None:
                parsed = source.parser(line)
                if parsed:
                    obs = PassiveObservation(**parsed)
            if obs is not None:
                self._observations.append(obs)
                self._assets.setdefault(obs.asset, "")
                count += 1
        return count

    def ingest_many(self, sources: Iterable[PassiveSource]) -> int:
        total = 0
        for source in sources:
            total += self.ingest(source)
        return total

    def observations(self) -> list[PassiveObservation]:
        return list(self._observations)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [obs.to_dict() for obs in self._observations]

    def assets(self) -> list[str]:
        return sorted(self._assets)

    def to_protocol_observations(self) -> list[ProtocolObservation]:
        out: list[ProtocolObservation] = []
        for obs in self._observations:
            if obs.protocol:
                out.append(ProtocolObservation(obs.asset, obs.protocol,
                                               "CRYPTOGRAPHY_OBSERVED" if obs.tls_version or obs.cipher_suite
                                               else "PROTOCOL_PRESENT",
                                               method="passive", detail=obs.detail,
                                               confidence=obs.confidence,
                                               extra={"source_kind": obs.source_kind}))
        return out

    def count(self) -> int:
        return len(self._observations)
