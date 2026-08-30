"""ZELNX Cloud Discovery Engine — cloud TLS discovery (spec §8).

Discovers TLS endpoints across cloud services and classifies each:

    TLS_SECURE | TLS_WEAK | TLS_LEGACY | PQC_MIGRATION_REQUIRED | UNKNOWN

Per-endpoint fields: endpoint, service, application, region, tls_version,
cipher_suites, certificate, certificate_algorithm, signature_algorithm,
key_exchange, public_key_size, curve, alpn, sni.

The classification model is conservative: an endpoint is only SECURE when
its minimum TLS is ≥ 1.2 with a modern key exchange; any RSA < 2048 or
SHA-1 signed certificate pushes it to WEAK/LEGACY.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

EndpointEnumerator = Callable[[], list[dict[str, Any]]]

TLS_SECURE = "TLS_SECURE"
TLS_WEAK = "TLS_WEAK"
TLS_LEGACY = "TLS_LEGACY"
PQC_MIGRATION_REQUIRED = "PQC_MIGRATION_REQUIRED"
UNKNOWN = "UNKNOWN"

CLASSIFICATIONS = (TLS_SECURE, TLS_WEAK, TLS_LEGACY, PQC_MIGRATION_REQUIRED, UNKNOWN)

CLASSICAL_KEY_EXCHANGES = ("RSA", "DH", "DHE", "DSS")
PQC_KEY_EXCHANGES = ("ML-KEM", "KYBER", "X25519MLKEM", "PQC")
LEGACY_TLS = ("SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1")


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class TlsEndpoint:
    """One TLS-terminating endpoint in the cloud estate."""

    endpoint: str
    provider: str = ""
    account: str = ""
    region: str = ""
    service: str = ""
    application: str = ""
    tls_version: str = ""
    cipher_suites: list[str] = field(default_factory=list)
    certificate_id: str = ""
    certificate_algorithm: str = ""
    signature_algorithm: str = ""
    key_exchange: str = ""
    public_key_size: int | None = None
    curve: str = ""
    alpn: list[str] = field(default_factory=list)
    sni: str = ""
    classification: str = UNKNOWN
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "service": self.service,
            "application": self.application,
            "tls_version": self.tls_version,
            "cipher_suites": list(self.cipher_suites),
            "certificate": self.certificate_id,
            "certificate_algorithm": self.certificate_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "key_exchange": self.key_exchange,
            "public_key_size": self.public_key_size,
            "curve": self.curve,
            "alpn": list(self.alpn),
            "sni": self.sni,
            "classification": self.classification,
            "evidence": self.evidence.to_dict(),
        }


def classify_endpoint(
    *,
    tls_version: str,
    key_exchange: str,
    public_key_size: int | None,
    signature_algorithm: str = "",
    pqc_hint: str | None = None,
) -> str:
    """Conservative TLS classification (spec §8)."""
    if pqc_hint and str(pqc_hint).upper() in PQC_KEY_EXCHANGES:
        return TLS_SECURE
    version = str(tls_version or "").upper()
    if not version and not key_exchange:
        return UNKNOWN
    if any(legacy in version for legacy in LEGACY_TLS) or "SSL" in version:
        return TLS_LEGACY
    kex = str(key_exchange or "").upper()
    # elliptic key exchanges first — "DH"/"DHE" are substrings of ECDH(E)
    if "ECDHE" in kex or "ECDH" in kex or "X25519" in kex or "X448" in kex:
        sig = str(signature_algorithm or "").upper()
        if "SHA1" in sig or "MD5" in sig:
            return TLS_WEAK
        if "1.2" in version or "1.3" in version or not version:
            return TLS_SECURE
        return TLS_WEAK
    if any(classical in kex for classical in CLASSICAL_KEY_EXCHANGES):
        if public_key_size is not None and public_key_size < 2048:
            return TLS_WEAK
        return PQC_MIGRATION_REQUIRED
    return UNKNOWN


def normalize_endpoint(row: dict[str, Any], *, provider: str) -> TlsEndpoint:
    tls_version = str(_pick(row, "tls_version", "min_tls", "tlsVersion", default="") or "")
    key_exchange = str(_pick(row, "key_exchange", "keyExchange", "key_exchange_algorithm",
                             default="") or "")
    pub_size = _pick(row, "public_key_size", "key_size", "publicKeySize", default=None)
    sig = str(_pick(row, "signature_algorithm", "signatureAlgorithm", default="") or "")
    classification = classify_endpoint(
        tls_version=tls_version,
        key_exchange=key_exchange,
        public_key_size=int(pub_size) if isinstance(pub_size, (int, float)) else None,
        signature_algorithm=sig,
        pqc_hint=_pick(row, "pqc_hint", "key_exchange", default=None),
    )
    return TlsEndpoint(
        endpoint=str(_pick(row, "endpoint", "hostname", "dns_name", "url", default="") or ""),
        provider=provider,
        account=str(_pick(row, "account", "subscription", "project", default="") or ""),
        region=str(_pick(row, "region", default="") or ""),
        service=str(_pick(row, "service", default="") or ""),
        application=str(_pick(row, "application", "app", default="") or ""),
        tls_version=tls_version,
        cipher_suites=[str(c) for c in (_pick(row, "cipher_suites", "ciphers", default=[]) or [])],
        certificate_id=str(_pick(row, "certificate_id", "certificate", "cert_arn", default="") or ""),
        certificate_algorithm=str(_pick(row, "certificate_algorithm", "cert_algorithm",
                                        default="") or ""),
        signature_algorithm=sig,
        key_exchange=key_exchange,
        public_key_size=int(pub_size) if isinstance(pub_size, (int, float)) else None,
        curve=str(_pick(row, "curve", default="") or ""),
        alpn=[str(a) for a in (_pick(row, "alpn", "alpn_protocols", default=[]) or [])],
        sni=str(_pick(row, "sni", default="") or ""),
        classification=classification,
        evidence=EvidenceSource(
            source_provider=provider,
            account=str(_pick(row, "account", "subscription", "project", default="") or ""),
            api_source=str(_pick(row, "api_source", default="tls-discovery") or ""),
        ),
    )


@dataclass
class TlsInventory:
    """All discovered TLS endpoints + classification rollup."""

    endpoints: list[TlsEndpoint] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [endpoint.to_dict() for endpoint in self.endpoints]

    def by_classification(self, classification: str) -> list[TlsEndpoint]:
        return [e for e in self.endpoints if e.classification == classification]

    def summary(self) -> dict[str, Any]:
        return {
            "endpoints": len(self.endpoints),
            "by_classification": {
                cls: len(self.by_classification(cls)) for cls in CLASSIFICATIONS
            },
            "errors": self.errors,
        }


class TlsDiscovery:
    """Run TLS endpoint discovery for injected enumerators."""

    def __init__(self, providers: list[dict[str, Any]], *, max_endpoints: int = 2000) -> None:
        self._providers = list(providers)
        self._max_endpoints = max_endpoints

    def discover(self) -> TlsInventory:
        inventory = TlsInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_tls_endpoints")
            if enumerator is None:
                inventory.errors.append(
                    {"provider": provider, "kind": "no_enumerator",
                     "detail": "no enumerate_tls_endpoints callable injected"}
                )
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if len(inventory.endpoints) >= self._max_endpoints:
                    break
                if isinstance(row, dict):
                    inventory.endpoints.append(normalize_endpoint(row, provider=provider))
        return inventory
