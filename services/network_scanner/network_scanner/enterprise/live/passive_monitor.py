"""Passive Network Monitoring (MODE 2).

Sources: SPAN/TAP, NetFlow, IPFIX, sFlow, firewall logs, VPN logs, DNS logs,
load balancer logs, TLS handshake metadata, SIEM events.

    Network Traffic → Passive Sensor → Metadata Extraction → Protocol
    Detection → Crypto Intelligence → CryptoObservation

Focus is metadata + cryptographic characteristics — never indiscriminate
payload collection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

PASSIVE_SOURCE_KINDS = (
    "SPAN_TAP", "NETFLOW", "IPFIX", "SFLOW", "FIREWALL_LOGS", "VPN_LOGS",
    "DNS_LOGS", "LOAD_BALANCER_LOGS", "TLS_HANDSHAKE_METADATA", "SIEM_EVENTS",
)

# field synonyms the metadata extractor understands
_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "asset": ("asset", "host", "hostname", "src_host", "device", "dst_host"),
    "ip": ("ip", "src_ip", "dst_ip", "client_ip", "server_ip"),
    "protocol": ("protocol", "tls", "application_protocol"),
    "tls_version": ("tls_version", "ssl_version"),
    "cipher_suite": ("cipher_suite", "cipher", "cipher_suites"),
    "certificate_fingerprint": ("certificate_fingerprint", "cert_sha256",
                                "cert_fingerprint", "sha256"),
    "algorithm": ("algorithm", "key_exchange", "signature_algorithm"),
    "key_size": ("key_size", "public_key_size"),
}


@dataclass
class CryptoObservation:
    """One cryptographic characteristic observed passively."""

    asset: str
    protocol: str = ""
    tls_version: str = ""
    cipher_suite: str = ""
    certificate_fingerprint: str = ""
    source_kind: str = "TLS_HANDSHAKE_METADATA"
    algorithm: str = ""
    key_size: Any = None
    confidence: float = 0.5
    observed_at: Any = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        observed = self.observed_at
        if hasattr(observed, "isoformat"):
            observed = observed.isoformat()
        return {"asset": self.asset, "protocol": self.protocol,
                "tls_version": self.tls_version,
                "cipher_suite": self.cipher_suite,
                "certificate_fingerprint": self.certificate_fingerprint,
                "source_kind": self.source_kind,
                "algorithm": self.algorithm, "key_size": self.key_size,
                "confidence": self.confidence, "observed_at": observed,
                "detail": self.detail}


class PassiveSensor:
    """A named, pollable passive source (injectable record stream)."""

    def __init__(self, kind: str, name: str = "",
                 records: Iterable[dict[str, Any]] = ()) -> None:
        if kind not in PASSIVE_SOURCE_KINDS:
            raise ValueError(f"unknown passive source kind '{kind}' "
                             f"(choose from {PASSIVE_SOURCE_KINDS})")
        self.kind = kind
        self.name = name or kind.lower()
        self._records = list(records)

    def poll(self) -> list[dict[str, Any]]:
        records, self._records = self._records, []
        return records

    def feed(self, record: dict[str, Any]) -> None:
        self._records.append(record)


class MetadataExtractor:
    """Converts raw passive records into ``CryptoObservation``."""

    def __init__(self, *, default_protocol: Callable[[str], str] | None = None) -> None:
        # source kind → protocol hint (NetFlow doesn't carry TLS version)
        self._default_protocol = default_protocol or (
            lambda kind: "TLS" if kind in ("TLS_HANDSHAKE_METADATA",
                                           "LOAD_BALANCER_LOGS") else "")

    @staticmethod
    def _pick(record: dict[str, Any], names: tuple[str, ...]) -> Any:
        for name in names:
            if name in record and record[name] not in (None, ""):
                return record[name]
        return None

    def extract(self, record: dict[str, Any], *,
                source_kind: str = "TLS_HANDSHAKE_METADATA",
                observed_at: Any | None = None) -> CryptoObservation | None:
        if not isinstance(record, dict) or not record:
            return None
        asset = self._pick(record, _FIELD_ALIASES["asset"])
        if asset is None:
            asset = self._pick(record, _FIELD_ALIASES["ip"])
        if asset is None:
            return None
        protocol = self._pick(record, _FIELD_ALIASES["protocol"])
        if not protocol:
            protocol = self._default_protocol(source_kind)
        tls_version = self._pick(record, _FIELD_ALIASES["tls_version"])
        cipher = self._pick(record, _FIELD_ALIASES["cipher_suite"])
        fingerprint = self._pick(record, _FIELD_ALIASES["certificate_fingerprint"])
        algorithm = self._pick(record, _FIELD_ALIASES["algorithm"])
        key_size = self._pick(record, _FIELD_ALIASES["key_size"])
        confidence = record.get("confidence", 0.5)
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.5
        return CryptoObservation(
            asset=str(asset), protocol=str(protocol or ""),
            tls_version=str(tls_version or ""),
            cipher_suite=str(cipher or ""),
            certificate_fingerprint=str(fingerprint or ""),
            source_kind=source_kind,
            algorithm=str(algorithm or ""),
            key_size=key_size,
            confidence=confidence,
            observed_at=observed_at or datetime.now(timezone.utc),
            detail=record.get("detail", ""),
        )


class PassiveMonitor:
    """Polls passive sensors and emits ``CryptoObservation`` batches."""

    def __init__(self, *, sensors: Iterable[PassiveSensor] | None = None,
                 extractor: MetadataExtractor | None = None,
                 clock: Callable[[], Any] | None = None) -> None:
        self._sensors: list[PassiveSensor] = list(sensors or [])
        self._extractor = extractor or MetadataExtractor()
        self._observations: list[CryptoObservation] = []
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def add_sensor(self, sensor: PassiveSensor) -> None:
        self._sensors.append(sensor)

    def observations(self) -> list[CryptoObservation]:
        return list(self._observations)

    def poll(self, *, now: Any | None = None) -> list[CryptoObservation]:
        now = now if now is not None else self._clock()
        batch: list[CryptoObservation] = []
        for sensor in self._sensors:
            for record in sensor.poll():
                obs = self._extractor.extract(record, source_kind=sensor.kind,
                                              observed_at=now)
                if obs is not None:
                    batch.append(obs)
        self._observations.extend(batch)
        return batch

    def drain(self) -> list[CryptoObservation]:
        out, self._observations = self._observations, []
        return out

    def to_dicts(self) -> list[dict[str, Any]]:
        return [obs.to_dict() for obs in self._observations]
