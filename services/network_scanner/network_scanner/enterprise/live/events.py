"""Event-driven rescanning — normalizer, asset identification, impact analysis.

The live monitor reacts to events instead of waiting for the next schedule:

    EVENT OCCURS → Event Normalizer → Asset Identification → Impact Analysis
    → Targeted Rescan → Update Evidence → Update Live CBOM

The scan pipeline is never restarted for a single asset change — only the
impacted asset(s) are rescanned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

EVENT_KINDS = (
    "NEW_DEVICE_CONNECTED",
    "DEVICE_DISCONNECTED",
    "CERTIFICATE_REPLACED",
    "CERTIFICATE_EXPIRED",
    "TLS_POLICY_CHANGED",
    "VPN_CONFIG_CHANGED",
    "FIREWALL_CONFIG_CHANGED",
    "CLOUD_RESOURCE_CHANGED",
    "NEW_PUBLIC_ENDPOINT",
    "ROUTING_TOPOLOGY_CHANGED",
    "CRYPTOGRAPHIC_ALGORITHM_CHANGED",
    "PASSIVE_OBSERVATION",
    "SCAN_COMPLETED",
    "DRIFT_DETECTED",
    "AGENT_SYNC",
)

# synonyms accepted by the normalizer → canonical kind
_EVENT_SYNONYMS: dict[str, str] = {
    "new_device": "NEW_DEVICE_CONNECTED",
    "device_connected": "NEW_DEVICE_CONNECTED",
    "host_connected": "NEW_DEVICE_CONNECTED",
    "device_disconnected": "DEVICE_DISCONNECTED",
    "host_disconnected": "DEVICE_DISCONNECTED",
    "cert_replaced": "CERTIFICATE_REPLACED",
    "certificate_renewed": "CERTIFICATE_REPLACED",
    "cert_expired": "CERTIFICATE_EXPIRED",
    "certificate_expired": "CERTIFICATE_EXPIRED",
    "tls_policy_changed": "TLS_POLICY_CHANGED",
    "vpn_config_changed": "VPN_CONFIG_CHANGED",
    "firewall_config_changed": "FIREWALL_CONFIG_CHANGED",
    "cloud_resource_changed": "CLOUD_RESOURCE_CHANGED",
    "public_endpoint": "NEW_PUBLIC_ENDPOINT",
    "new_endpoint": "NEW_PUBLIC_ENDPOINT",
    "route_changed": "ROUTING_TOPOLOGY_CHANGED",
    "topology_changed": "ROUTING_TOPOLOGY_CHANGED",
    "algorithm_changed": "CRYPTOGRAPHIC_ALGORITHM_CHANGED",
    "crypto_algorithm_changed": "CRYPTOGRAPHIC_ALGORITHM_CHANGED",
}

# crypto-affecting event kinds force a targeted DEEP rescan
CRYPTO_EVENT_KINDS = frozenset({
    "CERTIFICATE_REPLACED", "CERTIFICATE_EXPIRED", "TLS_POLICY_CHANGED",
    "VPN_CONFIG_CHANGED", "FIREWALL_CONFIG_CHANGED",
    "CRYPTOGRAPHIC_ALGORITHM_CHANGED", "NEW_PUBLIC_ENDPOINT",
})


@dataclass
class NetworkEvent:
    """A normalized, canonical event understood by the live monitor."""

    kind: str
    source: str
    observed_at: str
    asset_ids: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    severity: str = "INFO"

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind '{self.kind}' (choose from {EVENT_KINDS})")
        if self.severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"unknown severity '{self.severity}'")

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "source": self.source,
                "observed_at": self.observed_at,
                "asset_ids": list(self.asset_ids),
                "payload": dict(self.payload),
                "severity": self.severity}


class EventNormalizer:
    """Maps raw event dicts (vendor/API/SIEM shapes) to ``NetworkEvent``.

    Recognizes ``type``/``kind``/``event`` keys plus a synonym table, and
    extracts ``asset_ids`` from common payload fields (ip, hostname, device,
    endpoint, cert fingerprint).
    """

    def __init__(self, *, synonyms: dict[str, str] | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self._synonyms = dict(_EVENT_SYNONYMS)
        if synonyms:
            self._synonyms.update(synonyms)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _candidate(raw: dict[str, Any]) -> str | None:
        for key in ("kind", "type", "event", "event_type", "event_kind"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        return None

    def normalize(self, raw: dict[str, Any]) -> NetworkEvent | None:
        if not isinstance(raw, dict) or not raw:
            return None
        candidate = self._candidate(raw) or ""
        kind = self._synonyms.get(candidate, candidate.upper().replace(" ", "_"))
        if kind not in EVENT_KINDS:
            return None
        observed = raw.get("observed_at") or raw.get("timestamp") or raw.get("time")
        if not observed:
            observed = self._clock().isoformat()
        asset_ids = EventNormalizer.extract_asset_ids(raw)
        severity = str(raw.get("severity") or "INFO").upper()
        payload = {k: v for k, v in raw.items()
                   if k not in ("kind", "type", "event", "observed_at", "timestamp")}
        try:
            return NetworkEvent(kind=kind, source=str(raw.get("source") or "unknown"),
                                observed_at=str(observed),
                                asset_ids=asset_ids,
                                payload=payload, severity=severity)
        except ValueError:
            return None

    def normalize_many(self, raw_events: Iterable[dict[str, Any]]) -> list[NetworkEvent]:
        out: list[NetworkEvent] = []
        for raw in raw_events:
            event = self.normalize(raw)
            if event is not None:
                out.append(event)
        return out

    @staticmethod
    def extract_asset_ids(raw: dict[str, Any]) -> list[str]:
        ids: list[str] = []
        for key in ("asset_id", "device_id", "device", "host", "hostname",
                    "ip", "endpoint", "certificate_fingerprint", "fingerprint"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                ids.append(value.strip())
            elif isinstance(value, list):
                ids.extend(str(v) for v in value if str(v).strip())
        return list(dict.fromkeys(ids))  # preserve order, dedupe


class AssetIdentification:
    """Resolves event assets against the known asset registry."""

    def __init__(self, *, assets: dict[str, dict[str, Any]] | None = None) -> None:
        # asset_id → asset snapshot
        self._assets: dict[str, dict[str, Any]] = dict(assets or {})
        self._index: dict[str, list[str]] = {}  # identifier → asset_ids

    def register(self, asset_id: str, snapshot: dict[str, Any]) -> None:
        self._assets[asset_id] = dict(snapshot)
        for key in ("ip", "hostname", "fqdn", "asset_identity"):
            value = snapshot.get(key)
            if isinstance(value, str) and value.strip():
                self._index.setdefault(value.strip().lower(), []).append(asset_id)
        ips = snapshot.get("ip_addresses")
        if isinstance(ips, list):
            for ip in ips:
                if isinstance(ip, str) and ip.strip():
                    self._index.setdefault(ip.strip().lower(), []).append(asset_id)

    def identify(self, event: NetworkEvent) -> NetworkEvent:
        """Fill ``event.asset_ids`` from the registry when the event names
        an identifier we have seen before (IP/hostname/fqdn/identity)."""
        found: list[str] = []
        for raw_id in event.asset_ids:
            matches = self._index.get(str(raw_id).strip().lower())
            if matches:
                found.extend(matches)
        for key in ("ip", "hostname", "fqdn", "asset_identity"):
            value = event.payload.get(key)
            if isinstance(value, str) and value.strip():
                matches = self._index.get(value.strip().lower())
                if matches:
                    found.extend(matches)
        # event already names asset ids that ARE in the registry
        for asset_id in event.asset_ids:
            if asset_id in self._assets:
                found.append(asset_id)
        event.asset_ids = list(dict.fromkeys(found)) or event.asset_ids
        return event


class ImpactAnalysis:
    """Scope a targeted rescan: the asset itself plus graph dependents.

    The graph's ``dependents(asset_id)`` are the nodes that break when the
    asset changes, so they must be rescanned / re-evaluated together.
    """

    def __init__(self, *, dependents_fn: Callable[[str], list[str]] | None = None) -> None:
        self._dependents = dependents_fn or (lambda asset_id: [])

    def analyze(self, event: NetworkEvent) -> dict[str, Any]:
        impacted: list[str] = []
        for asset_id in event.asset_ids:
            impacted.append(asset_id)
            for dep in self._dependents(asset_id):
                if dep not in impacted:
                    impacted.append(dep)
        mode = "DEEP" if event.kind in CRYPTO_EVENT_KINDS else "LIGHTWEIGHT"
        return {
            "event": event.kind,
            "impacted_assets": impacted,
            "primary_assets": list(event.asset_ids),
            "targeted_scan_mode": mode,
            "severity": event.severity,
        }
