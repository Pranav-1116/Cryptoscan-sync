"""Universal Vendor Event Gateway (24/7 spec §2).

Every vendor event — Cisco syslog, Fortinet log, Palo Alto telemetry, F5
iControl, Thales HSM metadata, VMware vCenter alarm, … — enters one common
pipeline:  Event Gateway → Event Normalizer → canonical ``UniversalVendorEvent``.

The canonical event carries every field required by the spec plus a
``vendor_metadata`` map so vendor-specific detail is never lost.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Canonical event types across all vendors (§7, §8, §15, §26 …)."""

    VENDOR_DISCOVERED = "VENDOR_DISCOVERED"
    ASSET_DISCOVERED = "ASSET_DISCOVERED"
    ASSET_REMOVED = "ASSET_REMOVED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    FIRMWARE_CHANGED = "FIRMWARE_CHANGED"
    CERTIFICATE_CREATED = "CERTIFICATE_CREATED"
    CERTIFICATE_RENEWED = "CERTIFICATE_RENEWED"
    CERTIFICATE_REVOKED = "CERTIFICATE_REVOKED"
    CERTIFICATE_REPLACED = "CERTIFICATE_REPLACED"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    CA_CHANGED = "CA_CHANGED"
    TRUST_CHAIN_CHANGED = "TRUST_CHAIN_CHANGED"
    SIGNATURE_ALGORITHM_CHANGED = "SIGNATURE_ALGORITHM_CHANGED"
    HSM_CONFIGURATION_CHANGED = "HSM_CONFIGURATION_CHANGED"
    HSM_FIRMWARE_CHANGED = "HSM_FIRMWARE_CHANGED"
    HSM_CRYPTO_CAPABILITY_CHANGED = "HSM_CRYPTO_CAPABILITY_CHANGED"
    HSM_KEY_METADATA_CHANGED = "HSM_KEY_METADATA_CHANGED"
    HSM_CERTIFICATE_CHANGED = "HSM_CERTIFICATE_CHANGED"
    CRYPTO_CHANGED = "CRYPTO_CHANGED"
    KEY_CHANGED = "KEY_CHANGED"
    TLS_CHANGED = "TLS_CHANGED"
    IPSEC_CHANGED = "IPSEC_CHANGED"
    IKE_CHANGED = "IKE_CHANGED"
    SSH_CHANGED = "SSH_CHANGED"
    VPN_CHANGED = "VPN_CHANGED"
    AAA_CHANGED = "AAA_CHANGED"
    CRYPTO_POLICY_CHANGED = "CRYPTO_POLICY_CHANGED"
    TRUST_STORE_CHANGED = "TRUST_STORE_CHANGED"
    INTERFACE_CHANGED = "INTERFACE_CHANGED"
    ROUTING_CHANGED = "ROUTING_CHANGED"
    ADMIN_CONFIG_CHANGED = "ADMIN_CONFIG_CHANGED"
    HEALTH_CHANGED = "HEALTH_CHANGED"
    UNKNOWN = "UNKNOWN"


class ChangeType(str, Enum):
    """What kind of change the event represents."""

    CREATED = "CREATED"
    UPDATED = "UPDATED"
    REMOVED = "REMOVED"
    REPLACED = "REPLACED"
    RENEWED = "RENEWED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    DRIFTED = "DRIFTED"
    OBSERVED = "OBSERVED"  # no change — just a periodic observation
    UNKNOWN = "UNKNOWN"


class UniversalVendorEvent(BaseModel):
    """Canonical vendor event (spec §2)."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    vendor: str
    product: str
    product_version: Optional[str] = None
    asset_id: Optional[str] = None
    asset_type: str = "other"
    event_type: EventType = EventType.UNKNOWN
    change_type: ChangeType = ChangeType.OBSERVED
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: str = "unknown"  # e.g. "syslog", "restconf", "snmpv3", "management_api"
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    evidence_reference: Optional[str] = None  # hash into the evidence chain
    vendor_metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class EventGateway:
    """Single ingress for every vendor event. Append-only event log."""

    def __init__(self) -> None:
        self._log: list[UniversalVendorEvent] = []

    def ingest(self, event: UniversalVendorEvent) -> UniversalVendorEvent:
        self._log.append(event)
        return event

    def ingest_many(self, events: list[UniversalVendorEvent]) -> list[UniversalVendorEvent]:
        for event in events:
            self.ingest(event)
        return events

    def ingest_raw(self, raw: dict[str, Any]) -> UniversalVendorEvent:
        """Normalize an arbitrary vendor payload into a canonical event."""
        return self.ingest(EventNormalizer.normalize(raw))

    def events(self, *, since_index: int = 0) -> list[UniversalVendorEvent]:
        return list(self._log[since_index:])

    def __len__(self) -> int:
        return len(self._log)


# Vendor alias → canonical vendor/product mapping. Detection engines and
# gateways share it so "FortiGate", "Fortinet FortiOS" and "fortios" all
# resolve to the same identity (spec §2 "Vendor Identity Resolver").
_VENDOR_ALIASES: dict[str, tuple[str, str]] = {
    "fortigate": ("Fortinet", "FortiGate"),
    "fortios": ("Fortinet", "FortiOS"),
    "pan-os": ("Palo Alto", "PAN-OS"),
    "panos": ("Palo Alto", "PAN-OS"),
    "bigip": ("F5", "BIG-IP"),
    "big-ip": ("F5", "BIG-IP"),
    "netscaler": ("Citrix", "ADC"),
    "luna": ("Thales", "Luna HSM"),
    "nshield": ("Entrust", "nShield HSM"),
    "securityserver": ("Utimaco", "SecurityServer"),
    "ios-xe": ("Cisco", "IOS-XE"),
    "ios-xr": ("Cisco", "IOS-XR"),
    "nx-os": ("Cisco", "NX-OS"),
    "adcs": ("Microsoft", "AD CS"),
    "entra id": ("Microsoft", "Entra ID"),
    "azure ad": ("Microsoft", "Entra ID"),
    "eks": ("AWS", "EKS"),
    "aks": ("Microsoft", "AKS"),
    "gke": ("Google", "GKE"),
}

_ALIAS_KEYS = sorted(_VENDOR_ALIASES, key=len, reverse=True)


class EventNormalizer:
    """Turn raw vendor payloads into canonical UniversalVendorEvents."""

    @staticmethod
    def resolve_vendor(vendor_hint: str) -> tuple[str, str]:
        """Vendor identity resolution: aliases → canonical vendor/product."""
        lowered = (vendor_hint or "").strip().lower()
        for alias in _ALIAS_KEYS:
            if alias in lowered:
                return _VENDOR_ALIASES[alias]
        return vendor_hint, ""

    @classmethod
    def normalize(cls, raw: dict[str, Any]) -> UniversalVendorEvent:
        vendor_hint = str(raw.get("vendor") or raw.get("source_vendor") or "unknown")
        vendor, product_alias = cls.resolve_vendor(vendor_hint)
        product = str(raw.get("product") or product_alias or "unknown")
        event_type = raw.get("event_type") or raw.get("change") or "UNKNOWN"
        change_type = raw.get("change_type") or (
            ChangeType.UPDATED.value if event_type not in ("VENDOR_DISCOVERED",
                                                          "ASSET_DISCOVERED")
            else ChangeType.CREATED.value
        )
        try:
            event_type_enum = EventType(event_type.upper())
        except ValueError:
            event_type_enum = EventType.UNKNOWN
        try:
            change_enum = ChangeType(change_type.upper())
        except ValueError:
            change_enum = ChangeType.UNKNOWN

        return UniversalVendorEvent(
            vendor=vendor,
            product=product,
            product_version=raw.get("product_version") or raw.get("version"),
            asset_id=str(raw.get("asset_id") or raw.get("hostname") or raw.get("name") or ""),
            asset_type=str(raw.get("asset_type") or "other"),
            event_type=event_type_enum,
            change_type=change_enum,
            timestamp=str(raw.get("timestamp") or datetime.now(timezone.utc).isoformat()),
            source=str(raw.get("source") or "unknown"),
            confidence=float(raw.get("confidence") or 0.5),
            evidence_reference=raw.get("evidence_reference"),
            vendor_metadata={key: value for key, value in raw.items()
                            if key not in (
                                "vendor", "product", "product_version", "asset_id",
                                "asset_type", "event_type", "change_type",
                                "timestamp", "source", "confidence",
                                "evidence_reference", "change", "version",
                                "hostname", "name", "source_vendor",
                            )},
        )
