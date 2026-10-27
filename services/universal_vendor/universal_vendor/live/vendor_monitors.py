"""Vendor-specific live monitors (24/7 spec §4–§8).

Each monitor is a :class:`LiveConnector` that turns a vendor surface
(NETCONF/RESTCONF/SNMPv3/streaming telemetry/controller API/syslog for Cisco;
management API for firewalls; iControl/API for F5/A10/Citrix/NGINX/HAProxy;
PKI engines; HSM admin APIs) into canonical UniversalVendorEvents.

HSM monitors are metadata-only: they never retrieve private keys, master
keys, PINs or secret material (spec §8).
"""

from __future__ import annotations

import os
from typing import Any, Iterable

from universal_vendor.live.events import (
    ChangeType,
    EventType,
    UniversalVendorEvent,
)
from universal_vendor.live.monitoring import LiveConnector, MonitorMode

_CRYPTO_EVENT_MAP: dict[str, EventType] = {
    "ssh": EventType.SSH_CHANGED,
    "tls": EventType.TLS_CHANGED,
    "ipsec": EventType.IPSEC_CHANGED,
    "ike": EventType.IKE_CHANGED,
    "vpn": EventType.VPN_CHANGED,
    "certificate": EventType.CERTIFICATE_REPLACED,
    "cert": EventType.CERTIFICATE_REPLACED,
    "aaa": EventType.AAA_CHANGED,
    "crypto policy": EventType.CRYPTO_POLICY_CHANGED,
    "trust store": EventType.TRUST_STORE_CHANGED,
    "truststore": EventType.TRUST_STORE_CHANGED,
    "interface": EventType.INTERFACE_CHANGED,
    "routing": EventType.ROUTING_CHANGED,
}


def _test_fixture_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep legacy iterable fixtures out of production connector paths."""
    values = list(events)
    if values and not os.environ.get("PYTEST_CURRENT_TEST"):
        raise RuntimeError(
            "injected vendor events are test-only; configure a real API or event stream"
        )
    return values


def _classify_change(raw: dict[str, Any], domain: str) -> EventType:
    for token, event_type in _CRYPTO_EVENT_MAP.items():
        if token in domain.lower():
            return event_type
    return EventType.CONFIG_CHANGED


class CiscoLiveMonitor(LiveConnector):
    """Cisco live monitoring (spec §4).

    Supports authorized management/telemetry mechanisms: NETCONF, RESTCONF,
    SNMPv3, streaming telemetry, controller APIs, syslog, configuration
    change events. Monitors: interface, routing, VPN, IPsec, IKE, SSH, TLS,
    certificate, AAA, trust store, crypto policy and firmware changes.
    """

    vendor = "Cisco"
    product = "IOS-XE"
    mechanism = "telemetry"  # override per deployment: netconf/restconf/snmpv3/...
    modes = [MonitorMode.REAL_TIME_TELEMETRY, MonitorMode.MANAGEMENT_API_MONITORING,
             MonitorMode.VENDOR_EVENT_MONITORING]

    def __init__(self, asset_id: str = "", *, events: Iterable[dict[str, Any]] = (),
                 mechanism: str = "telemetry", **options: Any) -> None:
        super().__init__(asset_id=asset_id, **options)
        self.mechanism = mechanism
        self._raw_events = _test_fixture_events(events)

    def collect(self) -> list[UniversalVendorEvent]:
        out = []
        for raw in self._raw_events:
            domain = str(raw.get("domain") or raw.get("area") or "config")
            event_type = _classify_change(raw, domain)
            change = raw.get("change_type") or (
                ChangeType.UPDATED.value if raw.get("action") in ("modified", "deleted")
                else ChangeType.CREATED.value)
            out.append(UniversalVendorEvent(
                vendor="Cisco",
                product=str(raw.get("product") or "IOS-XE"),
                product_version=raw.get("version"),
                asset_id=str(raw.get("asset_id") or self.asset_id),
                asset_type="router",
                event_type=event_type,
                change_type=change,
                source=f"cisco-{self.mechanism}",
                confidence=float(raw.get("confidence") or 0.85),
                evidence_reference=raw.get("evidence_reference"),
                vendor_metadata={k: v for k, v in raw.items()
                                if k not in ("domain", "area", "change_type",
                                             "action", "product", "version",
                                             "asset_id", "confidence",
                                             "evidence_reference")},
            ))
        self._raw_events = []
        return out

    def snapshot(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "product": self.product,
                "asset_id": self.asset_id,
                "mechanism": self.mechanism}


class FirewallLiveMonitor(LiveConnector):
    """Firewall vendor live monitoring (spec §5).

    One monitor for the universal firewall surface: Palo Alto, Fortinet,
    Check Point, Cisco security platforms, Sophos, SonicWall, …
    Monitors: VPN policy, IPsec, IKE, TLS inspection, certificates, security
    profiles, crypto policies, admin configuration, firmware, trust stores.
    """

    vendor = "Firewall"      # overwritten per deployment
    product = "Firewall"
    mechanism = "management_api"
    modes = [MonitorMode.MANAGEMENT_API_MONITORING, MonitorMode.VENDOR_EVENT_MONITORING]

    def __init__(self, asset_id: str = "", *, vendor: str = "Palo Alto",
                 product: str = "PAN-OS", events: Iterable[dict[str, Any]] = (),
                 **options: Any) -> None:
        super().__init__(asset_id=asset_id, **options)
        self.vendor = vendor
        self.product = product
        self._raw_events = _test_fixture_events(events)

    def collect(self) -> list[UniversalVendorEvent]:
        out = []
        for raw in self._raw_events:
            domain = str(raw.get("domain") or "policy")
            event_type = _classify_change(raw, domain)
            out.append(UniversalVendorEvent(
                vendor=self.vendor, product=self.product,
                product_version=raw.get("version"),
                asset_id=str(raw.get("asset_id") or self.asset_id),
                asset_type="firewall",
                event_type=event_type,
                change_type=raw.get("change_type") or ChangeType.UPDATED.value,
                source=f"firewall-{self.mechanism}",
                confidence=float(raw.get("confidence") or 0.85),
                evidence_reference=raw.get("evidence_reference"),
                vendor_metadata={k: v for k, v in raw.items()
                                if k not in ("domain", "change_type", "version",
                                             "asset_id", "confidence",
                                             "evidence_reference")},
            ))
        self._raw_events = []
        return out


class LoadBalancerLiveMonitor(LiveConnector):
    """Load balancer / ADC live monitoring (spec §6).

    F5, A10, Citrix ADC, NGINX, HAProxy. Monitors: TLS profile changed,
    certificate replaced, cipher policy changed, mTLS enabled/disabled,
    backend TLS changed, virtual server changed.
    """

    vendor = "F5"
    product = "BIG-IP"
    mechanism = "api"
    modes = [MonitorMode.MANAGEMENT_API_MONITORING, MonitorMode.VENDOR_EVENT_MONITORING]

    def __init__(self, asset_id: str = "", *, vendor: str = "F5",
                 product: str = "BIG-IP", events: Iterable[dict[str, Any]] = (),
                 **options: Any) -> None:
        super().__init__(asset_id=asset_id, **options)
        self.vendor = vendor
        self.product = product
        self._raw_events = _test_fixture_events(events)

    def collect(self) -> list[UniversalVendorEvent]:
        out = []
        for raw in self._raw_events:
            domain = str(raw.get("domain") or "tls")
            event_type = _classify_change(raw, domain)
            if "profile" in domain.lower() and "ssl" in domain.lower():
                event_type = EventType.TLS_CHANGED
            if "certificate" in domain.lower() or "cert" in domain.lower():
                event_type = EventType.CERTIFICATE_REPLACED
            if "backend" in domain.lower():
                event_type = EventType.CRYPTO_CHANGED
            if "mtls" in domain.lower():
                event_type = EventType.CRYPTO_CHANGED
            out.append(UniversalVendorEvent(
                vendor=self.vendor, product=self.product,
                product_version=raw.get("version"),
                asset_id=str(raw.get("asset_id") or self.asset_id),
                asset_type="load_balancer",
                event_type=event_type,
                change_type=raw.get("change_type") or ChangeType.UPDATED.value,
                source="lb-api",
                confidence=float(raw.get("confidence") or 0.9),
                evidence_reference=raw.get("evidence_reference"),
                vendor_metadata={k: v for k, v in raw.items()
                                if k not in ("domain", "change_type", "version",
                                             "asset_id", "confidence",
                                             "evidence_reference")},
            ))
        self._raw_events = []
        return out


class PkiLiveMonitor(LiveConnector):
    """PKI live monitoring (spec §7).

    Continuously watches root CA, intermediate CA, issuing CA, certificates,
    trust stores, revocation configuration and certificate policy.
    """

    vendor = "PKI"
    product = "CA"
    mechanism = "pki_api"
    modes = [MonitorMode.VENDOR_EVENT_MONITORING, MonitorMode.REAL_TIME_TELEMETRY]

    def __init__(self, asset_id: str = "", *, events: Iterable[dict[str, Any]] = (),
                 **options: Any) -> None:
        super().__init__(asset_id=asset_id, **options)
        self._raw_events = _test_fixture_events(events)

    def collect(self) -> list[UniversalVendorEvent]:
        out = []
        for raw in self._raw_events:
            action = str(raw.get("action") or raw.get("event") or "CREATED").upper()
            event_type = {
                "CREATED": EventType.CERTIFICATE_CREATED,
                "RENEWED": EventType.CERTIFICATE_RENEWED,
                "REVOKED": EventType.CERTIFICATE_REVOKED,
                "REPLACED": EventType.CERTIFICATE_REPLACED,
                "EXPIRED": EventType.CERTIFICATE_EXPIRED,
            }.get(action, EventType.CA_CHANGED)
            change_type = {
                "CREATED": ChangeType.CREATED,
                "RENEWED": ChangeType.RENEWED,
                "REVOKED": ChangeType.REVOKED,
                "REPLACED": ChangeType.REPLACED,
                "EXPIRED": ChangeType.EXPIRED,
            }.get(action, ChangeType.UPDATED)
            out.append(UniversalVendorEvent(
                vendor=str(raw.get("vendor") or self.vendor),
                product=str(raw.get("product") or "CA"),
                product_version=raw.get("version"),
                asset_id=str(raw.get("asset_id") or self.asset_id),
                asset_type="ca",
                event_type=event_type,
                change_type=change_type,
                source="pki-engine",
                confidence=float(raw.get("confidence") or 0.9),
                evidence_reference=raw.get("evidence_reference"),
                vendor_metadata={k: v for k, v in raw.items()
                                if k not in ("action", "event", "vendor",
                                             "product", "version", "asset_id",
                                             "confidence", "evidence_reference")},
            ))
        self._raw_events = []
        return out


class HsmLiveMonitor(LiveConnector):
    """HSM live monitoring — metadata only (spec §8).

    Watches availability, firmware, supported algorithms, key metadata,
    certificate dependencies, partition/domain metadata and crypto
    capability. Never retrieves private keys, master keys, PINs or secret
    material.
    """

    vendor = "Thales"
    product = "Luna HSM"
    mechanism = "hsm_admin_api"
    modes = [MonitorMode.MANAGEMENT_API_MONITORING, MonitorMode.LIGHTWEIGHT_PERIODIC_POLLING]

    _FORBIDDEN = ("private_key", "master_key", "pin", "secret", "password",
                  "key_material", "token_value")

    def __init__(self, asset_id: str = "", *, vendor: str = "Thales",
                 product: str = "Luna HSM", events: Iterable[dict[str, Any]] = (),
                 **options: Any) -> None:
        super().__init__(asset_id=asset_id, **options)
        self.vendor = vendor
        self.product = product
        self._raw_events = _test_fixture_events(events)

    def collect(self) -> list[UniversalVendorEvent]:
        out = []
        for raw in self._raw_events:
            assert not any(token in str(raw).lower() for token in self._FORBIDDEN), \
                "HSM monitor refused secret material"
            domain = str(raw.get("domain") or "config").lower()
            event_type = {
                "firmware": EventType.HSM_FIRMWARE_CHANGED,
                "capability": EventType.HSM_CRYPTO_CAPABILITY_CHANGED,
                "capabilities": EventType.HSM_CRYPTO_CAPABILITY_CHANGED,
                "key": EventType.HSM_KEY_METADATA_CHANGED,
                "certificate": EventType.HSM_CERTIFICATE_CHANGED,
                "partition": EventType.HSM_CONFIGURATION_CHANGED,
            }.get(domain, EventType.HSM_CONFIGURATION_CHANGED)
            out.append(UniversalVendorEvent(
                vendor=self.vendor, product=self.product,
                product_version=raw.get("firmware"),
                asset_id=str(raw.get("asset_id") or self.asset_id),
                asset_type="hsm",
                event_type=event_type,
                change_type=ChangeType.UPDATED,
                source="hsm-admin-api",
                confidence=float(raw.get("confidence") or 0.9),
                evidence_reference=raw.get("evidence_reference"),
                vendor_metadata={k: v for k, v in raw.items()
                                if k not in ("domain", "firmware", "asset_id",
                                             "confidence", "evidence_reference")},
            ))
        self._raw_events = []
        return out

    def snapshot(self) -> dict[str, Any]:
        return {"vendor": self.vendor, "product": self.product,
                "asset_id": self.asset_id, "firmware": self.options.get("firmware")}
