"""24/7 live engine — event gateway + normalizer + asset state tests (§2, §3)."""

from __future__ import annotations

from universal_vendor.live.events import (
    ChangeType,
    EventGateway,
    EventNormalizer,
    EventType,
    UniversalVendorEvent,
)
from universal_vendor.live.state import LiveAssetStateEngine, MonitoringStatus


def test_canonical_event_shape():
    event = UniversalVendorEvent(
        vendor="Cisco", product="IOS-XE", asset_id="r1",
        event_type=EventType.CONFIG_CHANGED, change_type=ChangeType.UPDATED,
        vendor_metadata={"area": "crypto"},
    )
    data = event.to_dict()
    for key in ("event_id", "vendor", "product", "product_version", "asset_id",
                "asset_type", "event_type", "change_type", "timestamp", "source",
                "confidence", "evidence_reference", "vendor_metadata"):
        assert key in data, f"missing canonical field {key}"


def test_gateway_append_only():
    gateway = EventGateway()
    event = UniversalVendorEvent(vendor="F5", product="BIG-IP", asset_id="lb1",
                                 event_type=EventType.TLS_CHANGED)
    gateway.ingest(event)
    gateway.ingest_many([
        UniversalVendorEvent(vendor="F5", product="BIG-IP", asset_id="lb1",
                             event_type=EventType.CERTIFICATE_REPLACED),
        UniversalVendorEvent(vendor="Thales", product="Luna HSM", asset_id="hsm1",
                             event_type=EventType.HSM_FIRMWARE_CHANGED),
    ])
    assert len(gateway) == 3
    assert len(gateway.events(since_index=1)) == 2


def test_event_normalizer_vendor_aliases():
    normalized = EventNormalizer.normalize({
        "vendor": "FortiGate", "product": "FortiGate 100F",
        "event_type": "CONFIG_CHANGED", "change_type": "UPDATED",
        "asset_id": "fw-edge", "area": "ipsec",
    })
    assert normalized.vendor == "Fortinet"
    assert normalized.product == "FortiGate 100F"
    # vendor_metadata preserves everything else
    assert normalized.vendor_metadata["area"] == "ipsec"


def test_event_normalizer_preserves_vendor_specific():
    normalized = EventNormalizer.normalize({
        "vendor": "Palo Alto", "event_type": "CRYPTO_CHANGED",
        "tunnel_id": "t-42", "policy": "p1",
    })
    assert normalized.vendor_metadata["tunnel_id"] == "t-42"
    assert normalized.vendor_metadata["policy"] == "p1"
    assert normalized.event_type == EventType.CRYPTO_CHANGED


def test_state_new_changed_removed():
    engine = LiveAssetStateEngine()
    event = UniversalVendorEvent(vendor="Cisco", product="IOS-XE", asset_id="r1",
                                 event_type=EventType.VENDOR_DISCOVERED)
    assert engine.apply(event) == "NEW_ASSET"

    changed = UniversalVendorEvent(vendor="Cisco", product="IOS-XE", asset_id="r1",
                                   event_type=EventType.CONFIG_CHANGED,
                                   change_type=ChangeType.UPDATED)
    assert engine.apply(changed) == "CHANGED_ASSET"

    observed = UniversalVendorEvent(vendor="Cisco", product="IOS-XE", asset_id="r1",
                                    event_type=EventType.CONFIG_CHANGED,
                                    change_type=ChangeType.OBSERVED)
    assert engine.apply(observed) == "NO_CHANGE"

    removed = UniversalVendorEvent(vendor="Cisco", product="IOS-XE", asset_id="r1",
                                   event_type=EventType.ASSET_REMOVED)
    assert engine.apply(removed) == "REMOVED_ASSET"
    assert engine.get("r1").monitoring_status == MonitoringStatus.REMOVED


def test_state_tracks_firmware_and_crypto():
    engine = LiveAssetStateEngine()
    engine.apply(UniversalVendorEvent(vendor="Thales", product="Luna HSM",
                                      asset_id="hsm1"))
    engine.apply(UniversalVendorEvent(
        vendor="Thales", product="Luna HSM", asset_id="hsm1",
        event_type=EventType.FIRMWARE_CHANGED,
        vendor_metadata={"firmware": "7.4.2"}))
    state = engine.get("hsm1")
    assert state.firmware == "7.4.2"

    engine.mark_crypto_scanned("hsm1", {"algorithms": ["RSA", "AES"]})
    assert engine.get("hsm1").last_crypto_scan is not None
    assert engine.get("hsm1").crypto_scan["algorithms"] == ["RSA", "AES"]


def test_state_config_hash_transition():
    engine = LiveAssetStateEngine()
    engine.apply(UniversalVendorEvent(vendor="F5", product="BIG-IP", asset_id="lb1"))
    engine.update_config_hash("lb1", "hash-1", {"tls": "1.2"})
    engine.update_config_hash("lb1", "hash-2", {"tls": "1.3"})
    state = engine.get("lb1")
    assert state.current_config_hash == "hash-2"
    assert state.previous_config_hash == "hash-1"
    assert state.last_configuration_change is not None


def test_mark_stale():
    engine = LiveAssetStateEngine()
    engine.apply(UniversalVendorEvent(vendor="Cisco", product="IOS-XE",
                                      asset_id="r1"))
    stale = engine.mark_stale(threshold_seconds=-1)  # everything older than now
    assert "r1" in stale
    assert engine.get("r1").monitoring_status == MonitoringStatus.STALE
