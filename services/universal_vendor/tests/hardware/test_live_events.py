"""Live hardware events — canonical taxonomy, bus, pipeline (§2)."""

from __future__ import annotations

import pytest

from universal_vendor.hardware.live import (
    HardwareEvent,
    HardwareEventBus,
    HardwareEventPipeline,
    HardwareEventType,
    analyze_impact,
    canonical_event_types,
    classify_change,
    normalize_event_type,
)
from universal_vendor.hardware.live.state import HardwareStateEngine


# ── §2 taxonomy ────────────────────────────────────────────────────────

def test_canonical_taxonomy_covers_spec():
    names = set(canonical_event_types())
    for required in (
        "HARDWARE_DISCOVERED", "HARDWARE_REMOVED", "HARDWARE_REPLACED",
        "HARDWARE_CHANGED", "FIRMWARE_CHANGED", "BIOS_CHANGED", "UEFI_CHANGED",
        "BMC_CHANGED", "TPM_CHANGED", "HSM_CHANGED", "NIC_CHANGED",
        "STORAGE_CHANGED", "CRYPTO_CAPABILITY_CHANGED",
        "HARDWARE_CAPABILITY_CHANGED",
        "TPM_AVAILABLE", "TPM_UNAVAILABLE", "TPM_CONFIGURATION_CHANGED",
        "TPM_FIRMWARE_CHANGED",
        "HSM_ONLINE", "HSM_OFFLINE", "HSM_CAPABILITY_CHANGED",
        "HSM_CONFIGURATION_CHANGED",
    ):
        assert required in names, required


def test_legacy_aliases_normalize():
    assert normalize_event_type("DEVICE_ADDED") == "HARDWARE_DISCOVERED"
    assert normalize_event_type("DEVICE_REMOVED") == "HARDWARE_REMOVED"
    assert normalize_event_type("HARDWARE_DISCOVERED") == "HARDWARE_DISCOVERED"
    with pytest.raises(ValueError):
        normalize_event_type("NOT_A_REAL_EVENT")


# ── §2 classification ──────────────────────────────────────────────────

def test_classification_catalog():
    assert classify_change(HardwareEvent(event_type=HardwareEventType.HARDWARE_DISCOVERED)) == "NEW_DISCOVERY"
    assert classify_change(HardwareEvent(event_type=HardwareEventType.HARDWARE_REMOVED)) == "REMOVAL"
    assert classify_change(HardwareEvent(event_type=HardwareEventType.HARDWARE_REPLACED)) == "REPLACEMENT"
    assert classify_change(HardwareEvent(event_type=HardwareEventType.BIOS_CHANGED)) == "FIRMWARE_CHANGE"
    assert classify_change(HardwareEvent(event_type=HardwareEventType.TPM_UNAVAILABLE)) == "SECURITY_HARDWARE_CHANGE"
    assert classify_change(HardwareEvent(event_type=HardwareEventType.CRYPTO_CAPABILITY_CHANGED)) == "CAPABILITY_CHANGE"
    assert classify_change(HardwareEvent(event_type=HardwareEventType.NIC_CHANGED)) == "CONFIGURATION_CHANGE"


def test_impact_analysis():
    impact = analyze_impact(HardwareEvent(event_type=HardwareEventType.BIOS_CHANGED), "FIRMWARE_CHANGE")
    assert impact["crypto_affected"] is True
    assert impact["pqc_affected"] is True
    assert "firmware" in impact["affected_subsystems"]
    assert impact["severity"] == "MEDIUM"

    removal = analyze_impact(HardwareEvent(event_type=HardwareEventType.HARDWARE_REMOVED), "REMOVAL")
    assert removal["severity"] == "HIGH"
    assert "software_dependencies" in removal["affected_subsystems"]


# ── event bus ──────────────────────────────────────────────────────────

def test_event_bus_publish_subscribe():
    seen = []
    bus = HardwareEventBus()
    bus.subscribe(lambda e: seen.append(e.event_type.value))
    event = HardwareEvent(event_type=HardwareEventType.TPM_CHANGED, asset_id="srv-1")
    bus.emit(event)
    assert seen == ["TPM_CHANGED"]
    assert bus.count() == 1
    # a broken subscriber never breaks the bus
    bus.subscribe(lambda e: 1 / 0)
    bus.emit(HardwareEvent(event_type=HardwareEventType.NIC_CHANGED, asset_id="srv-1"))
    assert bus.count() == 2


# ── §2 pipeline ────────────────────────────────────────────────────────

def test_pipeline_identity_and_plan():
    pipeline = HardwareEventPipeline()
    event = HardwareEvent(
        event_type=HardwareEventType.HARDWARE_DISCOVERED,
        asset_id="",
        serial_reference="SN-4242",
        payload={"dmi_uuid": "550e8400-e29b-41d4-a716-446655440000"},
    )
    envelope = pipeline.process(event)
    assert envelope.change_class == "NEW_DISCOVERY"
    assert envelope.asset_id  # resolved through identity signals
    assert envelope.impact["pqc_affected"] is True


# ── state engine: full taxonomy + previous state (§3) ──────────────────

def test_state_engine_full_taxonomy():
    engine = HardwareStateEngine()
    assert engine.apply_event({"event_type": "HARDWARE_DISCOVERED",
                               "asset_id": "srv-1", "manufacturer": "Dell",
                               "model": "R760"}) == "NEW"
    assert engine.apply_event({"event_type": "BIOS_CHANGED",
                               "asset_id": "srv-1", "component": "BIOS",
                               "version": "2.19"}) == "CHANGED"
    state = engine.get("srv-1")
    assert state.firmware.get("BIOS") == "2.19"
    assert state.last_firmware_check is not None
    # previous state preserved (§3)
    assert state.previous_state is not None
    assert state.previous_state["firmware"] == {}
    # TPM lifecycle events update crypto check + tpm field
    engine.apply_event({"event_type": "TPM_AVAILABLE", "asset_id": "srv-1",
                        "tpm": {"present": True, "version": "2.0"}})
    assert engine.get("srv-1").tpm["version"] == "2.0"
    assert engine.get("srv-1").last_crypto_check is not None


def test_state_engine_removal_and_replacement():
    engine = HardwareStateEngine()
    engine.apply_event({"event_type": "HARDWARE_DISCOVERED", "asset_id": "h1"})
    assert engine.apply_event({"event_type": "HARDWARE_REMOVED", "asset_id": "h1"}) == "REMOVED"
    assert engine.apply_event({"event_type": "HARDWARE_REMOVED", "asset_id": "h1"}) == "NO_CHANGE"
    # replacement updates identity
    engine.apply_event({"event_type": "HARDWARE_REPLACED", "asset_id": "h1",
                        "model": "NewModel", "serial_reference": "SN-NEW"})
    assert engine.get("h1").model == "NewModel"
    assert engine.get("h1").serial_reference == "SN-NEW"


def test_state_engine_timestamp_param():
    engine = HardwareStateEngine()
    assert engine.apply_event({"event_type": "HARDWARE_DISCOVERED", "asset_id": "x"},
                              timestamp="2026-08-31T10:00:00+00:00") == "NEW"
    assert engine.get("x").first_seen == "2026-08-31T10:00:00+00:00"
