"""Versioned live HBOM (§15) + firmware change provenance (§7)."""

from __future__ import annotations

from universal_vendor.hardware.firmware import FirmwareIntelligence
from universal_vendor.hardware.hbom import HbomGenerator
from universal_vendor.hardware.models import HardwareObservation, HardwareType


def _obs(asset: str, firmware: dict | None = None) -> HardwareObservation:
    return HardwareObservation(
        asset_id=asset,
        manufacturer="Dell",
        model="R760",
        device_type=HardwareType.SERVER.value,
        firmware="2.18",
        firmware_components=firmware or {},
        confidence="high",
    )


# ── §15 versioned HBOM ─────────────────────────────────────────────────

def test_hbom_every_change_produces_new_version():
    hbom = HbomGenerator()
    hbom.add(_obs("srv-1"))
    v1 = hbom.snapshot(reason="discovery")
    assert v1["version"] == 1

    hbom.add(_obs("srv-2"))
    v2 = hbom.snapshot(reason="new device discovered")
    assert v2["version"] == 2

    history = hbom.version_history()
    assert [h["version"] for h in history] == [1, 2]
    # each version freezes its own document content
    assert len(history[0]["document"]["hardware"]) == 1
    assert len(history[1]["document"]["hardware"]) == 2


def test_hbom_version_retrieval():
    hbom = HbomGenerator()
    hbom.add(_obs("srv-1"))
    hbom.snapshot(reason="r1")
    hbom.snapshot(reason="r2")
    assert hbom.version(1)["reason"] == "r1"
    assert hbom.version(2)["reason"] == "r2"
    assert hbom.version(99) is None
    assert hbom.current_version() == 3


# ── §7 firmware provenance ─────────────────────────────────────────────

def test_firmware_change_stores_source_and_evidence():
    fw = FirmwareIntelligence()
    fw.observe(asset_id="srv-1", component="BIOS", version="2.18")
    fw.set_context(source="agent:dmi", evidence_id="ev-42")
    change = fw.observe(asset_id="srv-1", component="BIOS", version="2.19")
    assert change is not None
    d = change.to_dict()
    assert d["old_version"] == "2.18"
    assert d["new_version"] == "2.19"
    assert d["change_time"] == change.timestamp
    assert d["source"] == "agent:dmi"
    assert d["evidence_id"] == "ev-42"


def test_firmware_no_change_is_none_and_no_dup():
    fw = FirmwareIntelligence()
    fw.observe(asset_id="srv-1", component="BMC", version="1.0")
    assert fw.observe(asset_id="srv-1", component="BMC", version="1.0") is None
    assert len(fw.changes()) == 0


def test_firmware_reassessment_hook_fires_on_change():
    fired = []
    fw = FirmwareIntelligence(reassessment_hook=lambda payload: fired.append(payload))
    fw.observe(asset_id="hsm-1", component="HSM", version="7.0")
    change = fw.observe(asset_id="hsm-1", component="HSM", version="6.5")
    assert change.reassessment_triggered is True
    assert fired and fired[0]["type"] == "firmware_change"
    assert fired[0]["previous"] == "7.0" and fired[0]["current"] == "6.5"
