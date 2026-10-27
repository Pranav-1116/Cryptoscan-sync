"""Vendor PQC data pins — the 2026-09 refresh of the hardware registry.

These assertions freeze SHIPPING-support facts (vendor firmware releases and
CAVP/CMVP validations) so a future edit cannot silently regress or inflate
them. If a flag changes here, the change must cite a shipping release or a
validation listing — not a marketing roadmap.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "shared" / "shared_models"))

from shared_models.hardware_registry import catalog, classify_hardware  # noqa: E402


def _by_device(name: str) -> dict:
    matches = [e for e in catalog() if e["device"] == name]
    assert matches, f"{name} missing from catalog"
    return matches[0]


def test_hsm_vendors_ship_pqc():
    expected = {
        "Thales Luna HSM": "7.9",
        "Entrust nShield HSM": "13.8.0",
        "Utimaco SecurityServer": "5.5",
    }
    for device, fw in expected.items():
        entry = _by_device(device)
        assert entry["quantum_resistant"] is True, device
        assert fw in entry["notes"], (device, entry["notes"])  # firmware pinned in the note


def test_cloud_hsms_pqc_via_managed_firmware():
    for device in ("AWS CloudHSM", "IBM Cloud HSM", "Google Cloud HSM"):
        assert _by_device(device)["quantum_resistant"] is True, device
    azure = _by_device("Azure Dedicated HSM")
    assert azure["quantum_resistant"] is True
    assert "user-managed" in azure["notes"]  # honest: PQC needs the TENANT's fw upgrade


def test_roadmap_only_devices_stay_false_with_reason():
    payshield = _by_device("Thales payShield")
    assert payshield["quantum_resistant"] is False
    assert "not yet" in payshield["notes"]  # announced ≠ shipped

    for device in ("YubiKey 5", "SoftHSM", "Intel SGX"):
        assert _by_device(device)["quantum_resistant"] is False, device


def test_classification_inherits_pqc_flag():
    info = classify_hardware("Luna Network HSM", kind="hsm")
    assert info.canonical == "Thales Luna HSM"
    assert info.quantum_resistant is True
    legacy = classify_hardware("SoftHSM2", kind="hsm")
    assert legacy.quantum_resistant is False


def test_catalog_shape_unchanged():
    entries = catalog()
    assert len(entries) >= 60
    sample = entries[0]
    for key in ("raw", "device", "category", "status", "manufacturer",
                "recognized", "quantum_resistant", "attestation"):
        assert key in sample
    pqc_count = sum(1 for e in entries if e["quantum_resistant"])
    assert pqc_count == 10  # 7 keystore HSMs + 2 IBM Z entries + ARM CCA; +1 only with a shipping citation
