"""The component inventory: every class a bank audits, with a third state.

The point of these tests is the distinction the module exists for: PRESENT,
ABSENT and UNKNOWN are three different answers, and collapsing the third into the
second is how an unprivileged collector reports "this machine has no GPU, no TPM
and no crypto accelerator".
"""

from __future__ import annotations

import json

import pytest

from universal_vendor.hardware.components import (
    ABSENT,
    COMPONENT_KINDS,
    PRESENT,
    SECURITY_KINDS,
    UNKNOWN,
    Component,
    UnknownPlatform,
    classify_pci,
    from_linux,
    from_windows,
    pci_class_code,
)

LINUX = {
    "asset_id": "SN-0001",
    "device_type": "server",
    "dmi": {"manufacturer": "Dell Inc.", "product": "PowerEdge R760",
            "serial": "SN-0001", "bios_version": "1.9.3", "bios_date": "02/14/2024",
            "board": "0P4XX8"},
    "cpu": {"model name": "Intel(R) Xeon(R) Gold 6430", "vendor id": "GenuineIntel",
            "cpu(s)": "64", "core(s) per socket": "32", "socket(s)": "2",
            "virtualization": "VT-x"},
    "memory_modules": [{"size_mb": 32768, "locator": "DIMM_A1", "type": "DDR5"}],
    "memory_total_mb": 32768,
    "disks": [{"device": "/dev/nvme0n1", "model": "SAMSUNG MZQL2960HCJR",
               "serial_reference": "S6B7NX0T", "firmware": "GDC5",
               "smart": {"health_passed": True}}],
    "nics": [{"name": "eno1", "mac_address": "aa:bb:cc:dd:ee:01"}],
    "pci_devices": [
        {"slot": "00:00.0", "class": "Host bridge [0600]", "device": "Device [09a2]"},
        {"slot": "3b:00.0", "class": "VGA compatible controller [0300]",
         "device": "ASPEED Graphics [2000]"},
        {"slot": "5e:00.0", "class": "Ethernet controller [0200]",
         "device": "MT29101 [1015]"},
        {"slot": "d8:00.0", "class": "RAID bus controller [0104]",
         "device": "PERC H755 [10e2]"},
        {"slot": "e1:00.0", "class": "Processing accelerators [1200]",
         "device": "AI accelerator [0000]"},
    ],
    "sources": {"dmi": "sysfs", "cpu": "lscpu", "memory_modules": "dmidecode",
                "disks": "lsblk", "nics": "sysfs", "pci_devices": "lspci"},
    "unavailable": [],
}

WINDOWS = {
    "asset_id": "SN-WIN-0001",
    "device_type": "hypervisor_host",
    "platform": {"manufacturer": "Dell Inc.", "model": "PowerEdge R760",
                 "serial_reference": "SN-WIN-0001"},
    "firmware": {"bios_version": "1.9.3", "bios_release_date": "2024-02-14",
                 "baseboard_product": "0P4XX8"},
    "processors": [{"name": "Intel(R) Xeon(R) Platinum 8480+", "cores": 56}],
    "memory_total_mb": 262144,
    "disks": [{"model": "Dell NVMe ISE PS1010", "firmware": "1.1.0"}],
    "tpm": {"present": True, "version": "2.0, 0, 1.16", "manufacturer": "IFX",
            "firmware": "7.63.3353.0", "supported_algorithms": None},
    "sources": {"identity": "cim", "cpu": "cim", "disks": "cim", "tpm": "cim"},
    "unavailable": [],
}


def statuses(inventory):
    return {kind: inventory.by_kind()[kind].status
            for kind in COMPONENT_KINDS if kind in inventory.by_kind()}


# -- the shape of the answer ------------------------------------------------ #


def test_every_component_class_the_review_named_is_reported():
    inventory = from_linux(LINUX)
    assert set(statuses(inventory)) == set(COMPONENT_KINDS)
    assert len(COMPONENT_KINDS) == 15


def test_a_component_that_is_not_present_must_say_why():
    with pytest.raises(ValueError):
        Component(kind="gpu", status=ABSENT, source="lspci")
    with pytest.raises(ValueError):
        Component(kind="floppy", status=PRESENT, source="lspci")


def test_the_inventory_is_a_projection_and_stores_nothing():
    payload = from_linux(LINUX).to_dict()
    assert payload["schema"] == "cryptoscan.hardware-components/1"
    assert "components" in payload and "statuses" in payload
    assert payload["asset_id"] == "SN-0001"
    json.dumps(payload)  # it is a document, not an object graph


# -- what a Linux host yields ---------------------------------------------- #


def test_the_linux_reader_reaches_every_host_component_kind():
    inventory = from_linux(LINUX)
    found = statuses(inventory)
    for kind in ("cpu", "memory", "motherboard", "bios", "firmware", "pci", "disk", "nic"):
        assert found[kind] == PRESENT, kind
    cpu = inventory.by_kind()["cpu"]
    assert cpu.fields["model name"] == "Intel(R) Xeon(R) Gold 6430"
    assert cpu.source == "lscpu"


def test_a_gpu_is_found_by_pci_class_not_by_guessing_a_name():
    inventory = from_linux(LINUX)
    gpu = inventory.by_kind()["gpu"]
    assert gpu.status == PRESENT
    assert gpu.name == "ASPEED Graphics [2000]"
    assert gpu.evidence == ["pci:3b:00.0"]


def test_raid_a_storage_controller_and_a_crypto_accelerator_are_separate_kinds():
    found = statuses(from_linux(LINUX))
    assert found["raid"] == PRESENT
    assert found["crypto_accelerator"] == PRESENT
    # This host has no non-RAID storage controller: it is ABSENT, not UNKNOWN,
    # because the PCI scan succeeded and reported none.
    assert found["storage_controller"] == ABSENT


def test_firmware_is_per_component_not_a_single_yes():
    firmware = from_linux(LINUX).by_kind()["firmware"]
    assert firmware.fields["revisions"]["bios"] == "1.9.3"
    assert firmware.fields["revisions"]["disk:/dev/nvme0n1"] == "GDC5"


def test_a_failed_pci_scan_yields_unknown_not_absent():
    broken = {**LINUX, "pci_devices": [],
              "unavailable": ["lspci: command not found"]}
    broken["sources"] = {key: value for key, value in LINUX["sources"].items()
                         if key != "pci_devices"}
    found = statuses(from_linux(broken))
    for kind in ("pci", "gpu", "raid", "storage_controller", "crypto_accelerator"):
        assert found[kind] == UNKNOWN, kind
    assert "lspci" in from_linux(broken).by_kind()["gpu"].reason


def test_a_missing_cpu_fact_is_unknown_with_the_reason_lscpu_gave():
    no_cpu = {**LINUX, "cpu": {},
              "unavailable": ["lscpu: binary not installed (binary not installed)"]}
    cpu = from_linux(no_cpu).by_kind()["cpu"]
    assert cpu.status == UNKNOWN and "lscpu" in cpu.reason


# -- security hardware comes from its own reader --------------------------- #


def test_a_tpm_nobody_looked_for_is_unknown_not_absent():
    inventory = from_linux(LINUX)
    # A crypto accelerator this host *does* have came from PCI; the three kinds
    # no reader ran for are UNKNOWN, and each says so.
    for kind in ("tpm", "hsm", "smart_card"):
        assert statuses(inventory)[kind] == UNKNOWN
        assert "never looked" in inventory.by_kind()[kind].reason
    assert statuses(inventory)["crypto_accelerator"] == PRESENT
    assert SECURITY_KINDS == ("tpm", "hsm", "smart_card", "crypto_accelerator")


def test_a_security_reader_that_found_nothing_says_absent():
    inventory = from_linux(LINUX, security_hardware={
        "smart_card": {"present": False, "source": "pcsc", "reason": "no reader attached"}})
    card = inventory.by_kind()["smart_card"]
    assert card.status == ABSENT and card.reason == "no reader attached"


def test_a_security_record_is_projected_to_named_fields_only():
    inventory = from_linux(LINUX, security_hardware={"hsm": {
        "present": True, "manufacturer": "Thales", "model": "Luna K7",
        "firmware": "7.8.2", "cluster": "hsm-cluster-01", "ha_state": "ACTIVE",
        "supported_algorithms": ["RSA-3072", "ML-DSA-65"],
        "wrapped_key": "do-not-store-me", "evidence_id": "EV-1"}})
    hsm = inventory.by_kind()["hsm"]
    assert hsm.status == PRESENT
    assert hsm.fields["firmware"] == "7.8.2" and hsm.fields["ha_state"] == "ACTIVE"
    assert "wrapped_key" not in hsm.fields
    assert "do-not-store-me" not in json.dumps(inventory.to_dict())


# -- Windows ---------------------------------------------------------------- #


def test_the_windows_reader_reaches_the_same_kinds_it_has_readers_for():
    found = statuses(from_windows(WINDOWS))
    for kind in ("cpu", "memory", "motherboard", "bios", "firmware", "disk", "tpm"):
        assert found[kind] == PRESENT, kind
    # Nothing on Windows enumerates PCI classes yet, so GPU/RAID/accelerator are
    # UNKNOWN with the gap named — not "this server has no GPU".
    for kind in ("pci", "gpu", "raid", "storage_controller", "crypto_accelerator", "nic"):
        assert found[kind] == UNKNOWN, kind
        assert "allowlist" in from_windows(WINDOWS).by_kind()[kind].reason


def test_windows_memory_is_honest_about_module_level_detail():
    memory = from_windows(WINDOWS).by_kind()["memory"]
    assert memory.fields["total_mb"] == 262144
    assert "Win32_PhysicalMemory" in memory.fields["modules"]


def test_the_windows_tpm_record_is_metadata_only():
    tpm = from_windows(WINDOWS).by_kind()["tpm"]
    assert tpm.status == PRESENT and tpm.fields["manufacturer"] == "IFX"
    assert tpm.fields["supported_algorithms"] is None


def test_facts_of_an_unknown_shape_are_refused():
    with pytest.raises(UnknownPlatform):
        from_linux({"unrelated": True})
    with pytest.raises(UnknownPlatform):
        from_windows({"unrelated": True})


# -- classification --------------------------------------------------------- #


def test_pci_classes_map_to_the_component_the_review_named():
    assert classify_pci("VGA compatible controller [0300]") == "gpu"
    assert classify_pci("3D controller [0302]") == "gpu"
    assert classify_pci("Ethernet controller [0200]") == "nic"
    assert classify_pci("RAID bus controller [0104]") == "raid"
    assert classify_pci("Serial Attached SCSI controller [0107]") == "storage_controller"
    assert classify_pci("Encryption controller [1080]") == "crypto_accelerator"
    assert classify_pci("Host bridge [0600]") is None
    assert classify_pci("no class here") is None
    assert pci_class_code("Device [name] [0300]") == "0300"


def test_completeness_is_a_claim_about_looking_not_about_finding():
    """A host with no GPU is complete; a host nobody asked is not."""
    no_gpu = {**LINUX, "pci_devices": [d for d in LINUX["pci_devices"]
                                       if "[0300]" not in d["class"]]}
    inventory = from_linux(no_gpu, security_hardware={
        kind: {"present": False, "source": "reader", "reason": f"no {kind}"}
        for kind in ("tpm", "hsm", "smart_card", "crypto_accelerator")})
    assert inventory.by_kind()["gpu"].status == ABSENT
    assert inventory.complete is True
    assert from_linux(LINUX).complete is False
    # The accelerator came from PCI, so it is not a gap. What is left is the three
    # kinds no reader ran for, plus a storage controller this host genuinely lacks
    # — ABSENT is still reported as a gap of *evidence* about this host, and the
    # status says which of the two it is.
    assert {gap["kind"] for gap in from_linux(LINUX).gaps} == {
        "tpm", "hsm", "smart_card", "storage_controller"}
    assert from_linux(LINUX).by_kind()["storage_controller"].status == ABSENT
    assert from_linux(LINUX).by_kind()["tpm"].status == UNKNOWN
