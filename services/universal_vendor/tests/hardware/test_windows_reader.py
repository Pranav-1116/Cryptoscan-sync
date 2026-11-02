"""The Windows reader (H3): what it reads, what it refuses, how it fails.

No Windows host exists on this runner, so every test drives the production code
path with a recorded CIM transcript — the same approach the SNMP and HSM readers
use. What these tests prove is the allowlist, the projection, the failure modes
and the refusals. What they cannot prove is that a real appliance answers the
way the transcript does, and the artifact says so in its own words.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from universal_vendor.hardware.host.windows import (
    ALLOWLIST,
    CIM_ALLOWLIST,
    FORBIDDEN_POWERSHELL,
    POWERSHELL_ARGV,
    CimQueryRejected,
    CimResult,
    PowerShellCimProvider,
    RecordedCimProvider,
    WindowsHostCollector,
    cim_date,
    parse_cim_json,
    query_for,
    script_for,
)
from universal_vendor.hardware.safety import SecretMaterialRefused

PRODUCT = [{
    "Vendor": "Dell Inc.", "Name": "PowerEdge R760", "Version": "Not Specified",
    "IdentifyingNumber": "SN-WIN-0001",
    "UUID": "4C4C4544-0037-3510-8043-B7C04F4E4432",
}]
SYSTEM = [{
    "Manufacturer": "Dell Inc.", "Model": "PowerEdge R760", "TotalPhysicalMemory": 274877906944,
    "NumberOfProcessors": 2, "NumberOfLogicalProcessors": 128, "HypervisorPresent": True,
    "PartOfDomain": True,
}]
BIOS = [{
    "Manufacturer": "Dell Inc.", "Name": "1.9.3", "Version": "DELL   - 2",
    "SMBIOSBIOSVersion": "1.9.3", "ReleaseDate": "2024-02-14T00:00:00Z",
    "SerialNumber": "SN-WIN-0001",
}]
BASEBOARD = [{"Manufacturer": "Dell Inc.", "Product": "0P4XX8", "SerialNumber": "CNIVC00123",
              "Version": "A01"}]
PROCESSORS = [{
    "Manufacturer": "GenuineIntel", "Name": "Intel(R) Xeon(R) Platinum 8480+",
    "NumberOfCores": 56, "NumberOfLogicalProcessors": 112,
    "VirtualizationFirmwareEnabled": True, "ProcessorId": "BFEBFBFF000806F8",
}]
DISKS = [
    {"Model": "Dell NVMe ISE PS1010", "SerialNumber": "PHMC1234567",
     "FirmwareRevision": "1.1.0", "Size": 3840755982336, "MediaType": "Fixed hard disk media",
     "InterfaceType": "SCSI", "PNPDeviceID": "SCSI\\DISK&VEN_NVME"},
    {"Model": "DELL PERC H755", "SerialNumber": "0087C0A1", "FirmwareRevision": "52.16.1-4602",
     "Size": 1920383410176, "MediaType": "Fixed hard disk media", "InterfaceType": "SCSI",
     "PNPDeviceID": "SCSI\\DISK&VEN_DELL"},
]
TPM = [{
    "IsEnabled_InitialValue": True, "IsActivated_InitialValue": True,
    "ManufacturerIdTxt": "IFX", "ManufacturerVersion": "7.63.3353.0",
    "SpecVersion": "2.0, 0, 1.16", "PhysicalPresenceVersionInfo": "1.3",
}]
DEVICE_GUARD = [{
    "VirtualizationBasedSecurityStatus": 2, "SecurityServicesRunning": [1, 2],
    "SecurityServicesConfigured": [1, 2], "CodeIntegrityPolicyEnforcementStatus": 2,
}]

TRANSCRIPT = {
    "computer_system": SYSTEM, "product": PRODUCT, "bios": BIOS,
    "baseboard": BASEBOARD, "processors": PROCESSORS, "disk_drives": DISKS,
    "tpm": TPM, "device_guard": DEVICE_GUARD,
}


def collected(**overrides):
    provider = RecordedCimProvider({**TRANSCRIPT, **overrides})
    return WindowsHostCollector(provider, hostname="WIN-DB-01").collect()


# -- identity --------------------------------------------------------------- #


def test_identity_comes_from_the_product_class_not_the_hostname():
    context = collected().context
    assert context["platform"]["serial_reference"] == "SN-WIN-0001"
    assert context["platform"]["manufacturer"] == "Dell Inc."
    assert context["platform"]["model"] == "PowerEdge R760"
    assert context["asset_id"] == "SN-WIN-0001"


def test_a_blank_product_serial_falls_through_to_bios_then_baseboard():
    blanked = {**TRANSCRIPT, "product": [{**PRODUCT[0], "IdentifyingNumber": "  "}],
               "bios": [{**BIOS[0], "SerialNumber": ""}]}
    context = WindowsHostCollector(RecordedCimProvider(blanked)).collect().context
    assert context["platform"]["serial_reference"] == "CNIVC00123"


def test_a_host_with_no_serial_at_all_is_named_by_its_hostname_not_invented():
    blanked = {**TRANSCRIPT,
               "product": [{**PRODUCT[0], "IdentifyingNumber": ""}],
               "bios": [{**BIOS[0], "SerialNumber": ""}],
               "baseboard": [{**BASEBOARD[0], "SerialNumber": ""}]}
    facts = WindowsHostCollector(RecordedCimProvider(blanked),
                                 hostname="WIN-DB-01").collect()
    assert facts.context["asset_id"] == "WIN-DB-01"
    assert facts.context["platform"]["serial_reference"] is None


# -- firmware and hardware --------------------------------------------------- #


def test_platform_firmware_is_the_bios_version_and_its_release_date():
    firmware = collected().context["firmware"]
    assert firmware["bios_version"] == "1.9.3"
    assert firmware["bios_release_date"] == "2024-02-14"
    assert firmware["baseboard_product"] == "0P4XX8"


def test_every_disk_carries_its_own_firmware_revision():
    disks = collected().context["disks"]
    assert [disk["firmware"] for disk in disks] == ["1.1.0", "52.16.1-4602"]
    assert [disk["serial_reference"] for disk in disks] == ["PHMC1234567", "0087C0A1"]


def test_a_hypervisor_host_is_typed_as_one():
    context = collected().context
    assert context["device_type"] == "hypervisor_host"
    assert context["hypervisor_present"] is True
    assert context["memory_total_mb"] == 262144


def test_processors_are_counted_separately_from_their_cores():
    cpu = collected().context["processors"][0]
    assert cpu["cores"] == 56 and cpu["logical_processors"] == 112
    assert cpu["virtualization_firmware_enabled"] is True


# -- TPM and secure boot ----------------------------------------------------- #


def test_the_tpm_is_reported_as_metadata_only():
    tpm = collected().context["tpm"]
    assert tpm["present"] is True
    assert tpm["version"] == "2.0, 0, 1.16"
    assert tpm["manufacturer"] == "IFX"
    assert tpm["firmware"] == "7.63.3353.0"
    # What WMI does not expose is stated as absent, not invented.
    assert tpm["supported_algorithms"] is None and tpm["pcr_capabilities"] is None


def test_a_host_without_a_tpm_says_so_instead_of_reporting_a_false_one():
    facts = collected(tpm=[])
    assert facts.context["tpm"]["present"] is False
    assert any("Win32_Tpm" in reason for reason in facts.unavailable)
    assert facts.context["secure_boot"]["tpm_holds_boot_measurements"] is False


def test_secure_boot_is_read_from_device_guard():
    guard = collected().context["secure_boot"]
    assert guard["virtualization_based_security"] == 2
    assert guard["services_running"] == [1, 2]
    assert guard["code_integrity_policy"] == 2


# -- the allowlist and the refusals ----------------------------------------- #


def test_a_class_outside_the_allowlist_is_refused():
    with pytest.raises(CimQueryRejected):
        script_for("Win32_Process")
    with pytest.raises(CimQueryRejected):
        query_for("Win32_Product")


def test_every_allowlisted_read_is_a_get_with_named_properties():
    for query in CIM_ALLOWLIST:
        script = script_for(query.key)
        assert script.count("Get-CimInstance") == 1
        lowered = script.lower()
        assert not any(token in lowered for token in FORBIDDEN_POWERSHELL)
        assert "-property" in lowered
        for prop in query.properties:
            assert prop in script


def test_no_caller_text_can_reach_the_script():
    """The injection surface is absent, not filtered."""
    hostile = "WIN-01'; Remove-Item C:\\Windows -Recurse; '"
    provider = RecordedCimProvider(TRANSCRIPT)
    facts = WindowsHostCollector(provider, hostname=hostile).collect(asset_id=hostile)
    # The hostile string is data (a key), never a command, and the generated
    # scripts are byte-identical to the ones for a benign host.
    assert facts.context["asset_id"] == hostile
    assert all("Remove-Item" not in script_for(key) for key in ALLOWLIST)
    assert all("Remove-Item" not in " ".join(result.argv)
               for result in (provider.read(key) for key in ALLOWLIST))


def test_the_reader_can_only_emit_powershell_from_the_allowlist():
    module = Path(__file__).resolve().parents[2] / "universal_vendor" / "hardware" \
        / "host" / "windows.py"
    source = module.read_text(encoding="utf-8")
    lowered = source.lower()
    for token in FORBIDDEN_POWERSHELL:
        assert token not in lowered, f"{token} has no business in a CIM reader"
    assert "shell=" + "True" not in source
    # Exactly one place builds the command text, and it builds it from the
    # table: a script cannot be assembled from anything a caller supplies.
    assert source.count('f"Get-CimInstance') == 1
    assert "script_for" in source and "CIM_ALLOWLIST" in source


def test_the_provider_runs_an_argv_list_and_never_a_shell():
    seen: list[tuple[str, ...]] = []

    def runner(script: str, timeout: float) -> CimResult:
        seen.append((script, timeout))
        return CimResult(key="", records=[{"Model": "X"}])

    provider = PowerShellCimProvider(runner=runner, timeout=5.0)
    result = provider.read("disk_drives")
    assert result.ok and result.records == [{"Model": "X"}]
    script, timeout = seen[0]
    assert timeout == 5.0
    assert POWERSHELL_ARGV[0] == "powershell.exe"
    assert "-NoProfile" in POWERSHELL_ARGV and "-NonInteractive" in POWERSHELL_ARGV


# -- failure modes ----------------------------------------------------------- #


def test_a_missing_class_does_not_stop_the_other_reads():
    facts = collected(tpm=OSError("provider not available on this host"))
    assert facts.context["platform"]["serial_reference"] == "SN-WIN-0001"
    assert facts.context["tpm"]["present"] is False
    assert any("provider not available" in reason for reason in facts.unavailable)
    assert facts.sources["cpu"] == "cim:Win32_Processor"


def test_a_single_result_is_parsed_as_well_as_an_array():
    assert parse_cim_json('{"Model": "X"}') == [{"Model": "X"}]
    assert parse_cim_json('[{"Model": "X"}, {"Model": "Y"}]') == [{"Model": "X"},
                                                                  {"Model": "Y"}]
    assert parse_cim_json("   ") == []
    with pytest.raises(ValueError):
        parse_cim_json('"a string"')


def test_a_failed_read_is_reported_with_its_reason_not_swallowed():
    def runner(script: str, timeout: float) -> CimResult:
        return CimResult(key="", error="Access is denied")

    facts = WindowsHostCollector(PowerShellCimProvider(runner=runner)).collect()
    assert facts.context["platform"]["serial_reference"] is None
    assert facts.unavailable and all("Access is denied" in reason
                                     for reason in facts.unavailable)


def test_a_field_nobody_asked_for_is_dropped_not_stored():
    """Projection is the first defence: only named properties survive."""
    leaky = {**TRANSCRIPT, "tpm": [{**TPM[0], "RestrictedKey": "do-not-store-me"}]}
    facts = WindowsHostCollector(RecordedCimProvider(leaky)).collect()
    assert "do-not-store-me" not in json.dumps(facts.to_dict())


def test_secret_material_in_a_field_that_is_read_is_refused():
    """When the secret lands in a field the reader *does* project, it stops."""
    leaky = {**TRANSCRIPT, "tpm": [{**TPM[0], "ManufacturerVersion": "private_key=abc"}]}
    with pytest.raises(SecretMaterialRefused):
        WindowsHostCollector(RecordedCimProvider(leaky)).collect()


def test_cim_dates_are_normalised_and_never_guessed():
    assert cim_date("2024-02-14T00:00:00Z") == "2024-02-14"
    assert cim_date("/Date(1707868800000)/") == "2024-02-14"
    assert cim_date("not a date") is None
    assert cim_date(None) is None


def test_the_query_trail_names_what_was_read():
    facts = collected()
    assert facts.queries == [query.key for query in CIM_ALLOWLIST]
    assert json.dumps(facts.to_dict()) .startswith('{"schema": "cryptoscan.hardware.windows-host/1"')
