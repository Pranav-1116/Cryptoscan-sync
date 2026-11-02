"""The Linux host reader: what it reads, what it refuses, and how it fails.

Every test here drives the production code path with a fixture sysfs tree and a
recorded command transcript. Nothing shells out, so the suite proves the reader
without needing a Dell in the CI box — and the one test that does touch
``subprocess`` only runs ``true``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from universal_vendor.hardware.discovery import AgentBasedDiscovery
from universal_vendor.hardware.host.linux import (
    ALLOWED_BINARIES,
    CommandNotAllowed,
    CommandResult,
    LinuxHostCollector,
    PathNotAllowed,
    build_argv,
    parse_dmidecode_memory,
    parse_dmidecode_system,
    parse_lsblk,
    parse_lspci,
    parse_opensc_readers,
    parse_smartctl,
    parse_tpm2_getcap,
    subprocess_runner,
    validate_device,
)
from universal_vendor.hardware.safety import SecretMaterialRefused

DMIDECODE_MEMORY = """
Memory Device
\tSize: 32 GB
\tLocator: DIMM_A1
\tType: DDR5
\tSpeed: 4800 MT/s
\tManufacturer: Samsung
\tPart Number: M321R4GA3BB6

Memory Device
\tSize: No Module Installed
\tLocator: DIMM_A2
\tType: DDR5
"""

TPM2_GETCAP = """
TPM2_PT_FAMILY_INDICATOR:
  raw: 0x322E3000
  value: "2.0"
TPM2_PT_MANUFACTURER:
  raw: 0x49465800
  value: "IFX"
TPM2_PT_VENDOR_STRING_1:
  raw: 0x37363300
  value: "763"
TPM2_PT_FIRMWARE_VERSION_1:
  raw: 0x0007003F
TPM2_PT_FIRMWARE_VERSION_2:
  raw: 0x00083353
TPM2_PT_MANUFACTURER:
  raw: 0x49465800
  value: "IFX"
"""

OPENSC_READERS = """
# Detected readers (pcsc)
Nr.  Card  Features  Name
0    Yes             SCM Microsystems Inc. SCR 3310 00 00
1    No              Virtual PCD 00 00
"""

DMIDECODE_SYSTEM = """
System Information
\tManufacturer: Dell Inc.
\tProduct Name: PowerEdge R760
\tSerial Number: SN-0001
\tSKU Number: SKU-99
"""

LSBLK = json.dumps({"blockdevices": [
    {"name": "nvme0n1", "path": "/dev/nvme0n1", "serial": "S6B7NX0T",
     "model": "SAMSUNG MZQL2960HCJR", "rev": "GDC5", "type": "disk",
     "size": 960197124096, "rota": 0},
    {"name": "nvme0n1p1", "path": "/dev/nvme0n1p1", "serial": None, "model": None,
     "rev": None, "type": "part", "size": 536870912, "rota": 0},
    {"name": "sda", "path": "/dev/sda", "serial": "WD-1", "model": "WD4000",
     "rev": "1.2", "type": "disk", "size": 4000787030016, "rota": 1},
]})

LSPCI = (
    '00:00.0 "Host bridge [0600]" "Intel Corporation [8086]" "Device [09a2]" -r20 '
    '"Intel Corporation" "Device [0000]"\n'
    '3b:00.0 "Network controller [0280]" "Broadcom Inc. [14e4]" "Device [16d7]" -r10\n'
)

LSCPU = """
Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
Vendor ID:               GenuineIntel
  Model name:            Intel(R) Xeon(R) Gold 6430
    CPU(s):              64
    Core(s) per socket:  32
    Socket(s):           2
Virtualization features:
  Virtualization:        VT-x
Caches (sum of all):
  L1d:                   3 MiB
"""

SMART = json.dumps({
    "model_name": "SAMSUNG MZQL2960HCJR", "serial_number": "S6B7NX0T",
    "firmware_version": "GDC5", "smart_status": {"passed": True}, "rotation_rate": 0,
})


def _sysfs(root: Path, *, dmi: bool = True, nics: bool = True) -> Path:
    if dmi:
        directory = root / "class" / "dmi" / "id"
        directory.mkdir(parents=True)
        for name, value in {"sys_vendor": "Dell Inc.", "product_name": "PowerEdge R760",
                            "product_serial": "SN-0001", "bios_version": "2.19.1"}.items():
            (directory / name).write_text(value + "\n", encoding="utf-8")
    if nics:
        for name, files in {
            "eno1": {"address": "aa:bb:cc:dd:ee:ff", "operstate": "up", "mtu": "1500",
                     "speed": "10000"},
            "eno2": {"address": "aa:bb:cc:dd:ee:01", "operstate": "down", "mtu": "9000",
                     "speed": "-1"},
            "lo": {"address": "00:00:00:00:00:00", "operstate": "unknown", "mtu": "65536"},
        }.items():
            directory = root / "class" / "net" / name
            directory.mkdir(parents=True)
            for filename, value in files.items():
                (directory / filename).write_text(value + "\n", encoding="utf-8")
    return root


def _proc(root: Path, meminfo: str = "MemTotal:       65857124 kB\n") -> Path:
    (root / "sys" / "kernel").mkdir(parents=True)
    (root / "sys" / "kernel" / "hostname").write_text("pay-app-01\n", encoding="utf-8")
    (root / "meminfo").write_text(meminfo, encoding="utf-8")
    return root


class Transcript:
    """A recorded host: answers by binary, and remembers every argv it was given."""

    def __init__(self, *, dmidecode_ok: bool = True, smart_ok: bool = True,
                 tpm: bool = True, smart_card: bool = True) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.dmidecode_ok = dmidecode_ok
        self.smart_ok = smart_ok
        self.tpm = tpm
        self.smart_card = smart_card

    def __call__(self, argv, timeout):
        self.calls.append(tuple(argv))
        if argv[0] == "dmidecode" and argv[-1] == "system":
            if not self.dmidecode_ok:
                return CommandResult(tuple(argv), 1, "", "/dev/mem: Permission denied")
            return CommandResult(tuple(argv), 0, DMIDECODE_SYSTEM, "")
        if argv[0] == "dmidecode":
            if not self.dmidecode_ok:
                return CommandResult(tuple(argv), 1, "", "/dev/mem: Permission denied")
            return CommandResult(tuple(argv), 0, DMIDECODE_MEMORY, "")
        if argv[0] == "lscpu":
            return CommandResult(tuple(argv), 0, LSCPU, "")
        if argv[0] == "lsblk":
            return CommandResult(tuple(argv), 0, LSBLK, "")
        if argv[0] == "lspci":
            return CommandResult(tuple(argv), 0, LSPCI, "")
        if argv[0] == "tpm2_getcap":
            if not self.tpm:
                return CommandResult(tuple(argv), 1, "",
                                     "ERROR: tcti init allocation failed: resource unavailable")
            return CommandResult(tuple(argv), 0, TPM2_GETCAP, "")
        if argv[0] == "opensc-tool":
            if not self.smart_card:
                return CommandResult(tuple(argv), 0, "# Detected readers (pcsc)\n", "")
            return CommandResult(tuple(argv), 0, OPENSC_READERS, "")
        if argv[0] == "smartctl":
            if not self.smart_ok:
                return CommandResult(tuple(argv), 1, "", "/dev/nvme0n1: open failed")
            return CommandResult(tuple(argv), 0, SMART, "")
        return CommandResult(tuple(argv), 127, "", "not installed", available=False)


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

def test_dmidecode_system_extracts_identity():
    parsed = parse_dmidecode_system(DMIDECODE_SYSTEM)
    assert parsed["manufacturer"] == "Dell Inc."
    assert parsed["product"] == "PowerEdge R760"
    assert parsed["serial"] == "SN-0001"


def test_dmidecode_memory_skips_empty_slots():
    modules = parse_dmidecode_memory(DMIDECODE_MEMORY)
    assert len(modules) == 1, "an empty DIMM slot is not a memory module"
    assert modules[0]["size_mb"] == 32768
    assert modules[0]["locator"] == "DIMM_A1"


def test_lsblk_keeps_disks_and_drops_partitions():
    disks = parse_lsblk(LSBLK)
    assert [disk["device"] for disk in disks] == ["/dev/nvme0n1", "/dev/sda"]
    assert disks[0]["firmware"] == "GDC5"


def test_lsblk_tolerates_garbage():
    assert parse_lsblk("not json") == []


def test_lspci_splits_numeric_from_textual_identity():
    devices = parse_lspci(LSPCI)
    assert devices[0]["vendor_id"] == "8086"
    assert devices[0]["vendor"].startswith("Intel")
    assert devices[1]["device_id"] == "16d7"


def test_tpm2_getcap_keeps_identity_and_drops_every_other_property():
    parsed = parse_tpm2_getcap(TPM2_GETCAP)
    assert parsed["present"] is True
    assert parsed["version"] == "2.0" and parsed["manufacturer"] == "IFX"
    assert parsed["firmware"] == "7.63.8.13139"
    # PCR banks and algorithm bitmaps are TPM state, not inventory facts.
    assert parsed["pcr_capabilities"] is None
    assert set(parsed) == {"present", "version", "manufacturer", "firmware", "source",
                           "capabilities", "supported_algorithms", "pcr_capabilities"}


def test_tpm2_getcap_tolerates_text_it_does_not_understand():
    assert parse_tpm2_getcap("") == {}
    assert parse_tpm2_getcap("not a tpm transcript") == {}


def test_opensc_readers_separate_a_reader_from_a_card():
    readers = parse_opensc_readers(OPENSC_READERS)
    assert [reader["card_present"] for reader in readers] == [True, False]
    assert readers[1]["name"] == "Virtual PCD 00 00"
    assert parse_opensc_readers("# Detected readers (pcsc)\n") == []


def test_smartctl_reads_health_without_self_test_logs():
    parsed = parse_smartctl(SMART)
    assert parsed["health_passed"] is True
    assert parsed["firmware"] == "GDC5"
    assert "ata_smart_attributes" not in parsed


# --------------------------------------------------------------------------- #
# allowlists
# --------------------------------------------------------------------------- #

def test_only_allowlisted_binaries_may_run():
    assert build_argv("lsblk", "--json") == ("lsblk", "--json")
    with pytest.raises(CommandNotAllowed):
        build_argv("bash", "-c", "id")
    with pytest.raises(CommandNotAllowed):
        build_argv("dmidecode", "-t", "system; rm -rf /")
    for binary in ("sh", "curl", "python3", "/bin/sh"):
        assert binary.split("/")[-1] not in ALLOWED_BINARIES


def test_shell_metacharacters_are_refused_before_execution():
    for bad in ("a;b", "a|b", "$(id)", "`id`", "a\nb", "a b", ""):
        with pytest.raises(CommandNotAllowed):
            build_argv("lsblk", bad)


def test_only_block_devices_reach_smartctl():
    assert validate_device("/dev/nvme0n1") == "/dev/nvme0n1"
    for bad in ("/dev/sda; rm -rf /", "/etc/shadow", "/dev/../etc/shadow", "--device=x"):
        with pytest.raises(PathNotAllowed):
            validate_device(bad)


def test_sysfs_reads_are_closed_to_the_allowlist(tmp_path):
    collector = LinuxHostCollector(sys_root=_sysfs(tmp_path), runner=Transcript())
    with pytest.raises(PathNotAllowed):
        collector._read_sysfs("kernel/security/lockdown")
    with pytest.raises(PathNotAllowed):
        collector._read_interface_file(tmp_path / "class" / "net" / "eno1", "uevent")


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #

def test_collects_a_host_from_sysfs_and_allowlisted_commands(tmp_path):
    transcript = Transcript()
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=transcript).collect()

    context = facts.context
    assert context["dmi"]["manufacturer"] == "Dell Inc."
    assert context["dmi"]["serial"] == "SN-0001"
    assert context["memory_modules"][0]["size_mb"] == 32768
    assert context["memory_total_mb"] == 64313
    assert [disk["device"] for disk in context["disks"]] == ["/dev/nvme0n1", "/dev/sda"]
    assert context["disks"][0]["smart"]["health_passed"] is True
    assert {nic["name"] for nic in context["nics"]} == {"eno1", "eno2"}
    assert context["pci_devices"][0]["vendor_id"] == "8086"
    assert context["asset_id"] == "SN-0001"

    assert context["cpu"]["model name"] == "Intel(R) Xeon(R) Gold 6430"
    assert context["cpu"]["core(s) per socket"] == "32"
    # lscpu prints cache and mitigation lines that are not hardware components;
    # the allowlist keeps the processor facts and drops the rest.
    assert "l1d" not in context["cpu"] and "cpu op-mode(s)" not in context["cpu"]
    assert [call[0] for call in transcript.calls] == [
        "dmidecode", "lscpu", "lsblk", "smartctl", "smartctl", "lspci",
        "tpm2_getcap", "opensc-tool"]
    assert all(isinstance(call, tuple) for call in transcript.calls)
    assert facts.unavailable == []
    tpm = context["security_hardware"]["tpm"]
    assert tpm["present"] is True and tpm["manufacturer"] == "IFX"
    assert tpm["version"] == "2.0" and tpm["firmware"] == "7.63.8.13139"
    card = context["security_hardware"]["smart_card"]
    assert card["readers"] == 2 and card["card_present"] is True
    assert card["names"][0].startswith("SCM Microsystems")


def test_a_read_tpm_is_a_reader_not_an_absence(tmp_path):
    """A host that refuses the TPM is not a host without one."""
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=Transcript(tpm=False)).collect()
    assert "tpm" not in facts.context["security_hardware"]
    assert any("tpm2_getcap" in reason for reason in facts.unavailable)


def test_no_smart_card_reader_is_an_absence_the_reader_can_prove(tmp_path):
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=Transcript(smart_card=False)).collect()
    card = facts.context["security_hardware"]["smart_card"]
    assert card["present"] is False and card["readers"] == 0
    assert card["reason"] == "no smart-card reader is attached"


def test_the_tpm_reader_asks_for_identity_only():
    assert build_argv("tpm2_getcap", "properties-fixed") == ("tpm2_getcap", "properties-fixed")
    for bad in ("properties-variable", "--tcti=device", "/dev/tpm0"):
        with pytest.raises(CommandNotAllowed):
            build_argv("tpm2_getcap", bad)


def test_the_smart_card_reader_cannot_be_asked_for_a_card():
    assert build_argv("opensc-tool", "--list-readers") == ("opensc-tool", "--list-readers")
    with pytest.raises(CommandNotAllowed):
        build_argv("opensc-tool", "--read-certificate")


def test_dmi_falls_back_to_dmidecode_when_sysfs_is_empty(tmp_path):
    transcript = Transcript()
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys", dmi=False),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=transcript).collect()
    assert facts.context["dmi"]["manufacturer"] == "Dell Inc."
    assert facts.sources["dmi"] == "dmidecode"
    assert ("dmidecode", "-t", "system") in transcript.calls


def test_an_unprivileged_host_yields_facts_not_an_exception(tmp_path):
    """A hardened bank host will refuse dmidecode. That is a fact, not a crash."""
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys", dmi=False),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=Transcript(dmidecode_ok=False)).collect()
    assert facts.context["disks"], "sysfs and lsblk still work without root"
    assert any("needs root" in reason for reason in facts.unavailable)
    assert facts.context["memory_modules"] == []


def test_a_failed_smartctl_does_not_lose_the_disk(tmp_path):
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=Transcript(smart_ok=False)).collect()
    assert len(facts.context["disks"]) == 2
    assert "smart" not in facts.context["disks"][0]
    assert any("smartctl" in reason for reason in facts.unavailable)


def test_missing_binaries_are_reported_not_raised(tmp_path):
    def empty(argv, timeout):
        return CommandResult(tuple(argv), 127, "", "not installed", available=False)

    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=empty).collect()
    assert facts.context["dmi"]["serial"] == "SN-0001", "sysfs needs no binary"
    commands = {reason.split(":")[0] for reason in facts.unavailable}
    assert {"dmidecode -t memory", "lsblk", "lspci"} <= commands, "sysfs covers DMI, so " \
        "dmidecode -t system is not attempted"
    assert all("binary not installed" in reason for reason in facts.unavailable)


def test_host_facts_to_dict_is_json_serialisable(tmp_path):
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=Transcript()).collect()
    payload = json.loads(json.dumps(facts.to_dict()))
    assert payload["schema"] == "cryptoscan.host-facts/1"
    assert payload["commands"][0] == ["dmidecode", "-t", "memory"]


# --------------------------------------------------------------------------- #
# the output contract
# --------------------------------------------------------------------------- #

def test_collected_context_feeds_the_agent_collector(tmp_path):
    """The reader exists to feed discovery; prove the seam, not just the dict."""
    facts = LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                               proc_root=_proc(tmp_path / "proc"),
                               runner=Transcript()).collect()
    records = AgentBasedDiscovery().collect(facts.context)
    assert len(records) == 1
    record = records[0]
    assert record["serial_reference"] == "SN-0001"
    assert record["vendor_specific"]["memory_modules"][0]["size_mb"] == 32768
    assert record["vendor_specific"]["disks"][0]["firmware"] == "GDC5"
    assert record["vendor_specific"]["nics"][0]["mac_address"] == "aa:bb:cc:dd:ee:ff"


def test_secret_material_in_a_host_fact_is_refused(tmp_path):
    """The belt over the allowlists: a payload carrying a key never leaves."""

    class Leaky(Transcript):
        def __call__(self, argv, timeout):
            if argv[0] == "dmidecode" and argv[-1] == "memory":
                self.calls.append(tuple(argv))
                return CommandResult(tuple(argv), 0,
                                     "Memory Device\n\tSize: 32 GB\n"
                                     "\tLocator: private_key\n", "")
            return super().__call__(argv, timeout)

    with pytest.raises(SecretMaterialRefused):
        LinuxHostCollector(sys_root=_sysfs(tmp_path / "sys"),
                           proc_root=_proc(tmp_path / "proc"),
                           runner=Leaky()).collect()


def test_the_real_runner_uses_no_shell(monkeypatch, tmp_path):
    """`shell=False` is not a default we hope for — it is asserted at the call."""
    captured = {}

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr("subprocess.run", fake_run)
    result = subprocess_runner(("lsblk", "--json"), 2.0)
    assert result.returncode == 0
    assert isinstance(captured["argv"], list)
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 2.0
    assert captured["kwargs"]["check"] is False


def test_a_missing_binary_is_a_result_not_a_crash(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _binary: None)
    result = subprocess_runner(("dmidecode", "-t", "system"), 2.0)
    assert result.available is False
    assert result.returncode == 127
    assert "not installed" in result.stderr
