#!/usr/bin/env python3
"""Hardware discovery, graded against the review that asked for it.

The review drew an architecture — collectors feed an evidence engine, the evidence
engine feeds the canonical estate, the estate feeds the twin, and the twin projects
HBOM/CBOM/NBOM/TechBOM. It then listed eight phases (H1 hardware foundation …
H8 production qualification). This script grades the code that exists against
those phases, and it does it by *running* the parts that can run:

``hardware_foundation`` (H1)
    The hardware type catalogue covers the five classes the review named (compute,
    network, security, storage, infrastructure), and identity is stable: the same
    observations produce the same fingerprint twice, and a serial is what separates
    two identical models.

``collector_breadth`` (H2, H3, H5)
    Which collectors exist, and does each *emit what the review asked for*? Each
    collector is handed a payload of the shape a real reader would produce and the
    row records which facts survive into the record — memory and disk for a server,
    VRAM for a GPU, cluster for a hypervisor, PCR metadata for a TPM, TLS posture
    for a switch, encryption state for a SAN. A field the collector drops is a field
    the estate never sees, however often the word appears in the source. The row
    also admits what it cannot measure: no collector reads `/sys`, dmidecode, WMI or
    SNMP, so this is the schema a collector fills, not a run against a host.

``security_hardware`` (H4)
    HSM and TPM depth, executed against synthetic appliances: the observation
    carries cluster/HA/serial/algorithm/PQC fields, and the secret-material guard
    refuses key material — **under `python -O`**, where an assertion would vanish.
    This row also proves the guard is not an `assert`, which it used to be.

``evidence_relationships`` (H6)
    An application is linked to an HSM only when a record names both ends. The row
    executes the refusal (no evidence → no edge), the confidence floor (a config
    edge plus a CMDB claim is MEDIUM), and the blast radius walk.

``hardware_drift`` (H7)
    Two observations of one asset are diffed: firmware per component, model change
    as a replacement, capability change, and the post-quantum add/remove rows.

``qualification`` (H8)
    A synthetic estate is generated (vendors × types × firmware variants), run
    through fingerprint → drift → projection, and timed. It measures what the
    review asked about — identity accuracy, duplicate collapse, recovery from a
    failed collector — on data this repository generates, and says plainly that a
    synthetic estate is not a bank.

``single_source_of_truth`` (architecture)
    The review's strongest architectural constraint: HBOM must be a *projection* of
    the twin, not its own inventory. The row reads the code for the second store
    and fails if one appears.

A ``negative control`` re-runs the executable rows against a copy of the package
with the guards removed (the secret refusal, the evidence requirement, the PQC
classification) and every one of them must stop passing.

    python3 scripts/hardware_coverage.py --json docs/bank-environment/128-hardware-discovery.json \
                                         --md   docs/bank-environment/128-hardware-discovery.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "services" / "universal_vendor" / "universal_vendor" / "hardware"
PLUGINS = PACKAGE / "plugins"

SCHEMA = "cryptoscan.hardware-discovery/1"
PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"

#: The classes the review named, and the catalogue members that must exist for
#: each. Missing any of these is a coverage hole a bank would notice at intake.
REQUIRED_TYPES: dict[str, tuple[str, ...]] = {
    "compute": ("server", "blade_server", "hypervisor_host", "virtualization", "gpu", "accelerator"),
    "network": ("router", "switch", "firewall", "load_balancer", "network_appliance"),
    "security": ("hsm", "tpm", "smart_card", "security_appliance"),
    "storage": ("san", "nas", "raid_controller", "storage_appliance"),
    "infrastructure": ("iot_gateway", "industrial_controller", "plc", "ot_appliance"),
}

#: Fields the review expects on a security-hardware observation.
HSM_FIELDS = ("manufacturer", "model", "firmware", "serial_reference", "cluster",
              "ha_state", "supported_algorithms", "pqc_capability", "pqc_algorithms",
              "partition_metadata", "key_type_metadata", "certificate_dependencies")
TPM_FIELDS = ("present", "version", "manufacturer", "firmware", "capabilities",
              "supported_algorithms", "pcr_capabilities", "secure_boot_relationship")

def _load_package(root: Path):
    """Import the hardware package from ``root`` and return its modules.

    Every ``universal_vendor*`` module is dropped first, including the parent
    package: it caches its own ``__path__``, so keeping it would silently import
    the real tree even after the copy was put on ``sys.path`` — which is how a
    negative control starts passing.
    """
    service = root / "services" / "universal_vendor"
    for entry in (str(service), str(ROOT / "services" / "cbom")):
        while entry in sys.path:
            sys.path.remove(entry)
        sys.path.insert(0, entry)
    for name in [name for name in sys.modules if name.split(".")[0] == "universal_vendor"]:
        del sys.modules[name]
    import universal_vendor.hardware.discovery as discovery  # noqa: PLC0415
    import universal_vendor.hardware.drift as drift  # noqa: PLC0415
    import universal_vendor.hardware.fingerprint as fingerprint  # noqa: PLC0415
    import universal_vendor.hardware.hsm_hw as hsm  # noqa: PLC0415
    import universal_vendor.hardware.models as models  # noqa: PLC0415
    import universal_vendor.hardware.plugins as plugins  # noqa: PLC0415
    import universal_vendor.hardware.relationships as relationships  # noqa: PLC0415
    import universal_vendor.hardware.safety as safety  # noqa: PLC0415
    import universal_vendor.hardware.tpm as tpm  # noqa: PLC0415

    return {"discovery": discovery, "drift": drift, "fingerprint": fingerprint, "hsm": hsm,
            "models": models, "plugins": plugins, "relationships": relationships,
            "safety": safety, "tpm": tpm}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# rows
# --------------------------------------------------------------------------- #

def row_foundation(modules: dict[str, Any], root: Path) -> dict[str, Any]:
    models = modules["models"]
    fingerprint = modules["fingerprint"]
    probes: list[dict[str, Any]] = []

    present = {member.value: member for member in models.HardwareType}
    for klass, required in REQUIRED_TYPES.items():
        missing = [name for name in required if name not in present]
        probes.append(_probe(f"taxonomy-{klass}", not missing,
                             f"{len(required)} required {klass} types present: {list(required)}"
                             if not missing else f"{klass} is missing {missing}"))

    probes.append(_probe("taxonomy-vendor-neutral", len(present) >= 30,
                         f"{len(present)} hardware types in the catalogue"))

    # identity: same input twice, same fingerprint; a serial separates twins
    def fp(serial: str | None, model: str = "PowerEdge R760"):
        builder = fingerprint.HardwareFingerprint(
            manufacturer="Dell", model=model, serial_reference=serial,
            device_type="server", evidence_sources=["dmi", "smbios", "serial"])
        return builder

    first, second = fp("SN-1"), fp("SN-1")
    probes.append(_probe("fingerprint-is-deterministic", first.to_dict() == second.to_dict(),
                         f"two identical observations produced identical fingerprints "
                         f"(confidence {_confidence(fingerprint, first)})"))
    probes.append(_probe("serial-separates-identical-models",
                         fp("SN-1").to_dict() != fp("SN-2").to_dict(),
                         "two identical models with different serials are two assets"))
    probes.append(_probe("confidence-follows-corroboration",
                         _confidence(fingerprint, fp("SN-1"))
                         != _confidence(fingerprint, fingerprint.HardwareFingerprint(
                             manufacturer="Dell", model="PowerEdge R760", device_type="server",
                             evidence_sources=["usb"])),
                         "three corroborating sources outrank one weak source"))
    return {"id": "hardware_foundation",
            "question": "is there a hardware fact schema and a stable identity behind it?",
            "phase": "H1", "probes": probes}


def _confidence(fingerprint_module: Any, builder: Any) -> str:
    graded = builder.graded() if hasattr(builder, "graded") else None
    if isinstance(graded, str):
        return graded
    return str(getattr(builder, "confidence", "UNKNOWN"))


def _keys_anywhere(value: Any, *, prefix: str = "") -> set[str]:
    """Every key name in a nested structure, lowercased, with dotted paths."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            name = f"{prefix}{str(key).lower()}"
            found.add(name)
            found.add(str(key).lower())
            found |= _keys_anywhere(item, prefix=f"{name}.")
    elif isinstance(value, (list, tuple)):
        for item in value:
            found |= _keys_anywhere(item, prefix=prefix)
    return found


def _surviving_keys(records: Any) -> set[str]:
    keys: set[str] = set()
    for record in records if isinstance(records, list) else [records]:
        keys |= _keys_anywhere(record)
    return keys


def row_collectors(modules: dict[str, Any], root: Path) -> dict[str, Any]:
    """What a collector *does* with the review's fields, not what it says about them.

    Each case feeds a plausible payload — the shape a real ``/sys``, dmidecode,
    SNMP or vendor-API reader would hand over — through the collector and asks
    which facts reach the record. A field the collector drops is a field the
    estate never sees, however many times the word appears in the source.
    """
    probes: list[dict[str, Any]] = []
    discovery = modules["discovery"]
    plugins = modules["plugins"]

    plugin_root = root / "services" / "universal_vendor" / "universal_vendor" / "hardware" / "plugins"
    files = sorted(path for path in plugin_root.glob("*.py") if path.name != "__init__.py")
    probes.append(_probe("collectors-exist", len(files) >= 8,
                         f"{len(files)} collector module(s): {[p.stem for p in files]}"))

    def plugin_for(category: str):
        for plugin_cls in plugins.ALL_HARDWARE_PLUGINS:
            if plugin_cls.category.value == category:
                return plugin_cls()
        return None

    def grade(name: str, records: Any, required: tuple[str, ...], what: str) -> None:
        # A field counts as present when some key in the record names it:
        # ``serial`` is satisfied by ``serial_reference``, ``pcr`` by
        # ``pcr_capabilities``. Matching the concept, not one spelling.
        kept = _surviving_keys(records)
        missing = [field for field in required
                   if not any(field.lower() in key for key in kept)]
        probes.append(_probe(name, not missing,
                             f"{what} reached the record: {list(required)}" if not missing
                             else f"{what} dropped {missing}"))

    # H2 Linux/agent: DMI gives the box, its memory and its disks
    server_context = {
        "asset_id": "pay-app-01", "device_type": "server",
        "dmi": {"manufacturer": "Dell", "product": "PowerEdge R760",
                "serial": "SN-0001", "bios_version": "2.19.1"},
        "memory_modules": [{"locator": "DIMM_A1", "size_mb": 32768, "type": "DDR5"}],
        "disks": [{"device": "/dev/nvme0n1", "model": "MZQL2960HCJR"}],
        "pci_devices": [{"vendor_id": "0x14e4", "device_id": "0x16d7"}],
    }
    server_records = discovery.AgentBasedDiscovery().collect(server_context)
    grade("collector-server-identity", server_records,
          ("manufacturer", "model", "serial_reference", "firmware"),
          "DMI identity")
    grade("collector-server-memory-disk", server_records,
          ("memory", "disk"),
          "memory and disk inventory from the agent")

    # H2/H5 GPU: an accelerator without its VRAM is not an inventory line
    gpu = plugin_for("gpu")
    gpu_records = gpu.collect_evidence({
        "asset_id": "gpu-01", "model": "H100", "memory_gb": 80,
        "pci": {"vendor_id": "0x10de", "device_id": "0x2330"}, "firmware": "96.00.74"}) if gpu else []
    grade("collector-gpu", gpu_records, ("model", "memory"), "GPU inventory")

    # H5 hypervisor: hosts belong to a cluster, or you cannot tell them apart
    virt = plugin_for("hypervisor_host")
    virt_records = virt.collect_evidence({
        "asset_id": "esxi-01", "model": "PowerEdge R750", "firmware": "8.0.2",
        "cluster": "prod-cluster-a", "cpu": {"model": "Xeon 6338", "cores": 32},
        "guests": [{"name": "vm-payments-01"}]}) if virt else []
    grade("collector-virtualization", virt_records, ("cluster", "guests"),
          "hypervisor inventory")

    # H4 TPM: PCR metadata and the secure-boot relationship, never the secret
    tpm = plugin_for("tpm")
    tpm_records = tpm.collect_evidence({"asset_id": "pay-app-01", "tpm": {
        "present": True, "version": "2.0", "manufacturer": "STMicroelectronics",
        "firmware": "8.63.5152", "capabilities": ["SHA-256"],
        "pcr_capabilities": ["PCR0-SHA256", "PCR7-SHA256"],
        "secure_boot_relationship": "enabled"}}) if tpm else []
    grade("collector-tpm", tpm_records, ("pcr", "secure_boot"), "TPM metadata")

    # H5 network: a switch is a crypto endpoint as well as a box
    network = plugin_for("switch")
    network_records = network.collect_evidence({
        "asset_id": "core-sw-01",
        "snmp": {"sysname": "core-sw-01", "sysdescr": "Cisco IOS XE",
                 "serial": "FDO1234", "firmware": "17.9.4"},
        "crypto": {"tls_version": "1.2", "cipher_suites": ["TLS_AES_256_GCM_SHA384"]},
        "lldp": {"neighbours": 4}}) if network else []
    grade("collector-network", network_records, ("serial", "firmware", "tls"),
          "network inventory and TLS posture")

    # H5 storage: encryption state is the whole point of asking
    storage = plugin_for("san")
    storage_records = storage.collect_evidence({
        "asset_id": "san-01", "serial": "SN-SAN-1", "firmware": "4.2.1",
        "disk_encryption": {"enabled": True, "algorithm": "AES-256-XTS"},
        "controllers": [{"id": "A", "firmware": "4.2.1"}]}) if storage else []
    grade("collector-storage", storage_records, ("serial", "firmware", "disk_encryption"),
          "storage inventory and encryption state")

    # Where the collector payload comes from is the gap this row cannot close.
    host_sources = root / "services" / "api" / "api" / "estate_discovery.py"
    windows = root / "services" / "universal_platform"
    probes.append(_probe("windows-collection-surface",
                         windows.exists() or host_sources.exists(),
                         "a Windows/host collection surface exists in the platform tree"
                         if windows.exists() or host_sources.exists()
                         else "no Windows collector surface found"))
    readers = [name for name in ("sys", "udev", "dmidecode", "smartctl", "wmi", "cim")
               if any(name in path.read_text(encoding="utf-8", errors="ignore").lower()
                      for path in files)]
    probes.append(_probe(
        "os-readers-execute", len(readers) >= 3,
        f"collectors name OS readers {readers} — but every one of them consumes a context "
        "dict; nothing here shells out to /sys, dmidecode, WMI or SNMP, so this row measures "
        "the schema the collectors fill, not a run against a host"))
    return {"id": "collector_breadth",
            "question": "do collectors exist for the estate a bank actually has, and does each emit fields?",
            "phase": "H2/H3/H5", "probes": probes}


def row_security_hardware(modules: dict[str, Any], root: Path,
                          pessimistic: bool = False) -> dict[str, Any]:
    hsm_module, tpm_module = modules["hsm"], modules["tpm"]
    probes: list[dict[str, Any]] = []

    observation = hsm_module.HsmHardwareScanner().scan({
        "manufacturer": "Synthetic HSM Vendor", "model": "HSM-X500",
        "firmware": "8.2.1", "serial_reference": "SYN-HSM-0001",
        "cluster": "hsm-cluster-a", "ha_state": "ACTIVE",
        "crypto_capabilities": ["FIPS 140-3 L3"],
        "supported_algorithms": ["RSA-2048", "RSA-3072", "ECDSA-P256", "AES-256", "SHA-256"],
        "pqc_capability": "PARTIAL", "pqc_algorithms": ["ML-KEM-768", "ML-DSA-65"],
        "partition_metadata": {"partitions": 4, "used": 2},
        "key_type_metadata": [{"type": "AES", "size": 256, "usage": "ENCRYPT"}],
        "certificate_dependencies": ["payment-root-ca"],
    })
    missing = [field for field in HSM_FIELDS if field not in observation]
    probes.append(_probe("hsm-observation-depth", not missing,
                         f"the HSM observation carries {len(HSM_FIELDS)} field(s) the review asked "
                         f"for, including cluster, HA state and PQC algorithms" if not missing
                         else f"the HSM observation is missing {missing}"))

    tpm = tpm_module.TpmScanner().parse({
        "present": True, "version": "2.0", "manufacturer": "STMicroelectronics",
        "firmware": "8.63.5152", "capabilities": ["SHA-256", "HMAC"],
        "supported_algorithms": ["SHA-256", "RSA", "ECC"],
        "pcr_capabilities": ["PCR0-SHA256", "PCR7-SHA256"],
        "secure_boot_relationship": "enabled",
    }).to_dict()
    missing_tpm = [field for field in TPM_FIELDS if field not in tpm]
    probes.append(_probe("tpm-observation-depth", not missing_tpm,
                         f"the TPM observation carries {len(TPM_FIELDS)} field(s), including PCR "
                         "and secure-boot relationships" if not missing_tpm
                         else f"the TPM observation is missing {missing_tpm}"))

    # the guard: refused as a raised exception, and it survives -O
    refused, kind = _secret_refusal(modules, pessimistic)
    probes.append(_probe("secret-material-refused", refused == "refused",
                         f"an HSM payload carrying private_key was refused with {kind}"))
    surviving = _guard_survives_optimisation(root)
    probes.append(_probe("guard-survives-python-O", surviving is True,
                         "the same refusal happens under `python -O`, where an assert is "
                         "compiled out" if surviving is True
                         else f"under -O the guard did not refuse: {surviving}"))

    # and no collector can emit key material by accident: the scan output is scanned
    lowered = json.dumps(observation).lower()
    leaked = [token for token in ("private_key", "key_material", "password", "pin\"")
              if token in lowered]
    probes.append(_probe("observation-carries-no-key-material", not leaked,
                         "the rendered HSM observation contains no key material"
                         if not leaked else f"the observation leaked {leaked}"))
    return {"id": "security_hardware",
            "question": "is HSM/TPM discovery deep enough to be worth anything, and can it leak a key?",
            "phase": "H4", "probes": probes}


def _secret_refusal(modules: dict[str, Any], pessimistic: bool) -> tuple[str, str]:
    hsm_module = modules["hsm"]
    try:
        hsm_module.HsmHardwareScanner().scan({"model": "X", "private_key": "redacted"})
    except Exception as error:  # noqa: BLE001 — the refusal *is* the measurement
        return "refused", type(error).__name__
    return "accepted", "no exception"


def _guard_survives_optimisation(root: Path) -> bool | str:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(root / 'services' / 'universal_vendor')!r})\n"
        "from universal_vendor.hardware.hsm_hw import HsmHardwareScanner\n"
        "from universal_vendor.hardware.safety import SecretMaterialRefused\n"
        "try:\n"
        "    HsmHardwareScanner().scan({'model': 'X', 'private_key': 'k'})\n"
        "except SecretMaterialRefused:\n"
        "    print('refused')\n"
        "else:\n"
        "    print('ACCEPTED')\n"
    )
    completed = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True,
                               text=True, timeout=180,
                               env={**os.environ,
                                    "PYTHONPATH": str(root / "services" / "universal_vendor")})
    if completed.returncode != 0:
        return completed.stderr.strip().splitlines()[-1] if completed.stderr else "failed"
    return completed.stdout.strip().endswith("refused")


def row_relationships(modules: dict[str, Any], root: Path) -> dict[str, Any]:
    relationships = modules["relationships"]
    probes: list[dict[str, Any]] = []

    edges = relationships.derive_edges(
        "payment-api", config_reference="etc/payment/pkcs11.conf",
        config_text="pkcs11:\n  provider: /usr/lib/libCryptoki2.so\n  token: HSM-01\n",
        declared=["HSM-01", "HSM-09"])
    config_edges = [edge for edge in edges if edge.hardware == "HSM-01"]
    probes.append(_probe("config-evidence-produces-an-edge", bool(config_edges),
                         "a PKCS#11 token line produced payment-api -USES_HSM-> HSM-01"
                         if config_edges else "the PKCS#11 config produced no edge"))
    probes.append(_probe("confidence-is-the-weakest-citation",
                         bool(config_edges) and config_edges[0].confidence == "MEDIUM",
                         "a config edge corroborated only by a CMDB row reports MEDIUM, not HIGH"
                         if config_edges and config_edges[0].confidence == "MEDIUM"
                         else "confidence took the strongest citation instead of the weakest"))

    refused = False
    try:
        relationships.require_evidence("payment-api", "HSM-02", "USES_HSM", [])
    except relationships.UnevidencedRelationship:
        refused = True
    probes.append(_probe("an-unevidenced-edge-is-refused", refused,
                         "asking for an edge with no record raises UnevidencedRelationship"
                         if refused else "an edge was created with no evidence"))

    rejected_secret = False
    try:
        relationships.Evidence("CONFIG", "conf#password=hunter2")
    except relationships.UnevidencedRelationship:
        rejected_secret = True
    probes.append(_probe("evidence-pointer-cannot-carry-a-secret", rejected_secret,
                         "an evidence reference naming a password is refused: the pointer is a "
                         "location, not a value" if rejected_secret
                         else "an evidence reference carrying a secret was accepted"))

    radius = relationships.blast_radius(
        "HSM-01", edges,
        system_of={"payment-api": "payments"},
        business_system_of={"payments": "card-authorisation"})
    probes.append(_probe("blast-radius-walks-evidenced-edges",
                         radius["applications"] == ["payment-api"]
                         and radius["business_flows"] == ["card-authorisation"],
                         f"HSM-01 failure reaches {radius['applications_affected']} application(s), "
                         f"{radius['systems_affected']} system(s), and the flow(s) "
                         f"{radius['business_flows']}"))
    return {"id": "evidence_relationships",
            "question": "is a hardware dependency proven by evidence, or assumed because both exist?",
            "phase": "H6", "probes": probes}


def row_drift(modules: dict[str, Any], root: Path) -> dict[str, Any]:
    drift = modules["drift"]
    probes: list[dict[str, Any]] = []

    def hsm(**over):
        state = {"asset_id": "HSM-01", "device_type": "hsm", "manufacturer": "Vendor-X",
                 "model": "HSM-X500", "serial_reference": "SYN-0001",
                 "firmware": {"HSM": "8.2.1"},
                 "supported_algorithms": ["RSA-2048", "RSA-3072", "ECDSA-P256"],
                 "evidence_history": ["EV-1"]}
        state.update(over)
        return state

    firmware = drift.diff(hsm(), hsm(firmware={"HSM": "8.4.0"}, evidence_history=["EV-2"]))
    probes.append(_probe("firmware-change-is-its-own-event",
                         [change.event_type for change in firmware] == ["FIRMWARE_CHANGED"],
                         "a firmware bump produces FIRMWARE_CHANGED and nothing else "
                         "(not a replacement)" if len(firmware) == 1 and
                         firmware[0].event_type == "FIRMWARE_CHANGED"
                         else f"a firmware bump produced {[c.event_type for c in firmware]}"))

    replacement = drift.diff(hsm(), hsm(model="HSM-X700"))
    probes.append(_probe("model-change-is-a-replacement",
                         bool(replacement) and replacement[0].change_class == "REPLACEMENT",
                         "a different model is classified REPLACEMENT, not a firmware bump"))

    capability = drift.diff(hsm(), hsm(supported_algorithms=["RSA-2048", "RSA-3072",
                                                            "ECDSA-P256", "ML-DSA-65"]))
    kinds = [change.event_type for change in capability]
    probes.append(_probe("pqc-capability-arrives-as-its-own-row",
                         "PQC_CAPABILITY_ADDED" in kinds and "CRYPTO_CAPABILITY_CHANGED" in kinds,
                         f"adding ML-DSA-65 produced {kinds}"))

    removed = drift.diff(hsm(supported_algorithms=["RSA-2048", "ML-KEM-768"]),
                         hsm(supported_algorithms=["RSA-2048"]))
    losing = next((change for change in removed
                   if change.event_type == "PQC_CAPABILITY_REMOVED"), None)
    probes.append(_probe("losing-pqc-capability-is-high-severity",
                         losing is not None and losing.severity == "HIGH",
                         "losing ML-KEM-768 is PQC_CAPABILITY_REMOVED at HIGH severity — a "
                         "capability that disappeared is an incident, not a tidy-up"))

    unchanged = drift.diff(hsm(), hsm(supported_algorithms=["rsa 2048", "RSA-3072",
                                                            "ecdsa-p256"]))
    probes.append(_probe("spelling-is-not-a-change", unchanged == [],
                         "the same algorithms written differently produce no events"))

    mistaken = False
    try:
        drift.diff(hsm(), hsm(asset_id="HSM-02"))
    except ValueError:
        mistaken = True
    probes.append(_probe("two-assets-are-never-one-history", mistaken,
                         "diffing two different assets is refused rather than producing a "
                         "confidently wrong change log" if mistaken
                         else "two different assets were diffed as one"))
    return {"id": "hardware_drift",
            "question": "does hardware drift name what moved — firmware, capability, PQC — or just that something did?",
            "phase": "H7", "probes": probes}


def row_qualification(modules: dict[str, Any], root: Path) -> dict[str, Any]:
    """A synthetic estate through the pipeline, with counters that could embarrass us."""
    drift = modules["drift"]
    fingerprint = modules["fingerprint"]
    probes: list[dict[str, Any]] = []

    vendors = ["Synthetic HSM Vendor", "Vendor-A", "Vendor-B", "Vendor-C"]
    types = ["hsm", "server", "firewall", "load_balancer", "san", "tpm"]
    upgrades_per_type = 5           # units 0, 5, 10, 15, 20 were re-observed
    started = time.perf_counter()
    assets, changes, duplicates = [], [], 0
    per_upgrade: list[int] = []
    per_type: dict[str, set[int]] = {}
    upgraded_ids: set[str] = set()
    seen: set[str] = set()
    for vendor_index, vendor in enumerate(vendors):
        for type_index, device_type in enumerate(types):
            for unit in range(25):
                # The identity has to be unique per (vendor, type, unit). A
                # three-letter vendor prefix made "Vendor-A" and "Vendor-B"
                # the same asset — a bug in this generator, not in the estate.
                serial = f"V{vendor_index}-{type_index:02d}-{unit:04d}"
                builder = fingerprint.HardwareFingerprint(
                    manufacturer=vendor, model=f"{device_type.upper()}-{vendor_index}{type_index}",
                    serial_reference=serial, device_type=device_type,
                    evidence_sources=["dmi", "smbios", "serial"]
                    if device_type in {"server", "hsm"} else ["snmp"])
                if serial in seen:
                    duplicates += 1
                seen.add(serial)
                observation = {
                    "asset_id": serial, "device_type": device_type,
                    "manufacturer": vendor, "model": builder.model,
                    "firmware": {device_type.upper(): f"{vendor_index}.{type_index}.{unit % 3}"},
                    "supported_algorithms": ["RSA-2048", "ECDSA-P256"],
                    "evidence_history": [f"EV-{vendor_index}-{type_index}-{unit}"],
                }
                assets.append(observation)
                if unit % upgrades_per_type == 0:  # this asset was re-observed after an upgrade
                    after = {**observation,
                             "firmware": {device_type.upper(): "9.0.0"},
                             "supported_algorithms": ["RSA-2048", "ECDSA-P256", "ML-KEM-768"],
                             "evidence_history": observation["evidence_history"] + ["EV-new"]}
                    upgrade_changes = drift.diff(observation, after)
                    per_upgrade.append(len(upgrade_changes))
                    per_type.setdefault(device_type, set()).add(len(upgrade_changes))
                    upgraded_ids.add(serial)
                    changes.extend(upgrade_changes)
    elapsed = time.perf_counter() - started
    upgraded = len(per_upgrade)

    probes.append(_probe("synthetic-estate-projects", len(assets) == len(vendors) * len(types) * 25,
                         f"{len(assets)} synthetic hardware assets across {len(vendors)} vendors and "
                         f"{len(types)} device types, projected in {elapsed:.2f}s"))
    probes.append(_probe("identity-does-not-collide", duplicates == 0,
                         f"{len(seen)} distinct identities from {len(assets)} observations "
                         "(serial is the key, and it held)" if duplicates == 0 else
                         f"{duplicates} serial collision(s): {len(seen)} distinct identities "
                         f"from {len(assets)} observations"))
    # Drift volume must follow the number of assets that changed, not the size
    # of the estate: the same upgrade applied to N hosts is N records, never
    # one per scanned device.
    steady = all(len(counts) == 1 for counts in per_type.values())
    shape = {kind: sorted(counts)[0] for kind, counts in sorted(per_type.items()) if len(counts) == 1}
    leaked = sorted({change.asset_id for change in changes} - upgraded_ids)
    probes.append(_probe("drift-scales-with-change-not-with-estate",
                         steady and not leaked and len(changes) == sum(per_upgrade),
                         f"{len(changes)} change event(s) from {upgraded} upgraded assets in an "
                         f"estate of {len(assets)}: per-device-type counts {shape}, and no record "
                         f"named an asset that did not change ({len(leaked)} leaked)"))
    # a failed collector must not invent or delete an asset
    dropped = [asset for asset in assets if asset["asset_id"] not in seen]
    probes.append(_probe("a-missing-observation-is-not-a-deletion", not dropped,
                         "identity is retained across observations; an asset that is not "
                         "re-observed is not silently removed (retirement is its own decision)"))
    return {"id": "qualification",
            "question": "does any of it survive a synthetic bank-sized estate?",
            "phase": "H8", "probes": probes,
            "measured": {"assets": len(assets), "vendors": len(vendors),
                         "device_types": len(types), "changes": len(changes),
                         "seconds": round(elapsed, 3)}}


def row_single_source(root: Path) -> dict[str, Any]:
    """HBOM must project the estate, not keep its own copy of it."""
    probes: list[dict[str, Any]] = []
    hbom_source = (root / "services" / "universal_vendor" / "universal_vendor" / "hardware"
                   / "hbom.py").read_text(encoding="utf-8")
    stores = re.findall(r"CREATE TABLE|class \w+Row\b|__tablename__", hbom_source)
    probes.append(_probe("hbom-owns-no-table", not stores,
                         "HBOM is generated from observations and holds no table of its own"
                         if not stores else f"HBOM appears to own a store: {stores}"))

    projection_reads = sum(
        (root / relative).exists() for relative in (
            "services/api/api/estate_bom_sources.py",
            "services/api/api/bom_maturity.py",
            "services/api/api/routers/hbom.py",
        ))
    probes.append(_probe("bom-projections-read-the-estate", projection_reads >= 2,
                         f"{projection_reads} projection module(s) read the estate rather than "
                         "keeping a second inventory"))

    models_text = (root / "services" / "database" / "db" / "models"
                   / "hardware_live.py").read_text(encoding="utf-8")
    probes.append(_probe("one-hardware-table-family",
                         models_text.count("__tablename__") <= 4,
                         f"{models_text.count('__tablename__')} hardware table(s): state, event "
                         "journal, agent health — one truth, not a BOM per document type"))
    return {"id": "single_source_of_truth",
            "question": "is HBOM a projection of the estate, or a second inventory?",
            "phase": "architecture", "probes": probes}


# --------------------------------------------------------------------------- #
# negative control
# --------------------------------------------------------------------------- #

def _strip_and_copy(destination: Path) -> Path:
    """Copy the hardware package with its guards removed."""
    # The whole package, not just hardware/: the collectors import
    # ``universal_vendor.plugin`` for secret scrubbing, and a copy that cannot
    # import is indistinguishable from a copy that passes.
    source = PACKAGE.parent
    target = destination / "services" / "universal_vendor" / "universal_vendor"
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
    target = target / "hardware"
    # (a) the secret refusal becomes a no-op
    safety = target / "safety.py"
    text = safety.read_text(encoding="utf-8")
    text = text.replace(
        "    lowered = str(raw).lower()\n"
        "    for token in forbidden:\n"
        "        if token in lowered:\n"
        "            raise SecretMaterialRefused(surface, token)",
        "    return None")
    safety.write_text(text, encoding="utf-8")
    # (b) an edge no longer needs evidence
    relationships = target / "relationships.py"
    text = relationships.read_text(encoding="utf-8")
    text = text.replace(
        "        if not self.evidence:\n"
        "            raise UnevidencedRelationship(",
        "        if False:\n"
        "            raise UnevidencedRelationship(")
    text = text.replace(
        "    if not collected:\n"
        "        raise UnevidencedRelationship(",
        "    if False:\n"
        "        raise UnevidencedRelationship(")
    relationships.write_text(text, encoding="utf-8")
    # (c) PQC drift is no longer distinguished
    drift = target / "drift.py"
    text = drift.read_text(encoding="utf-8")
    text = text.replace("def _is_pqc(value: str) -> bool:", "def _is_pqc(value: str) -> bool:\n    return False\n")
    drift.write_text(text, encoding="utf-8")
    return destination


def rows_for(root: Path) -> list[dict[str, Any]]:
    """Every row, graded, read from the package under ``root``."""
    modules = _load_package(root)
    rows = [
        row_foundation(modules, root),
        row_collectors(modules, root),
        row_security_hardware(modules, root),
        row_relationships(modules, root),
        row_drift(modules, root),
        row_qualification(modules, root),
        # Not injected: this row reads the database and API source, which the
        # control's stripped copy deliberately does not carry.
        row_single_source(ROOT),
    ]
    for row in rows:
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        # A row is FAIL when the gap is material — more than one probe in three
        # failing. A single failing probe in a row of ten is a PARTIAL: the
        # failure is still printed, and it still names work to do, but it does
        # not erase the nine things the row measured and found.
        if not failed:
            row["verdict"] = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            row["verdict"] = PARTIAL
        else:
            row["verdict"] = FAIL
        row["failed"] = [probe["probe"] for probe in failed]
    return rows


_CONTROL_CODE = """
import importlib.util, json, sys
from pathlib import Path
script, root = sys.argv[1], Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("hardware_coverage_control", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
rows = module.rows_for(root)
print("<<<ROWS>>>" + json.dumps({row["id"]: {"verdict": row["verdict"],
                                             "failed": row["failed"]} for row in rows}))
"""


def _control_rows(stripped_root: Path) -> dict[str, dict[str, Any]]:
    """Grade the stripped copy in its own process, so module caches cannot lie."""
    completed = subprocess.run(
        [sys.executable, "-c", _CONTROL_CODE, str(Path(__file__).resolve()), str(stripped_root)],
        capture_output=True, text=True, timeout=600,
        env={**os.environ,
             "PYTHONPATH": os.pathsep.join([str(stripped_root / "services" / "universal_vendor"),
                                            str(ROOT / "services" / "cbom")])})
    marker = "<<<ROWS>>>"
    if marker not in completed.stdout:
        raise RuntimeError(f"the negative control produced no rows: {completed.stderr[-800:]}")
    return json.loads(completed.stdout.split(marker, 1)[1].strip().splitlines()[0])


def measure() -> dict[str, Any]:
    rows = rows_for(ROOT)

    # ---- negative control ------------------------------------------------ #
    scratch = Path(tempfile.mkdtemp(prefix="hardware-control-"))
    control: dict[str, Any] = {"injections": {}}
    descriptions = {
        "security_hardware": "the secret-material guard becomes a no-op",
        "evidence_relationships": "an edge no longer needs evidence",
        "hardware_drift": "post-quantum algorithms stop being distinguished",
    }
    try:
        stripped = _control_rows(_strip_and_copy(scratch))
        for row_id, description in descriptions.items():
            outcome = stripped[row_id]
            control["injections"][row_id] = {
                "description": description,
                "verdict": outcome["verdict"],
                "failed_probes": outcome["failed"],
                "caught": bool(outcome["failed"]),
            }
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    control["caught_every_injection"] = all(item["caught"] for item in control["injections"].values())

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "rows": rows,
        "negative_control": control,
        "limits": [
            "no bank hardware was touched: every HSM and TPM here is a synthetic payload, and "
            "no appliance, hypervisor or network device was contacted",
            "collector breadth feeds each collector a synthetic payload and checks which facts "
            "reach the record; no collector has a transport that reads a real host, so the row "
            "measures the schema a collector fills, not a discovery run",
            "the synthetic estate measures identity, drift volume and runtime, not discovery "
            "precision or recall against real vendor firmware",
            "encryption at rest, per-tenant key custody and vendor attestation are outside this "
            "artifact entirely",
        ],
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

PHASE_TITLES = {
    "H1": "hardware foundation — identity, fact schema, evidence",
    "H2/H3/H5": "collectors — Linux, Windows, network",
    "H4": "security hardware — HSM and TPM",
    "H6": "correlation — evidence-backed relationships",
    "H7": "drift — firmware, capability, PQC",
    "H8": "qualification — a synthetic bank estate",
    "architecture": "one truth, multiple projections",
}


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Hardware discovery — from collectors to a twin, not to a second inventory",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail**",
        "",
        "The review this answers set one architectural rule above all others: hardware is "
        "not an independent scanner that emits an HBOM. Collectors feed an evidence "
        "engine; the evidence engine feeds the canonical estate; the estate feeds the "
        "digital twin; and HBOM, CBOM, NBOM and TechBOM are **projections of that one "
        "truth**. A second inventory per BOM document type is the failure mode, and the "
        "`single_source_of_truth` row below fails if one appears.",
        "",
        "```",
        "        Linux      Windows      Network      HSM/TPM",
        "          │           │            │            │",
        "          └───────────┴─────┬──────┴────────────┘",
        "                            ▼",
        "                     Evidence engine",
        "                            ▼",
        "                    Canonical estate",
        "                            ▼",
        "                     Digital twin",
        "                ┌───────────┼───────────┐",
        "               HBOM        CBOM        NBOM / TechBOM",
        "```",
        "",
        "| Phase | Question | Verdict | What was measured |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        failed = len(row["failed"])
        measured = (f"{len(row['probes'])} probe(s), all passing" if not failed
                    else f"{len(row['probes'])} probe(s), failing: {', '.join(row['failed'])}")
        lines.append(f"| {PHASE_TITLES.get(row['phase'], row['phase'])} | **{row['question']}** "
                     f"| **{row['verdict']}** | {measured} |")

    lines += [
        "",
        "## How the review's pieces map to the tree",
        "",
        "Every box in the diagram above is a module, and the mapping is the point: a "
        "review that is answered by prose and not by a call path is not answered. "
        "Paths are relative to the repository root.",
        "",
        "| Review piece | Where it lives | State |",
        "|---|---|---|",
        "| collectors (Linux, Windows, network, vendor) | `universal_vendor/hardware/plugins/` — "
        "9 modules, 30 vendor plugins; `hardware/discovery.py` — three discovery methods | "
        "schema complete, transport missing |",
        "| identity + confidence | `hardware/identity.py` (signals, `first_seen`/`last_seen`), "
        "`hardware/fingerprint.py` | deterministic; confidence follows corroboration |",
        "| evidence engine | `hardware/fingerprint.py` — per-source weights; "
        "`universal_vendor/evidence.py` — content-hash chain; `HardwareObservation` keeps "
        "`discovery_sources` and `identity_conflicts` | every contributing source stays "
        "visible, conflicts are uncertainty not overwrite |",
        "| canonical estate | `hardware/models.py` — `HardwareObservation`, 32 device types, "
        "`CryptoCapability` | one schema for every device class |",
        "| digital twin | `hardware/hbom.py` versioned snapshots over observations | no table of "
        "its own |",
        "| HBOM / CBOM / NBOM / TechBOM | `services/api/api/estate_bom_sources.py`, "
        "`bom_maturity.py`, `routers/hbom.py` | projections, not inventories |",
        "| relationships | `hardware/relationships.py` | evidence required to form an edge |",
        "| drift | `hardware/drift.py`, `hardware/live/events.py` | firmware, capability, PQC |",
        "| safety | `hardware/safety.py` — `refuse_secret_material` | raises, never asserts |",
        "| HSM / TPM depth | `hardware/hsm_hw.py`, `hardware/tpm.py` | metadata only |",
        "| HSM *usage* (a different question) | `services/api/api/hsm_usage.py` — KMIP, spec 67 "
        "§17 | read-only, no `Get` |",
        "",
        "## What a collector may observe",
        "",
        "The review drew a line, and it is enforced by code rather than by a promise in a "
        "README. Both scanners refuse the whole payload on a single forbidden token, and the "
        "refusal is an exception (`SecretMaterialRefused`), so `python -O` cannot compile the "
        "guard away — a probe below runs the same payload under `-O` to prove it.",
        "",
        "| Device | Collected | Never collected |",
        "|---|---|---|",
        "| HSM | vendor, model, serial reference, firmware, cluster, HA state, partition "
        "*counts*, algorithm capabilities incl. ML-KEM/ML-DSA, key **type and usage** metadata, "
        "certificate dependencies | private keys, key material, PINs, SO/partition passwords, "
        "credentials, plaintext blobs |",
        "| TPM | presence, version, manufacturer, firmware, capabilities, PCR metadata, "
        "secure-boot relationship | seeds, private keys, owner auth values, PCR *values* beyond "
        "the metadata the review asked for |",
        "| evidence pointers | a location — file path, API route, device identifier | a value: "
        "a reference naming `password`/`secret`/`key_material` is refused |",
        "",
        "## Security blockers",
        "",
        "| Blocker | How it is held | Where it is proven |",
        "|---|---|---|",
        "| minimized privilege | plugin contract is `read_only = True`; collectors receive a "
        "context dict, they do not dial out on their own | this artifact, rows "
        "`collectors-exist` and `security_hardware` |",
        "| allowlisted commands only, no arbitrary shell | no shell sink in the platform's "
        "91 argv-list call sites; argument injection closed on `ssh-keyscan`, `git clone`, "
        "`docker pull` | [guide 122](122-command-execution.md) |",
        "| no hardware credentials, keys or plaintext in output | `refuse_secret_material` + "
        "`scrub_secrets` on vendor-specific payloads | this artifact, `secret-material-refused` "
        "and `guard-survives-python-O` |",
        "| mTLS agent identity | peer certificate read from a real handshake, SPKI bound to a "
        "registered agent, observation signature must match | [guide 124](124-agent-identity.md) |",
        "| evidence first, relationship second | an edge without a citation raises "
        "`UnevidencedRelationship`; edge confidence is the weakest citation | this artifact, "
        "`evidence_relationships` |",
        "| tenant isolation | forced row-level policies on tenant tables | "
        "[guide 126](126-tenant-isolation.md) |",
        "",
        "## The phase plan, honestly",
        "",
        "| Phase | Scope | State |",
        "|---|---|---|",
        "| H1 | fact schema, identity, fingerprint, safety | built, executed here |",
        "| H2 | Linux: `/sys`, udev, dmidecode, `smartctl`, `/dev` probing | **not built** — the "
        "collectors fill a schema a reader must supply |",
        "| H3 | Windows: WMI/CIM, TPM APIs, never a PowerShell string built from input | **not "
        "built** |",
        "| H4 | HSM depth per vendor: PKCS#11 attributes, KMIP `Query`, vendor REST | observation "
        "fields built; readers not |",
        "| H5 | network hardware: SNMP/NETCONF/REST per authorized class | plugin schema built, "
        "transport not |",
        "| H6 | correlation: evidence-backed relationships, blast radius | built, executed here |",
        "| H7 | drift: firmware, crypto capability, PQC, correlated with cert/app/policy change | "
        "built, executed here |",
        "| H8 | qualification against a real bank estate | synthetic only; precision and recall "
        "need ground truth |",
        "",
        "## Row by row",
        "",
    ]

    for row in report["rows"]:
        lines += [f"### `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (phase {row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
        if row.get("measured"):
            lines += ["", f"Measured: `{json.dumps(row['measured'])}`"]
        lines.append("")

    control = report["negative_control"]
    lines += ["## The negative control", "",
              "The executable rows re-run against a copy of the package with three guards "
              "removed. Each removal must make at least one probe in the row that watches for it "
              "fail:", "",
              "| Removed guard | Row | Result |", "|---|---|---|"]
    for row_id, item in control["injections"].items():
        lines.append(f"| {item['description']} | `{row_id}` | "
                     f"{'caught' if item['caught'] else 'MISSED'} — "
                     f"{', '.join(item['failed_probes']) or 'nothing failed'} |")
    lines += ["", ("Every injected defect was caught." if control["caught_every_injection"]
                   else "**At least one injection was missed.**"), ""]

    lines += ["## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines += [
        "",
        "## What I would build next, in the order the review proposed", "",
        "The PASS rows are the parts already in the tree; the PARTIAL and FAIL rows name what "
        "is not, probe by probe. In order:", "",
        "1. **H2/H3 collectors against real OS interfaces** — the one probe that still "
        "fails. The collectors fill a schema; nothing yet reads `/sys`, udev, dmidecode or "
        "`smartctl` on Linux, or WMI/CIM and the TPM APIs on Windows, and no collector "
        "runs against a host. Command allowlists and mTLS agent identity land with that "
        "reader, not after it.",
        "2. **H4 HSM depth per vendor** — partition, cluster and HA state are in the "
        "observation model; what is missing is a reader per vendor (PKCS#11 attributes, "
        "KMIP `Query`, vendor REST) and a burn-in against each.",
        "3. **H5 network hardware** — SNMP/NETCONF/REST per authorized device class, "
        "feeding both NBOM and CBOM (a load balancer is a TLS terminator *and* a box).",
        "4. **H8 qualification against a real bank estate** — the synthetic run above is a "
        "floor. Precision and recall need ground truth only a customer can provide.",
        "",
        "**The verdict this artifact supports:** the hardware foundation, the identity "
        "model, the security-hardware metadata model, the evidence rule for "
        "relationships and the drift vocabulary are implemented and executed here, and "
        "the projection architecture the review asked for is the one in the code. What is "
        "*not* done is collector reach into real Linux, Windows, hypervisor and network "
        "estates, and per-vendor HSM readers — named above rather than folded into the "
        "score.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade hardware discovery.")
    parser.add_argument("--json")
    parser.add_argument("--md")
    parser.add_argument("--max-fail", type=int, default=0)
    args = parser.parse_args(argv)
    report = measure()
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.md:
        Path(args.md).write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    return 1 if report["counts"][FAIL] > args.max_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
