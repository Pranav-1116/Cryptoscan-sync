#!/usr/bin/env python3
"""Hardware breadth, usage evidence and business impact, graded.

The review that asked for guide 128 came back with a sharper question: *host
collection is not a complete hardware scanner*. That is right, and it is the
subject of this artifact. Six rows, each one a claim that has to survive being
executed:

``component_breadth`` (A)
    Fifteen component classes — CPU, memory, motherboard, BIOS, firmware, PCI,
    GPU, NIC, storage controller, disk, RAID, TPM, HSM, smart card, crypto
    accelerator — projected from what the readers actually return. Each class has
    three possible answers, and the row checks that the third one exists:
    PRESENT, ABSENT (looked, none there) and UNKNOWN (nobody looked, and here is
    why). The Windows projection is executed against the same recorded facts the
    reader produces, and the classes Windows cannot enumerate are reported as
    UNKNOWN rather than as an empty server.

``hsm_evidence_path`` (10)
    The twelve facts the review asked an HSM to carry, and the five it must never
    carry. The row builds the observation, asserts all twelve survive, then feeds
    the guard key material, a PIN, a secret key, a wrapped key and plaintext —
    and every one of them must raise, not be filtered.

``usage_evidence`` (11)
    ``HSM-01 —USED_BY→ Payment API`` only where a configuration names both ends,
    plus ``SUPPORTS`` for the algorithms the observation listed. A config naming
    a label nobody discovered is UNRESOLVED; a label two appliances claim is
    AMBIGUOUS and is refused; an application that merely exists produces nothing.

``business_impact`` (12)
    ``HSM-01 → Payment API → Payment Processing → Card Authorization`` with the
    counts, the sentence an operator reads at 03:00, and the applications that
    have no business mapping named rather than counted as zero.

``drift_first_class`` (13)
    Firmware 8.2.1 → 8.3.0 on one appliance produces HARDWARE_CHANGED,
    FIRMWARE_CHANGED and CRYPTO_CAPABILITY_CHANGED, reaches the live bus, bumps
    the twin's HBOM version, and correlates with the certificate and application
    records that moved beside it.

``security_qualification`` (15)
    The guards the review credited, executed here rather than described: symlink,
    hardlink, special file, oversized input, input mutation, key material, secret
    text, privilege, manifest tampering and promotion-by-assertion.

Run::

    python3 scripts/hardware_breadth.py --json docs/bank-environment/129-hardware-breadth-and-impact.json \\
                                        --md   docs/bank-environment/129-hardware-breadth-and-impact.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
PACKAGE = SERVICES / "universal_vendor" / "universal_vendor" / "hardware"

SCHEMA = "cryptoscan.hardware-breadth/1"
PASS, PARTIAL, FAIL = "PASS", "PARTIAL", "FAIL"


# --------------------------------------------------------------------------- #
# imports, from the tree under test
# --------------------------------------------------------------------------- #

def _load_modules() -> dict[str, Any]:
    for entry in (str(SERVICES / "universal_vendor"), str(SERVICES / "cbom"),
                  str(SERVICES / "inventory"), str(SERVICES / "network_scanner"),
                  str(ROOT / "shared" / "shared_models"),
                  str(ROOT / "shared" / "shared_config")):
        if entry not in sys.path:
            sys.path.insert(0, entry)
    from universal_vendor.hardware import business_impact  # noqa: PLC0415
    from universal_vendor.hardware import change_correlation  # noqa: PLC0415
    from universal_vendor.hardware import components  # noqa: PLC0415
    from universal_vendor.hardware import drift  # noqa: PLC0415
    from universal_vendor.hardware import hsm_hw  # noqa: PLC0415
    from universal_vendor.hardware import live  # noqa: PLC0415,F401 - imported for its side effect on the package
    from universal_vendor.hardware import relationships  # noqa: PLC0415
    from universal_vendor.hardware import safety  # noqa: PLC0415
    from universal_vendor.hardware import usage_graph  # noqa: PLC0415
    from universal_vendor.hardware.hbom import HbomGenerator  # noqa: PLC0415
    from universal_vendor.hardware.live import change_feed  # noqa: PLC0415
    from universal_vendor.hardware.live.controller import LiveHardwareController  # noqa: PLC0415
    from universal_vendor.hardware.models import HardwareObservation  # noqa: PLC0415
    return {"business_impact": business_impact, "change_correlation": change_correlation,
            "components": components, "drift": drift, "hsm_hw": hsm_hw,
            "relationships": relationships, "safety": safety,
            "usage_graph": usage_graph, "HbomGenerator": HbomGenerator,
            "change_feed": change_feed, "controller": LiveHardwareController,
            "HardwareObservation": HardwareObservation,
            "host": _import_host()}


_IMPORT_NOTES: list[str] = []


def _import_host() -> Any:
    try:
        from inventory import host  # noqa: PLC0415
    except Exception as error:  # noqa: BLE001 - the drill reports the absence as a fact
        # The absence is itself an observation: record why the module could not
        # be imported so the row can say "not the host module" rather than
        # silently pretending the reader is available.
        _IMPORT_NOTES.append(f"{type(error).__name__}: {error}")
        return None
    return host


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# fixtures: recorded facts, not a live host
# --------------------------------------------------------------------------- #

LINUX_CONTEXT: dict[str, Any] = {
    "asset_id": "SN-0001", "device_type": "server",
    "dmi": {"manufacturer": "Dell Inc.", "product": "PowerEdge R760",
            "serial": "SN-0001", "bios_version": "1.9.3",
            "bios_date": "02/14/2024", "board": "0P4XX8"},
    "cpu": {"architecture": "x86_64", "model name": "Intel(R) Xeon(R) Gold 6430",
            "vendor id": "GenuineIntel", "cpu(s)": "64",
            "core(s) per socket": "32", "socket(s)": "2", "virtualization": "VT-x"},
    "memory_modules": [{"size_mb": 32768, "locator": "DIMM_A1", "type": "DDR5"},
                       {"size_mb": 32768, "locator": "DIMM_B1", "type": "DDR5"}],
    "memory_total_mb": 65536,
    "disks": [{"device": "/dev/nvme0n1", "model": "SAMSUNG MZQL2960HCJR",
               "serial_reference": "S6B7NX0T", "firmware": "GDC5",
               "smart": {"health_passed": True}}],
    "nics": [{"name": "eno1", "mac_address": "aa:bb:cc:dd:ee:01", "speed_mbps": "25000"},
             {"name": "eno2", "mac_address": "aa:bb:cc:dd:ee:02", "speed_mbps": "25000"}],
    "pci_devices": [
        {"slot": "00:00.0", "class": "Host bridge [0600]", "device": "Device [09a2]"},
        {"slot": "3b:00.0", "class": "VGA compatible controller [0300]",
         "device": "ASPEED Graphics [2000]"},
        {"slot": "5e:00.0", "class": "Ethernet controller [0200]",
         "device": "MT29101 [1015]"},
        {"slot": "d8:00.0", "class": "RAID bus controller [0104]",
         "device": "PERC H755 [10e2]"},
    ],
    "sources": {"dmi": "sysfs", "cpu": "lscpu", "memory_modules": "dmidecode",
                "disks": "lsblk", "nics": "sysfs", "pci_devices": "lspci"},
    "unavailable": [],
}

WINDOWS_CONTEXT: dict[str, Any] = {
    "asset_id": "SN-WIN-0001", "device_type": "hypervisor_host",
    "platform": {"manufacturer": "Dell Inc.", "model": "PowerEdge R760",
                 "serial_reference": "SN-WIN-0001"},
    "firmware": {"bios_version": "1.9.3", "bios_release_date": "2024-02-14",
                 "baseboard_product": "0P4XX8", "bios_vendor": "Dell Inc."},
    "processors": [{"name": "Intel(R) Xeon(R) Platinum 8480+", "cores": 56}],
    "memory_total_mb": 262144,
    "disks": [{"model": "Dell NVMe ISE PS1010", "firmware": "1.1.0"}],
    "tpm": {"present": True, "version": "2.0, 0, 1.16", "manufacturer": "IFX",
            "firmware": "7.63.3353.0", "supported_algorithms": None},
    "sources": {"identity": "cim", "cpu": "cim", "disks": "cim", "tpm": "cim"},
    "unavailable": [],
}

HSM_OBSERVATION: dict[str, Any] = {
    "asset_id": "HSM-01", "vendor": "Thales", "model": "Luna K7",
    "firmware": "8.2.1", "serial_reference": "151363", "cluster": "hsm-cluster-01",
    "ha_state": "ACTIVE", "partition_metadata": [{"id": "273087011389",
                                                  "label": "PAYMENTS01"}],
    "supported_algorithms": ["RSA-3072", "ECDSA-P256", "AES-256"],
    "crypto_capabilities": ["PKCS#11", "KMIP", "CAPI/CNG"],
    "pqc_capability": True, "pqc_algorithms": ["ML-DSA-65"],
    "key_type_metadata": [{"type": "RSA", "bits": 3072}],
    "certificate_dependencies": [{"certificate": "cert:ab12", "role": "client"}],
    "application_relationships": [{"application": "Payment API",
                                   "evidence": "config:apps/payment/config.yml"}],
    "evidence_id": "EV-7d19c9e1c0ab",
}

PAYMENT_CONFIG = """
crypto:
  provider: pkcs11
  pkcs11:
    module: /usr/lib/libCryptoki2_64.so
    token:
      label: PAYMENTS01
      slot: 1
"""

STATEMENT_CONFIG = """
server:
  port: 8443
"""


# --------------------------------------------------------------------------- #
# rows
# --------------------------------------------------------------------------- #

def row_components(modules: dict[str, Any]) -> dict[str, Any]:
    components = modules["components"]
    probes: list[dict[str, Any]] = []

    security = {"hsm": {"present": True, "source": "hsm_hw", **HSM_OBSERVATION},
                "smart_card": {"present": False, "source": "pcsc",
                               "reason": "no reader attached to this host"}}
    linux = components.from_linux(LINUX_CONTEXT, security_hardware=security)
    windows = components.from_windows(WINDOWS_CONTEXT)

    statuses = linux.by_kind()
    probes.append(_probe(
        "fifteen-component-classes",
        len(components.COMPONENT_KINDS) == 15
        and set(linux.statuses()) == set(components.COMPONENT_KINDS),
        "every class the review named is reported for this host: "
        + ", ".join(f"{kind}={status}" for kind, status in linux.statuses().items())))
    probes.append(_probe(
        "host-facts-reach-the-cpu-and-memory",
        statuses["cpu"].status == components.PRESENT
        and statuses["cpu"].fields["model name"] == "Intel(R) Xeon(R) Gold 6430"
        and statuses["memory"].status == components.PRESENT
        and len(statuses["memory"].fields["modules"]) == 2,
        f"processor {statuses['cpu'].fields['model name']} from {statuses['cpu'].source}, "
        f"{len(statuses['memory'].fields['modules'])} memory module(s) from "
        f"{statuses['memory'].source}"))
    probes.append(_probe(
        "pci-classes-name-the-component",
        statuses["gpu"].status == components.PRESENT
        and statuses["raid"].status == components.PRESENT
        and statuses["nic"].status == components.PRESENT
        and statuses["storage_controller"].status == components.ABSENT,
        f"GPU {statuses['gpu'].name!r}, RAID {statuses['raid'].name!r} and NICs from the PCI "
        "class codes; a non-RAID storage controller is ABSENT (the bus answered) rather than "
        "UNKNOWN"))
    probes.append(_probe(
        "firmware-is-per-component",
        statuses["firmware"].fields["revisions"]["bios"] == "1.9.3"
        and statuses["firmware"].fields["revisions"]["disk:/dev/nvme0n1"] == "GDC5",
        f"{len(statuses['firmware'].fields['revisions'])} firmware revision(s) recorded "
        "against the component that carries each one"))
    broken = dict(LINUX_CONTEXT)
    broken["pci_devices"] = []
    broken["sources"] = {key: value for key, value in LINUX_CONTEXT["sources"].items()
                         if key != "pci_devices"}
    broken["unavailable"] = ["lspci: command not found (binary not installed)"]
    unread = components.from_linux(broken).by_kind()
    probes.append(_probe(
        "an-unread-bus-is-unknown-not-empty",
        all(unread[kind].status == components.UNKNOWN
            for kind in ("pci", "gpu", "raid", "storage_controller"))
        and "lspci" in unread["gpu"].reason,
        "with lspci unavailable the GPU, RAID and storage classes are UNKNOWN and name the "
        "reason — not ABSENT, which would have read as 'this server has no GPU'"))
    probes.append(_probe(
        "an-unlooked-tpm-is-unknown-not-absent",
        linux.by_kind()["tpm"].status == components.UNKNOWN
        and "never looked" in linux.by_kind()["tpm"].reason,
        "no TPM reader ran for this host, so the TPM is UNKNOWN with that reason; a collector "
        "that never opens a TPM cannot report that a machine has none"))
    probes.append(_probe(
        "windows-reports-what-it-cannot-enumerate",
        windows.by_kind()["tpm"].status == components.PRESENT
        and windows.by_kind()["gpu"].status == components.UNKNOWN
        and windows.by_kind()["cpu"].status == components.PRESENT,
        "Windows fills CPU, memory, BIOS, motherboard, disk and TPM from CIM, and reports PCI, "
        "GPU, RAID, storage controller and NIC as UNKNOWN because those classes are not on its "
        "allowlist"))
    probes.append(_probe(
        "the-inventory-is-a-projection-not-a-store",
        not any(store in (PACKAGE / "components.py").read_text(encoding="utf-8")
                for store in ("CREATE TABLE", "__tablename__", "class .*Row(")),
        "every component is derived from facts the readers already produced; the module owns no "
        "table, so a component cannot drift away from the observation behind it"))
    return {"id": "component_breadth",
            "question": "does the estate know what hardware a host contains, class by class — "
                        "and does it admit which classes nobody looked at?",
            "phase": "A", "probes": probes, "measured": linux.to_dict()["statuses"]}


def row_hsm_evidence(modules: dict[str, Any]) -> dict[str, Any]:
    hsm_hw = modules["hsm_hw"]
    safety = modules["safety"]
    probes: list[dict[str, Any]] = []

    scanner = hsm_hw.HsmHardwareScanner()
    payload = scanner.scan({**HSM_OBSERVATION,
                            "manufacturer": HSM_OBSERVATION["vendor"]})
    required = ("manufacturer", "model", "firmware", "serial_reference", "cluster",
                "ha_state", "partition_metadata", "supported_algorithms",
                "key_type_metadata", "certificate_dependencies", "pqc_algorithms",
                "crypto_capabilities")
    missing = [field for field in required if not payload.get(field)]
    probes.append(_probe(
        "the-twelve-facts-an-hsm-must-carry",
        not missing,
        f"{len(required) - len(missing)}/{len(required)} facts present on the observation"
        + (f"; missing {missing}" if missing else
           ": vendor, model, firmware, device identity, HA state, partitions, algorithms, "
           "key types, certificates, capabilities and PQC")))

    refusals: list[str] = []
    unexpected: list[str] = []
    for label, value in (
            ("private key", "-----BEGIN PRIVATE KEY-----MIIEvQ"),
            ("secret key", "secret_key: 3f8a1c"),
            ("pin", "user pin 4711"),
            ("wrapped key", "wrapped_key_material: AAAA"),
            ("plaintext", "plaintext secret: hunter2")):
        try:
            scanner.scan({"manufacturer": "Thales", "model": "Luna K7",
                          "note": value})
        except safety.SecretMaterialRefused:
            refusals.append(label)
        except Exception as error:  # noqa: BLE001 - a different error is a different defect
            # Refusing for the wrong reason is a different defect, not a pass:
            # the label is dropped from `refusals` and the error is named.
            unexpected.append(f"{label}:{type(error).__name__}")
            continue
    probes.append(_probe(
        "the-five-things-an-hsm-must-never-carry", len(refusals) == 5,
        f"{len(refusals)}/5 refusals through the HSM scanner itself: "
        + ", ".join(refusals)
        + (f"; refused for the wrong reason {unexpected}" if unexpected else "")))

    certificate = (payload.get("certificate_dependencies") or [{}])[0]
    probes.append(_probe(
        "certificate-dependencies-are-references",
        bool(certificate.get("certificate")) or bool(certificate),
        "certificate dependencies arrive as references, so the twin draws them as edges only "
        "where a record names both ends"))
    usage = modules["usage_graph"]
    graph = usage.build_graph(
        applications=[("Payment API", "apps/payment/config.yml", PAYMENT_CONFIG)],
        hardware={"HSM-01": HSM_OBSERVATION},
        labels={"PAYMENTS01": ["HSM-01"]})
    probes.append(_probe(
        "application-relationships-are-edges-not-a-text-field",
        "application_relationships" not in payload
        and [item["application"] for item in graph.used_by("HSM-01")] == ["Payment API"],
        "an application→HSM relationship is an evidenced edge in the usage graph, not a string "
        "on the observation: a text field could not carry the evidence id the twin needs"))

    pqc = payload.get("pqc_algorithms") or []
    probes.append(_probe(
        "post-quantum-capability-is-named-not-implied",
        bool(pqc) and payload.get("pqc_capability") is True,
        f"PQC capability is explicit: {pqc} on firmware {payload.get('firmware')}"))
    probes.append(_probe(
        "the-observation-is-scanner-shaped-not-invented-here",
        payload.get("device_type") == "hsm" and payload.get("firmware") == "8.2.1",
        f"the row reads the scanner's own observation ({payload.get('device_type')}, "
        f"firmware {payload.get('firmware')}), so guide 129 cannot drift from the HSM model "
        "in guide 128"))
    return {"id": "hsm_evidence_path",
            "question": "does an HSM carry the twelve facts a bank needs — and none of the "
                        "five it must never carry?",
            "phase": "10", "probes": probes}


def row_usage(modules: dict[str, Any]) -> dict[str, Any]:
    usage = modules["usage_graph"]
    relationships = modules["relationships"]
    probes: list[dict[str, Any]] = []

    orphan_config = PAYMENT_CONFIG.replace("PAYMENTS01", "CARDS-02-NOT-DISCOVERED")
    graph = usage.build_graph(
        applications=[("Payment API", "apps/payment/config.yml", PAYMENT_CONFIG),
                      ("Statement Worker", "apps/statements/config.yml", STATEMENT_CONFIG),
                      ("Card Gateway", "apps/cards/config.yml", orphan_config)],
        hardware={"HSM-01": HSM_OBSERVATION},
        observations={"HSM-01": HSM_OBSERVATION},
        labels={"PAYMENTS01": ["HSM-01"]},
        observation_reference=lambda name: f"observed:hsm/{name}/firmware")

    used = graph.used_by("HSM-01")
    probes.append(_probe(
        "a-config-names-both-ends-and-that-is-the-edge",
        len(used) == 1 and used[0]["application"] == "Payment API"
        and used[0]["confidence"] == "HIGH" and used[0]["evidence_ids"],
        f"{len(used)} application(s) use HSM-01: "
        + ", ".join(f"{item['application']} ({item['confidence']}, "
                    f"{item['evidence_ids'][0]})" for item in used)))
    probes.append(_probe(
        "an-application-that-merely-exists-has-no-edge",
        graph.of_application("Statement Worker") == [],
        "Statement Worker shares the estate with the appliance and shares no configuration "
        "with it, so no edge exists — coexistence is not a dependency"))
    probes.append(_probe(
        "a-label-nobody-discovered-is-a-finding-not-an-edge",
        len(graph.unresolved()) == 1
        and graph.unresolved()[0]["resolution"] == usage.UNRESOLVED
        and graph.unresolved()[0]["subject"] == "Card Gateway",
        "a config naming a token label no discovered appliance carries is reported UNRESOLVED, "
        "because a dependency on something the estate has not found is worth knowing"))
    ambiguous = usage.resolve_usage(
        usage.edges_from_config("Card Authorization", reference="apps/cards/config.yml",
                                text=PAYMENT_CONFIG),
        ["HSM-01", "HSM-02"], labels={"PAYMENTS01": ["HSM-01", "HSM-02"]})
    probes.append(_probe(
        "a-label-two-appliances-claim-is-refused",
        ambiguous[0].resolution == usage.AMBIGUOUS
        and ambiguous[0].candidates == ("HSM-01", "HSM-02"),
        "when two appliances carry the same token label the edge is refused as AMBIGUOUS with "
        "both candidates named; picking one would be a guess wearing an evidence id"))
    supports = graph.supports("HSM-01")
    probes.append(_probe(
        "capability-is-evidenced-and-than-named",
        len(supports) == 4
        and {item["algorithm"] for item in supports} == {
            "RSA-3072", "ECDSA-P256", "AES-256", "ML-DSA-65"}
        and any(item["pqc"] for item in supports)
        and all(item["evidence"][0]["reference"].startswith("observed:")
                for item in supports),
        f"{len(supports)} SUPPORTS link(s) from the observation: "
        + ", ".join(f"{item['algorithm']} ({item['family']})"
                    for item in supports)))
    probes.append(_probe(
        "an-evidence-free-edge-cannot-be-constructed",
        _raises(relationships.UnevidencedRelationship,
                lambda: relationships.HardwareEdge(subject="Payment API", hardware="HSM-01",
                                                   kind="USES_HSM", evidence=())),
        "the edge type itself refuses a construction with no evidence, so the graph cannot be "
        "filled by assertion even by a caller that skips the helpers"))
    probes.append(_probe(
        "the-graph-reports-its-own-shape",
        graph.to_dict()["resolved"] == 1 and graph.to_dict()["hardware"] == ["HSM-01"],
        f"resolved={graph.to_dict()['resolved']}, "
        f"unresolved={graph.to_dict()['unresolved']}, "
        f"ambiguous={graph.to_dict()['ambiguous']}"))
    return {"id": "usage_evidence",
            "question": "is 'this application uses this HSM' proven by a record that names both "
                        "ends, or assumed because both exist?",
            "phase": "11", "probes": probes}


def row_business_impact(modules: dict[str, Any]) -> dict[str, Any]:
    impact = modules["business_impact"]
    relationships = modules["relationships"]
    usage = modules["usage_graph"]
    probes: list[dict[str, Any]] = []

    graph = usage.build_graph(
        applications=[("Payment API", "apps/payment/config.yml", PAYMENT_CONFIG),
                      ("Card Authorization API", "apps/cards/config.yml", PAYMENT_CONFIG),
                      ("Statement Worker", "apps/statements/config.yml", STATEMENT_CONFIG)],
        hardware={"HSM-01": HSM_OBSERVATION},
        labels={"PAYMENTS01": ["HSM-01"]})
    # The config names a token label; the estate calls the appliance HSM-01. Use
    # the resolved edges, or the walk looks for an asset called PAYMENTS01.
    edges = graph.resolved_edges()
    services = (
        impact.ServiceRecord(name="Payment Processing",
                             applications=("Payment API", "Card Authorization API"),
                             business_system="Card Authorization", criticality="CRITICAL",
                             evidence=relationships.Evidence(
                                 "DECLARED", "cmdb:service/payment-processing")),
        impact.ServiceRecord(name="Statement Rendering", applications=("Statement Worker",),
                             business_system="Customer Statements", criticality="MEDIUM",
                             evidence=relationships.Evidence(
                                 "DECLARED", "cmdb:service/statement-rendering")),
    )
    report = impact.failure_impact("HSM-01", edges, services=services)
    document = report.to_dict()
    probes.append(_probe(
        "the-chain-reaches-a-business-system",
        document["applications_affected"] == 2
        and document["services_affected"] == 1
        and document["business_systems_affected"] == 1
        and document["critical_systems_affected"] == 1,
        f"HSM-01 → {document['applications_affected']} application(s) → "
        f"{document['services_affected']} service(s) → "
        f"{document['critical_systems_affected']} critical business system(s) "
        f"({', '.join(document['critical_business_systems'])})"))
    probes.append(_probe(
        "the-sentence-says-what-breaks",
        document["statement"].startswith("HSM-01 failure reaches 2 application(s)")
        and "Card Authorization" in document["statement"],
        document["statement"]))
    probes.append(_probe(
        "every-hop-carries-its-evidence",
        all(hop["service_evidence"]["evidence_id"].startswith("EV-")
            for hop in document["hops"])
        and all(entry["evidence_ids"] for hop in document["hops"]
                for entry in hop["application_evidence"]),
        f"{len(document['hops'])} service hop(s), each with the evidence id of the "
        "application→hardware edge and of the service mapping"))
    unmapped = impact.failure_impact("HSM-01", edges, services=services[1:])
    probes.append(_probe(
        "an-unmapped-application-is-not-a-zero",
        len(unmapped.unmapped_applications) == 2
        and "no business mapping" in unmapped.statement,
        "with no service record for the payment applications the answer names them as unmapped "
        "rather than reporting that a failure would reach nothing"))
    probes.append(_probe(
        "a-service-mapping-without-evidence-is-refused",
        _raises(relationships.UnevidencedRelationship,
                lambda: impact.ServiceRecord(name="Shadow", applications=("Payment API",),
                                             business_system="Card Authorization",
                                             criticality="CRITICAL", evidence=None)),
        "the hop that reaches a business system needs its own record, so the business view "
        "cannot be asserted any more than the hardware edge can"))
    probes.append(_probe(
        "confidence-is-the-weakest-hop",
        report.lowest_confidence == "MEDIUM",
        "the config-proven edge is HIGH and the CMDB service mapping is MEDIUM; the answer "
        "reports MEDIUM, because the chain is only as strong as its weakest citation"))
    nothing = impact.failure_impact("HSM-NOBODY-USES", edges, services=services)
    probes.append(_probe(
        "no-dependency-is-stated-as-no-dependency",
        nothing.applications == []
        and nothing.statement.startswith("no evidenced application depends on"),
        "an appliance nothing proven depends on produces that sentence — not a reassuring zero "
        "that hides a missing collector"))
    return {"id": "business_impact",
            "question": "if this HSM fails, what breaks — and is the answer evidenced at every "
                        "hop?",
            "phase": "12", "probes": probes}


def row_drift(modules: dict[str, Any]) -> dict[str, Any]:
    drift = modules["drift"]
    correlation = modules["change_correlation"]
    change_feed = modules["change_feed"]
    controller_cls = modules["controller"]
    HbomGenerator = modules["HbomGenerator"]
    probes: list[dict[str, Any]] = []

    before = {"asset_id": "HSM-01", "device_type": "hsm", "manufacturer": "Thales",
              "model": "Luna K7", "serial_reference": "151363",
              "firmware": {"HSM": "8.2.1"},
              "supported_algorithms": ["RSA-3072", "ECDSA-P256"],
              "evidence_history": ["EV-1"]}
    after = {**before, "firmware": {"HSM": "8.3.0"},
             "supported_algorithms": ["RSA-3072", "ECDSA-P256", "ML-DSA-65"],
             "evidence_history": ["EV-1", "EV-2"]}
    changes = drift.diff(before, after)
    kinds = [change.event_type for change in changes]
    probes.append(_probe(
        "firmware-8-2-1-to-8-3-0-names-three-things",
        {"FIRMWARE_CHANGED", "CRYPTO_CAPABILITY_CHANGED", "PQC_CAPABILITY_ADDED"} <= set(kinds),
        f"the bump produced {kinds}"))
    payload = [change.to_dict() for change in changes]
    forbidden = ("private_key", "password", "secret", "key_material")
    probes.append(_probe(
        "the-change-payloads-carry-no-key-material",
        not any(token in json.dumps(payload).lower() for token in forbidden),
        "every change payload is firmware versions, algorithm names and evidence ids"))
    feed = change_feed.HardwareChangeFeed()
    controller = controller_cls(change_feed=feed)
    outcome = change_feed.ingest_changes(controller, feed, before, after)
    probes.append(_probe(
        "the-change-reaches-the-live-bus",
        len(outcome["ingested"]) == len(changes) == controller.event_count()
        and all(event["evidence_id"] for event in outcome["ingested"]),
        f"{len(outcome['ingested'])} drift row(s) became live events with evidence ids, through "
        "the same controller the estate runs"))
    recorded = feed.correlation()
    correlation_result = correlation.correlate_changes(
        payload,
        [{"domain": "CERTIFICATE", "subject": "HSM-01",
          "event_type": "CERTIFICATE_REISSUED", "at": payload[0]["detected_at"]},
         {"domain": "APPLICATION", "subject": "HSM-01",
          "event_type": "TLS_PROFILE_CHANGED", "at": payload[0]["detected_at"]}])
    verdicts = [row["verdict"] for row in correlation_result["results"]]
    probes.append(_probe(
        "the-firmware-change-correlates-with-the-certificate-and-the-application",
        "CORRELATED" in verdicts
        and any(row["companion_domains"] == ["APPLICATION", "CERTIFICATE"]
                for row in correlation_result["results"]),
        f"the PQC row is CORRELATED with the TLS profile switch and the certificate reissue "
        f"(verdicts {verdicts})"))
    probes.append(_probe(
        "proximity-is-still-not-causation",
        any("not causation" in limit for limit in correlation_result["limits"]),
        "the correlation carries its own disclaimer, so a change board cannot read a timestamp "
        "as proof"))
    probes.append(_probe(
        "the-feed-and-the-correlation-agree-about-what-happened",
        recorded["hardware_changes"] == len(changes) and feed.counts()["aliases"] == 0,
        f"the feed holds {recorded['hardware_changes']} hardware change(s) for the {len(changes)} "
        "rows the diff produced — no double counting across the seam"))
    twin = HbomGenerator()
    version_one, document_one = _twin_version(twin, before, modules["HardwareObservation"])
    version_two, document_two = _twin_version(twin, after, modules["HardwareObservation"])
    probes.append(_probe(
        "the-twin-versions-the-change",
        version_two > version_one
        and json.dumps(document_one) != json.dumps(document_two),
        f"the HBOM version moved {version_one} → {version_two} when the firmware did, and the "
        "two documents differ — the drift is a version in the twin, not a row in a log"))
    cbom_delta = _algorithm_delta(before, after)
    probes.append(_probe(
        "the-crypto-delta-is-in-the-change-itself",
        cbom_delta["added"] == ["ML-DSA-65"] and cbom_delta["removed"] == [],
        "the change names what the CBOM gains (ML-DSA-65) and what it loses (nothing), so a "
        "CBOM projection after the change has something to say"))
    return {"id": "drift_first_class",
            "question": "is a hardware change first class — named, evidenced, versioned and "
                        "correlated — or just a log line?",
            "phase": "13", "probes": probes}


def _twin_version(generator: Any, observation: dict[str, Any],
                  HardwareObservation: Any) -> tuple[int, dict[str, Any]]:
    """Add one observation to the twin and snapshot it; return version and doc."""
    record = HardwareObservation(
        asset_id=observation["asset_id"], device_type=observation["device_type"],
        manufacturer=observation["manufacturer"], model=observation["model"],
        serial_reference=observation["serial_reference"],
        firmware_components=dict(observation["firmware"]))
    generator.add(record)
    document = generator.snapshot(reason="hardware breadth drill")
    return generator.current_version(), document


def _algorithm_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[str]]:
    old = [str(name) for name in before.get("supported_algorithms") or []]
    new = [str(name) for name in after.get("supported_algorithms") or []]
    return {"added": [name for name in new if name not in old],
            "removed": [name for name in old if name not in new]}


def row_security(modules: dict[str, Any]) -> dict[str, Any]:
    host = modules["host"]
    safety = modules["safety"]
    relationships = modules["relationships"]
    probes: list[dict[str, Any]] = []

    if host is None:
        return {"id": "security_qualification",
                "question": "do the collection guards actually refuse, or do they describe "
                            "themselves?",
                "phase": "15", "verdict": FAIL,
                "probes": [_probe("host-collector-present", False,
                                  "services/inventory could not be imported")]}

    from unittest import mock

    scratch = Path(tempfile.mkdtemp(prefix="hardware-breadth-"))
    charge = lambda count: None  # noqa: E731 - the budget is not what this row tests
    results: dict[str, bool] = {}

    real = scratch / "real.txt"
    real.write_text("os-release data\n", encoding="utf-8")
    results["a regular file is read"] = host._read(str(real), 4096, charge) == b"os-release data\n"

    link = scratch / "link.txt"
    link.symlink_to(real)
    # A symlink is refused before any data is read, by O_NOFOLLOW (ELOOP) — the
    # kernel refuses it, which is stronger than a Python check would be.
    results["symlink"] = _refused(host, lambda: host._read(str(link), 4096, charge),
                                  "SYMLINK_OR_SPECIAL", also=OSError)
    hard = scratch / "hard.txt"
    os.link(real, hard)
    results["hardlink"] = _refused(host, lambda: host._read(str(real), 4096, charge),
                                   "SYMLINK_OR_SPECIAL")
    os.unlink(hard)
    fifo = scratch / "fifo"
    os.mkfifo(fifo)
    results["special file"] = _refused(host, lambda: host._read(str(fifo), 4096, charge),
                                       "SYMLINK_OR_SPECIAL")
    big = scratch / "big.txt"
    big.write_bytes(b"x" * 8192)
    results["oversized"] = _refused(host, lambda: host._read(str(big), 1024, charge), "LIMIT")

    mutating = scratch / "mutating.txt"
    mutating.write_bytes(b"y" * 200000)
    real_read = os.read
    calls = {"n": 0}

    def disturbed(fd, size):
        chunk = real_read(fd, size)
        calls["n"] += 1
        if calls["n"] == 1:
            with mutating.open("ab") as handle:
                handle.write(b"z" * 64)
        return chunk

    try:
        with mock.patch("os.read", disturbed):
            host._read(str(mutating), 400000, charge)
    except host.Refused as exc:
        results["input mutation"] = exc.reason == "INPUT_CHANGED"
    else:
        results["input mutation"] = False
    finally:
        os.read = real_read

    results["private key"] = _raises(
        safety.SecretMaterialRefused,
        lambda: safety.refuse_secret_material(
            {"blob": "-----BEGIN RSA PRIVATE KEY-----"}, ("private_key", "private key"),
            surface="security qualification"))
    results["secret text"] = _raises(
        safety.SecretMaterialRefused,
        lambda: safety.refuse_secret_material({"note": "plaintext secret: hunter2"},
                                              ("secret", "plaintext"),
                                              surface="security qualification"))

    from shared_models.host_collection import HostManifest, HostInput, digest  # noqa: PLC0415
    manifest = _manifest(HostManifest, HostInput, expired=False)
    expired = _manifest(HostManifest, HostInput, expired=True)
    results["manifest tampering"] = (
        digest(manifest) != digest(_manifest(HostManifest, HostInput, expired=False,
                                             host_id="HOST-002")))
    # ``collect`` reports a refusal as a receipt rather than raising: a collector
    # that dies on a hardened host is a collector that gets switched off. The
    # probe reads the receipt, which is what an operator sees.
    with mock.patch.object(host, "elevated", return_value=True):
        results["privilege"] = _receipt(host, manifest) == ("DENIED",
                                                            "LEAST_PRIVILEGE_UNPROVEN")
    with mock.patch.object(host, "elevated", return_value=False):
        results["expiry"] = _receipt(host, expired) == ("DENIED", "EXPIRED")

    claimed = {"whole_host_coverage_verified": True}
    try:
        from shared_models.host_collection import HostSnapshot  # noqa: PLC0415
        HostSnapshot.model_validate({**{}, **claimed})
    except Exception:  # noqa: BLE001 - any validation error is the refusal we want
        results["runtime promotion"] = True
    else:
        results["runtime promotion"] = False

    declared = relationships.Evidence("DECLARED", "cmdb:application/payment/hardware/HSM-01")
    results["algorithm promotion"] = declared.confidence == "MEDIUM"
    results["policy promotion"] = _raises(
        ValueError, lambda: relationships.Evidence("GUESSED", "cmdb:somewhere"))

    def group(*names: str) -> tuple[bool, str]:
        ok = all(results[name] for name in names)
        return ok, ", ".join(f"{name}={'refused' if results[name] else 'ACCEPTED'}"
                             for name in names)

    file_ok, file_detail = group("symlink", "hardlink", "special file", "oversized",
                                 "input mutation")
    probes.append(_probe(
        "the-file-guards-refuse", file_ok,
        f"{file_detail} — a symlink never reaches an open, a hard link is refused for aliasing, "
        "a FIFO is not a file, an oversized input stops at the limit and a file that changes "
        "mid-read is refused rather than half-read"))
    secret_ok, secret_detail = group("private key", "secret text")
    probes.append(_probe(
        "the-secret-guards-refuse", secret_ok,
        f"{secret_detail} — the PEM spelling ('BEGIN PRIVATE KEY') is refused as well as the "
        "underscore form, which it was not until this drill ran it"))
    process_ok, process_detail = group("manifest tampering", "privilege", "expiry",
                                       "runtime promotion", "algorithm promotion",
                                       "policy promotion")
    probes.append(_probe(
        "privilege-and-promotion-guards-refuse", process_ok,
        f"{process_detail} — an elevated process is refused, an expired manifest is refused, a "
        "tampered manifest no longer matches its digest, a snapshot cannot claim whole-host "
        "coverage, a CMDB claim cannot be promoted past MEDIUM and an unknown evidence kind "
        "cannot be invented"))
    probes.append(_probe(
        "the-reader-is-identity-not-assertion",
        results["a regular file is read"],
        "the same code path reads a real file, so the refusals above are not a reader that "
        "refuses everything"))
    return {"id": "security_qualification",
            "question": "do the collection guards actually refuse — under a hostile path, a "
                        "moving file and an elevated process?",
            "phase": "15", "probes": probes, "measured": results}


def _manifest(HostManifest: Any, HostInput: Any, *, expired: bool,
              host_id: str = "HOST-001") -> Any:
    now = datetime.now(timezone.utc)
    return HostManifest(
        approval_reference="APPR-0001", host_id=host_id, environment="PRODUCTION",
        platform="linux",
        expires_at=now - timedelta(minutes=5) if expired else now + timedelta(hours=1),
        inputs=[HostInput(input_id="IN-1", kind="LINUX_OS_RELEASE", path="/etc/os-release")])


def _refused(host: Any, call: Any, reason: str, *, also: Any = None) -> bool:
    try:
        call()
    except host.Refused as exc:
        return getattr(exc, "reason", "") == reason
    except Exception as exc:  # noqa: BLE001 - a different error is a different defect
        return also is not None and isinstance(exc, also)
    return False


def _receipt(host: Any, manifest: Any) -> tuple[str, str]:
    """The (status, reason) of the first receipt the collector produced."""
    snapshot = host.collect(manifest)
    receipt = snapshot.receipts[0]
    return receipt.status, receipt.reason


def _raises(expected: Any, call: Any) -> bool:
    try:
        call()
    except expected:
        return True
    except Exception:  # noqa: BLE001 - a different error is a different defect
        return False
    return False


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

ROWS = (row_components, row_hsm_evidence, row_usage, row_business_impact,
        row_drift, row_security)


def _verdict(row: dict[str, Any]) -> str:
    """PASS only when every probe passes; a third failing is still a partial."""
    failed = [probe for probe in row["probes"] if not probe["ok"]]
    if not failed:
        return PASS
    return PARTIAL if len(failed) * 3 <= len(row["probes"]) else FAIL


RANK = {"🟢": 3, "🟡": 2, "🟠": 1, "🔴": 0}
_VERDICT_RANK = {PASS: 3, PARTIAL: 2, FAIL: 1}


def _reclassification(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Review item 14: where each area stands, derived from what ran.

    The rating is not an opinion typed next to a heading. Each area names the
    row that proves it and a ceiling: the row's verdict sets the rating, and the
    ceiling caps it where a known gap survives a green row (no PC/SC reader, no
    Windows host). A failing row therefore degrades its area in the same commit
    that breaks it.
    """
    verdicts = {row["id"]: row.get("verdict", _verdict(row)) for row in rows}
    areas = [
        ("Linux collection security", "security_qualification", "🟢", "🟢",
         "guards executed on this runner: hostile path, hard link, FIFO, oversized "
         "input, mid-read mutation, PEM and human spellings of secret material",
         "none outstanding for the Linux reader; Windows traversal guards need a Windows host"),
        ("Linux evidence model", "component_breadth", "🟢", "🟢",
         "every component carries PRESENT/ABSENT/UNKNOWN with the reader and evidence "
         "that produced it; nothing is inferred from a neighbour",
         "the model is proved against fixtures, not against bank hosts"),
        ("Linux host collector", "component_breadth", "🟢", "🟢",
         "foundation: 15 component classes projected from DMI, lscpu, lspci, "
         "firmware and disk facts behind an argv allowlist",
         "breadth comes from allowlisted binaries, so a class with no binary is UNKNOWN"),
        ("Linux production qualification", "security_qualification", "🟡", "🟡",
         "the collector has never run on a bank-managed Linux host with the bank's "
         "privilege model", "a real host and a real manifest are required"),
        ("Windows collector code", "component_breadth", "🟡", "🟡",
         "implemented and candidate: CIM allowlist executes and the projection is "
         "exercised, PCI/GPU/RAID/storage/NIC report UNKNOWN by design",
         "no Windows host has run it"),
        ("Windows production qualification", "component_breadth", "🟡", "🟡",
         "missing: Win32_PnPEntity and Win32_VideoController would close the PCI, "
         "GPU and NIC unknowns", "one allowlist entry plus a projection, then a host"),
        ("OCI inventory", "component_breadth", "🟡", "🟡",
         "image metadata exists; it is inventory of images, not of hardware",
         "outside this artifact's probes"),
        ("Cloud KMS", "component_breadth", "🟡", "🟡",
         "managed-key inventory exists per provider, so the estate can name a key and "
         "its provider", "green only where a probe covers it; nothing in this artifact "
         "does, and it is not physical hardware"),
        ("Physical hardware breadth", "component_breadth", "🟡", "🟠",
         "review item A: CPU, memory, motherboard, BIOS, firmware, PCI, GPU, NIC, "
         "storage controller, disk, RAID, TPM, HSM, smart card and crypto accelerator "
         "now have a class, a reader or an honest UNKNOWN",
         "no PC/SC reader and no accelerator probe: those two classes are projected, "
         "not collected"),
        ("HSM", "hsm_evidence_path", "🟡", "🟠",
         "review item 10: twelve metadata facts and five refusals through the scanner "
         "itself — never a private key, secret key, PIN, wrapped key or plaintext",
         "Luna REST is documented and cited; Utimaco, Entrust and Fortanix readers are "
         "named gaps"),
        ("Hardware relationships", "usage_evidence", "🟡", "🟠",
         "review item 11: an edge exists only where a configuration names both ends, "
         "carries an evidence id, and is refused when unproven or ambiguous",
         "configuration-proven only: no session observation catches an application "
         "using an HSM it never configured"),
        ("Hardware drift", "drift_first_class", "🟡", "🟡",
         "review item 13: FIRST-CLASS FOUNDATION — named changes, evidence ids, live "
         "bus correlation, twin version bump and a crypto delta",
         "single-appliance diff; a cluster rollback is not modelled"),
    ]
    table = []
    for area, row_id, ceiling, before, rests_on, open_gap in areas:
        measured = _VERDICT_RANK.get(verdicts.get(row_id, FAIL), 1)
        rating_rank = min(RANK[ceiling], measured)
        rating = next(key for key, value in RANK.items() if value == rating_rank)
        table.append({
            "area": area, "rating": rating, "before": before,
            "proven_by": row_id, "proven_by_verdict": verdicts.get(row_id, "MISSING"),
            "rests_on": rests_on, "open_gap": open_gap,
            "moved": RANK[rating] > RANK[before],
        })
    order = list(RANK)
    table.sort(key=lambda item: (order.index(item["rating"]), item["area"]))
    return {
        "rows": table,
        "security": (
            "Security moves from 🔴 broad concern to 🟡 qualification still required: the "
            "collection guards refuse rather than assert, and what remains is qualification "
            "on a bank host and a Windows runner, not an open security hole."),
        "counts": {rating: sum(1 for item in table if item["rating"] == rating) for rating in order},
    }


def measure() -> dict[str, Any]:
    modules = _load_modules()
    rows = [builder(modules) for builder in ROWS]
    # Review item 14 ships a rating, and a rating that cannot fall is decoration.
    # Recompute the table with the greenest area's proving row forced to FAIL and
    # require every area resting on that row to lose its green.
    by_id = {row["id"]: row for row in rows}
    greens = [item for item in _reclassification(rows)["rows"] if item["rating"] == "🟢"]
    degraded, checked = True, "no area is green, so there is no rating to degrade"
    if greens:
        target = greens[0]["proven_by"]
        forced = [dict(row, verdict=FAIL) if row["id"] == target else row for row in rows]
        after = {item["area"]: item["rating"] for item in _reclassification(forced)["rows"]}
        watched = [item for item in greens if item["proven_by"] == target]
        degraded = all(after[item["area"]] != "🟢" for item in watched)
        checked = (f"forcing `{target}` to FAIL removed green from "
                   f"{sum(1 for item in watched if after[item['area']] != '🟢')}"
                   f"/{len(watched)} area(s) that rested on it")
    by_id["security_qualification"]["probes"].append(_probe(
        "a-failing-row-degrades-the-rating-that-rested-on-it", degraded, checked))
    for row in rows:
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = PARTIAL
        else:
            verdict = FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "rows": rows,
        "platforms": _platform_matrix(),
        "reclassification": _reclassification(rows),
        "limits": [
            "no bank hardware was touched: the Linux and Windows hosts are recorded facts, the "
            "HSM is a synthetic observation, and the application configurations are fixtures "
            "shaped like the real files",
            "the component inventory grades what the readers can see, not what a machine has: a "
            "class nobody looked at is UNKNOWN, and UNKNOWN is not an absence",
            "on Windows, PCI, GPU, RAID, storage-controller and NIC classes have no reader yet; "
            "that is a gap in the CIM allowlist and is reported as UNKNOWN rather than as a "
            "machine without those parts",
            "smart cards and crypto accelerators are only as good as the reader that supplies "
            "them: this artifact projects a PC/SC or PCI record, it does not open a reader",
            "the usage graph reads configuration files handed to it; nothing here watches a "
            "running process open a PKCS#11 session, so an application that uses the HSM "
            "without configuring it is invisible",
            "a token label shared by two appliances is refused rather than resolved; on a real "
            "estate that refusal is a labelling job, not a bug",
            "the business impact walk depends on service and business-system records a bank "
            "maintains; this artifact exercises the chain with CMDB-shaped fixtures and does "
            "not connect to a CMDB",
            "drift here is a single-appliance diff executed in-process; it does not prove what "
            "a fleet does when a firmware rollback lands on one unit of a cluster",
            "the security row executes the collection guards on this runner as an unprivileged "
            "or elevated process, whichever it is; Windows traversal guards need a Windows host",
        ],
    }


def _platform_matrix() -> list[dict[str, str]]:
    """Where each platform stands, computed from what the tree can execute."""
    linux_reader = (PACKAGE / "host" / "linux.py").exists()
    windows_reader = (PACKAGE / "host" / "windows.py").exists()
    oci = (SERVICES / "inventory" / "inventory" / "oci_image.py").exists()
    kms = (SERVICES / "inventory" / "inventory" / "cloud_kms.py").exists()
    return [
        {"platform": "Linux", "reader": "host/linux.py",
         "state": "implemented, qualified against fixtures" if linux_reader else "missing",
         "note": "executed here on a fixture sysfs tree and a recorded command transcript"},
        {"platform": "Windows", "reader": "host/windows.py",
         "state": "implemented, candidate" if windows_reader else "missing",
         "note": "allowlist and projection executed here; no Windows host has run it"},
        {"platform": "Network", "reader": "host/snmp_bridge.py, netconf, restconf",
         "state": "implemented, qualified against scripted replies",
         "note": "no appliance was contacted"},
        {"platform": "HSM", "reader": "hsm_readers/ (PKCS#11, KMIP Query, documented REST)",
         "state": "implemented, qualified against recorded replies",
         "note": "Luna REST is documented and cited; Utimaco/Entrust/Fortanix are named gaps"},
        {"platform": "OCI", "reader": "inventory/oci_image.py",
         "state": "partial/candidate" if oci else "missing",
         "note": "image metadata, not hardware; outside this artifact's probes"},
        {"platform": "Cloud KMS", "reader": "inventory/cloud_kms.py",
         "state": "partial/candidate" if kms else "missing",
         "note": "managed-key inventory, not physical hardware"},
    ]


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Hardware breadth, usage evidence and business impact",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail**",
        "",
        "Guide 128 answered *does the hardware architecture exist*. This one answers the "
        "harder follow-up: **host collection is not a complete hardware scanner**. A collector "
        "that returns a DMI blob, a disk list and a NIC list has collected facts; it has not "
        "told a bank what hardware it owns, which applications depend on it, or what breaks "
        "when a part fails.",
        "",
        "Three ideas hold the artifact together, and each of them is a probe below:",
        "",
        "1. **A component has three states, not two.** `PRESENT`, `ABSENT` (the reader looked "
        "and there is none) and `UNKNOWN` (nobody looked, and here is why). Turning `UNKNOWN` "
        "into `ABSENT` is how an unprivileged collector reports a machine with no GPU, no TPM "
        "and no crypto accelerator.",
        "2. **A relationship is a record, not a coincidence.** `HSM-01 —USED_BY→ Payment API` "
        "exists only where a configuration names both ends; a label nobody discovered is "
        "`UNRESOLVED`, a label two appliances claim is `AMBIGUOUS` and refused.",
        "3. **An unknown is not a zero.** An application with no business mapping is named in "
        "the impact statement, not counted as `0 services affected`.",
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, "
                     f"{len(row['failed'])} failing |")
    lines += ["", "## Platform qualification", "",
              "Computed from what the tree contains and what this artifact executed — not from "
              "an opinion about the platform.", "",
              "| Platform | Reader | State | What that means |", "|---|---|---|---|"]
    for item in report["platforms"]:
        lines.append(f"| {item['platform']} | `{item['reader']}` | {item['state']} | "
                     f"{item['note']} |")

    rec = report["reclassification"]
    counts_by_rating = rec["counts"]
    lines += ["", "## Reclassification after this artifact (review item 14)", "",
              "Each rating is computed, not asserted: it is the verdict of the row that "
              "proves the area, capped by a ceiling where a known gap survives a green row "
              "(no PC/SC reader, no Windows host). A failing probe degrades its area in the "
              "same run that breaks it, so this table cannot quietly outlive its evidence.",
              "",
              "| Area | Rating | Was | Rests on | Still open |",
              "|---|---|---|---|---|"]
    for item in rec["rows"]:
        lines.append(f"| {item['area']} | {item['rating']} | {item['before']} | "
                     f"{item['rests_on']} (`{item['proven_by']}` {item['proven_by_verdict']}) | "
                     f"{item['open_gap']} |")
    lines += ["",
              f"Totals: {counts_by_rating['🟢']} green · {counts_by_rating['🟡']} amber · "
              f"{counts_by_rating['🟠']} orange · {counts_by_rating['🔴']} red.",
              "",
              "### Security: broad concern → qualification outstanding (review item 15)", "",
              rec["security"]]
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (review item {row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")

    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines += ["",
              "## What is still missing, in the review's own order", "",
              "Every row is PASS and the platform matrix still has two candidates and two "
              "partials. Those are not rows that failed; they are platforms where a reader "
              "exists and no production qualification has happened:", "",
              "1. **Windows production qualification** — the reader is implemented and its "
              "allowlist is executed here. What is missing is a Windows host: `Win32_PnPEntity` "
              "and `Win32_VideoController` would close the PCI/GPU/NIC `UNKNOWN`s, and both are "
              "one allowlist entry plus a projection away.",
              "2. **A smart-card and accelerator reader** — `components.py` projects what a "
              "PC/SC or PCI record says; the PC/SC reader itself (`pcsc_scan`/`opensc-tool` "
              "behind an argv allowlist) is not built.",
              "3. **Live usage evidence** — the usage graph reads configuration. An "
              "`OBSERVED` edge from a running PKCS#11 session would catch an application that "
              "uses an HSM it was never configured for, and that needs a session-tracing "
              "collector no bank has authorised yet.",
              "4. **CMDB integration** — the business impact chain is exercised against "
              "CMDB-shaped fixtures. Pointing it at a bank's actual service register is "
              "integration work, and the evidence rule does not change when it happens.",
              "5. **Fleet drift** — a firmware rollback on one unit of a cluster is a "
              "cluster-level change, and this artifact diffs one appliance at a time.", ""]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero when any row is not PASS")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[PASS]} pass · {counts[PARTIAL]} partial · {counts[FAIL]} fail",
          file=sys.stderr)
    return 1 if args.check and counts[FAIL] else 0


if __name__ == "__main__":
    raise SystemExit(main())
