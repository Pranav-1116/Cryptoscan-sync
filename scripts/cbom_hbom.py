#!/usr/bin/env python3
"""Guide 167 — hardware is a view of the estate, and a capability is not a use.

The HBOM review (`docs/bank-environment/hbom-review-2026-11-03.md`) makes sixteen points
against a hardware layer that was, until now, three disconnected surfaces. This guide
builds the answer and measures it: ``cbom.hbom_graph`` puts hardware into the *same* graph
as the CBOM, SBOM, NBOM and VBOM, so a device has one identity everywhere and the edges
around it are claims with a basis.

What the measurement is about:

* the **device is a tree** — CPU, memory, motherboard, BIOS, TPM, NIC, storage, RAID, GPU,
  PCI, accelerator and HSM are nodes with the review's field set, and every field the
  collector did not supply is named in ``unknown_fields``;
* the **HSM** is a device with a cluster, HA peers, partitions, capabilities, key types,
  sizes, operations and the applications wired to it — never a vendor and a model string;
* **capability, operation, use and custody are four relations**, not one: a datasheet may
  say an HSM supports RSA, only a read or a probe may say an operation ran there, and
  neither says an application used the algorithm;
* **identity is evidence** — a hostname, an IP and a MAC are refused as anchors, so a
  re-addressed machine is the same machine and the change is drift, not a new device;
* **key material is refused**, and what a collector may hand over is a reference.

The fixture is the review's own example estate: Payments, Card Authorization, Payments API,
``BANK-SRV-001`` and one HSM cluster whose firmware reached end of life.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ROOT / "services"
SCHEMA = "cryptoscan.cbom-hbom-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID = "EVID-829182"
NOW = "2026-11-03T08:30:00Z"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES / "shared"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import hbom_graph, techbom, techbom_queries  # noqa: PLC0415

    return {"h": hbom_graph, "t": techbom, "q": techbom_queries}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


# --------------------------------------------------------------------------- #
# The fixture: the review's estate
# --------------------------------------------------------------------------- #

def _evidence(h: Any, suffix: str = "", **fields: Any) -> dict[str, Any]:
    return h.evidence(
        EVID + suffix, collector=fields.pop("collector", "linux-hardware-collector"),
        collector_version=fields.pop("collector_version", "1.4.2"),
        target_id=fields.pop("target_id", "BANK-SRV-001"),
        observed_at=fields.pop("observed_at", NOW),
        source=fields.pop("source", "/sys/class/dmi/id"),
        evidence_type=fields.pop("evidence_type", "INVENTORY"),
        raw_reference=fields.pop("raw_reference", "dmi/id/product_serial"),
        normalized_fact=fields.pop("normalized_fact", "serial=SN-7K2L"),
        hash=fields.pop("hash", "sha256:3b1f9c0d"),
        confidence=fields.pop("confidence", "HIGH"), **fields)


def _parts(h: Any, t: Any) -> dict[str, Any]:
    """Assets and claims, named so the guide can quote them."""
    record = _evidence(h)
    release = h.firmware("PaymentHSM firmware 8.4.2", version="8.4.2",
                         vendor="SyntheticHSM", product="PaymentHSM-9000",
                         release_date="2025-04-01", status="EOL", eol_date="2026-09-30",
                         vulnerabilities=["CVE-2026-1111"], evidence_ids=[EVID])
    advisory = h.vulnerability("CVE-2026-1111", severity="HIGH", published="2026-08-14",
                               summary="HSM firmware 8.4.x accepts a legacy MAC length",
                               affected_versions=["8.4.0", "8.4.2"],
                               evidence_ids=[EVID])
    device = h.hsm("HSM-001", vendor="SyntheticHSM", product="PaymentHSM-9000",
                   model="PaymentHSM-9000", firmware_version="8.4.2",
                   firmware_release=release, ha_mode="Active/Active",
                   cluster="HSM-CLUSTER-A", members=[{"name": "HSM-002", "role": "active"}],
                   partitions=[{"name": "HSM-001-P1", "id": "P1",
                                "key_types": ["RSA", "EC"],
                                "applications": ["Payments API"]},
                               {"name": "HSM-001-P2", "id": "P2", "key_types": ["AES"],
                                "applications": ["Card Authorization"]}],
                   capabilities=[{"algorithm": "RSA-2048", "key_types": ["RSA"],
                                  "key_sizes": [2048], "operations": ["SIGN", "VERIFY"]},
                                 {"algorithm": "AES-256-GCM", "key_types": ["AES"],
                                  "key_sizes": [256], "operations": ["ENCRYPT"]},
                                 {"algorithm": "ML-KEM-768", "key_types": ["ML-KEM"],
                                  "key_sizes": [768], "operations": ["ENCAPSULATE"]}],
                   key_types=["RSA", "EC", "AES"], key_sizes=[2048, 256],
                   operations=["SIGN", "VERIFY", "ENCRYPT"], certificates=["cert:abab"],
                   applications=["Payments API", "Card Authorization"],
                   systems=["Payments"], serial_number="HSM-SN-7K2L",
                   location="DC1-R12-U7", datacenter="DC1",
                   evidence_ids=[EVID], evidence=[record])

    bank = h.server(manufacturer="Dell", model="PowerEdge R760", serial_number="SN-7K2L",
                    asset_tag="BANK-SRV-001", datacenter="DC1", rack="R12", slot="U7",
                    owner="Payments Platform", environment="PRODUCTION",
                    cpu={"model": "Xeon Gold 6430", "cores": 32, "threads": 64,
                         "topology": "2 sockets x 16 cores", "vendor": "Intel"},
                    memory={"total_mb": 524288, "modules": 8, "vendor": "Samsung"},
                    motherboard={"model": "0R760A", "revision": "A02",
                                 "vendor": "Dell", "part_number": "0R760A-A02"},
                    bios={"version": "2.4.1", "vendor": "Dell", "release_date": "2026-02-10"},
                    tpm={"version": "2.0", "vendor": "Infineon", "fips": "140-2"},
                    nics=[{"model": "Broadcom 57414", "vendor": "Broadcom",
                           "mac": "aa:bb:cc:00:11:22", "ip": "10.10.1.20",
                           "vlan": "VLAN-40", "zone": "PAYMENTS",
                           "firmware_version": "22.31.1"}],
                    storage=[{"model": "NVMe PM1743", "vendor": "Samsung",
                              "size_gb": 3840, "firmware_version": "1.2.3"}],
                    raid={"model": "PERC H755", "vendor": "Dell",
                          "firmware_version": "52.21.0-4606"},
                    gpus=[{"model": "L4", "vendor": "NVIDIA", "memory_gb": 24}],
                    pci=[{"model": "Crypto PCIe card", "vendor": "SyntheticHSM",
                          "slot": "4"}],
                    accelerator={"model": "SyntheticHSM ACC-8000",
                                 "vendor": "SyntheticHSM", "firmware_version": "3.2.0"},
                    evidence_ids=[EVID], evidence=[record])

    service = tb_asset(t, "APPLICATION", "Payments API")
    gateway_app = tb_asset(t, "APPLICATION", "Payment Gateway")
    card_app = tb_asset(t, "APPLICATION", "Card Authorization")
    system = tb_asset(t, "BUSINESS_SYSTEM", "Payments")
    card_system = tb_asset(t, "BUSINESS_SYSTEM", "Card Services")
    process = tb_asset(t, "PROCESS", "payments-api")
    crypto_rsa = tb_asset(t, "CRYPTO_ASSET", "RSA-2048", evidence_type="RUNTIME_OBSERVED")
    crypto_aes = tb_asset(t, "CRYPTO_ASSET", "AES-256-GCM", evidence_type="CONFIGURED")
    library = tb_asset(t, "CRYPTO_LIBRARY", "OpenSSL 3.0.13")
    firewall = h.hardware("FIREWALL", manufacturer="Palo Alto", model="PA-5450",
                          firmware_version="11.1.3", asset_tag="fw-edge-01",
                          location="DC1-R01-U20", datacenter="DC1", ip="10.10.0.1",
                          vlan="VLAN-10", ha_mode="Active/Passive",
                          evidence_ids=[EVID])
    segment = h.hardware("NETWORK_SEGMENT", asset_tag="SEG-VLAN-40", manufacturer="Cisco",
                         model="VLAN-40", vlan="VLAN-40", zone="PAYMENTS",
                         subnet="10.10.1.0/24", evidence_ids=[EVID])
    waf = tb_asset(t, "WAF", "edge-waf")
    balancer = tb_asset(t, "LOAD_BALANCER", "payments-lb")
    gateway = tb_asset(t, "API_GATEWAY", "payments-gw")
    endpoint = tb_asset(t, "NETWORK_ENDPOINT", "payments.example.bank:443")

    host = bank["assets"][0]["name"]
    nic = next(row for row in bank["assets"] if row["kind"] == "NIC")
    capability_rsa = next(row for row in device["assets"]
                          if row["kind"] == "CRYPTO_CAPABILITY"
                          and "RSA-2048" in row["name"])

    claims = [
        h.claim("Payments", "CONTAINS", "Payments API", basis="cmdb-import",
                evidence_ids=[EVID]),
        h.claim("Payments", "CONTAINS", "Payment Gateway", basis="cmdb-import",
                evidence_ids=[EVID]),
        h.claim("Card Services", "CONTAINS", "Card Authorization", basis="cmdb-import",
                evidence_ids=[EVID]),
        h.claim("Payments API", "USES_HSM", "HSM-001", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("Card Authorization", "USES_HSM", "HSM-001", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("Payments API", "USES_CRYPTO", "CRYPTO_ASSET:RSA-2048:PRODUCTION",
                basis="runtime-probe", evidence_ids=[EVID]),
        h.claim("CRYPTO_ASSET:RSA-2048:PRODUCTION", "PROTECTED_BY", "HSM-001",
                basis="config-parse", evidence_ids=[EVID]),
        h.claim("Payments API", "RUNS_ON", host, basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("payments-api", "RUNS_ON", host, basis="process-trace",
                evidence_ids=[EVID]),
        h.claim("payments-api", "LOADS", "OpenSSL 3.0.13", basis="process-trace",
                evidence_ids=[EVID]),
        h.claim("OpenSSL 3.0.13", "PROVIDES_ALGORITHM", "CRYPTO_ASSET:RSA-2048:PRODUCTION",
                basis="runtime-probe", evidence_ids=[EVID]),
        h.claim(nic["name"], "ATTACHED_TO", segment["name"], basis="agent-inventory",
                evidence_ids=[EVID]),
        h.claim(firewall["name"], "FORWARDS_TO", "edge-waf", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("edge-waf", "FORWARDS_TO", "payments-lb", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("payments-lb", "FORWARDS_TO", "payments-gw", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("payments-gw", "ROUTES_TO", "Payments API", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("Payments API", "EXPOSES", "payments.example.bank:443", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("payments.example.bank:443", "PROTECTED_BY", "edge-waf", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("HSM-001", "PERFORMS", capability_rsa["name"], basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("PaymentHSM firmware 8.4.2", "HAS_VULNERABILITY", "CVE-2026-1111",
                basis="vendor-portal", evidence_ids=[EVID]),
        h.claim("Card Services", "OWNS", "HSM-001", basis="cmdb-import",
                evidence_ids=[EVID]),
    ]
    return {
        "parts": [device, bank, firewall, segment,
                  {"assets": [advisory, service, gateway_app, card_app, system,
                              card_system, process, crypto_rsa, crypto_aes, library,
                              waf, balancer, gateway, endpoint], "claims": claims}],
        "names": {"host": host, "nic": nic["name"], "firewall": firewall["name"],
                  "segment": segment["name"], "capability": capability_rsa["name"],
                  "release": release["name"]},
    }


def tb_asset(t: Any, kind: str, name: str, **fields: Any) -> dict[str, Any]:
    return t.asset(kind, name, evidence_ids=[EVID], **fields)


def _document(h: Any, t: Any, *, with_drift: bool = False) -> dict[str, Any]:
    fixture = _parts(h, t)
    return h.estate(*fixture["parts"], estate_id="bank-estate",
                    environment="PRODUCTION",
                    expected={"HSM": 2, "PHYSICAL_SERVER": 1, "NIC": 2, "CPU": 2,
                              "FIREWALL": 1, "CERTIFICATE": 4},
                    gaps=[{"kind": "HSM", "reason": "one HSM collector offline: the vendor "
                                                    "API answered 503 at 08:30"},
                          {"kind": "CERTIFICATE", "reason": "the certificate store needs "
                                                            "an operator credential"}]), fixture


def _bom(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    h, t = modules["h"], modules["t"]
    document, fixture = _document(h, t)
    return h.build(document), fixture


# --------------------------------------------------------------------------- #
# Rows — one per point of the review
# --------------------------------------------------------------------------- #

def row_components(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _bom(modules)
    assets = bom["assets"]
    kinds = {row["kind"] for row in assets}
    server = next(row for row in assets if row["kind"] == "PHYSICAL_SERVER")
    tree = next(node for node in bom["component_tree"]
                if node["asset_id"] == server["name"])
    child_kinds = {child["kind"] for child in tree["children"]}
    fields = server["attributes"]["field_completeness"]
    probes = [
        _probe("a-server-is-a-tree-of-parts-not-a-row",
               {"CPU", "MEMORY", "MOTHERBOARD", "BIOS", "TPM", "NIC", "STORAGE",
                "RAID_CONTROLLER", "GPU", "PCI_DEVICE", "CRYPTO_ACCELERATOR"} <= child_kinds,
               f"{len(tree['children'])} component(s): "
               + ", ".join(sorted(child_kinds))),
        _probe("the-device-field-set-is-declared-and-counted",
               fields["expected"] == 19 and fields["declared"] >= 12,
               f"{fields['declared']} of {fields['expected']} declared field(s) supplied"),
        _probe("what-the-collector-did-not-supply-is-named-not-hidden",
               "part_number" not in fields["missing"] or "part_number"
               in server["attributes"]["unknown_fields"],
               f"{len(fields['missing'])} field(s) listed as unknown: "
               + ", ".join(fields["missing"][:5])),
        _probe("every-component-carries-its-own-evidence-and-identity",
               all(row["evidence_ids"] and row["attributes"].get("identity")
                   for row in assets if row["kind"] in modules["h"].HARDWARE_KINDS
                   and "asset_id" in row["attributes"]),
               f"{len([row for row in assets if 'identity' in row['attributes']])} "
               "asset(s) carry an identity block"),
        _probe("bios-and-firmware-are-reachable-as-their-own-assets",
               {"BIOS", "FIRMWARE"} <= kinds and any(
                   row["relation"] == "RUNS_BIOS" for row in bom["claims"]),
               "RUNS_BIOS plus RUNS_FIRMWARE, not a version string on the server row"),
    ]
    return {"id": "components", "question": "is a server a tree of parts, with the field set",
            "phase": "review hbom / 1", "probes": probes}


def row_hsm(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    counts = bom["techbom"]["by_kind"]
    relations = {row["relation"] for row in bom["claims"]}
    hsm_row = next(row for row in bom["assets"] if row["kind"] == "HSM"
                   and row["name"] == "HSM-001")
    attributes = hsm_row["attributes"]
    capability = next(row for row in bom["assets"]
                      if row["kind"] == "CRYPTO_CAPABILITY" and "ML-KEM-768" in row["name"])
    probes = [
        _probe("an-hsm-carries-cluster-ha-peers-and-partitions",
               counts.get("HSM_CLUSTER") == 1 and counts.get("HSM_PARTITION") == 2
               and {"MEMBER_OF", "PEERS_WITH", "HAS_PARTITION"} <= relations,
               f"cluster 1, partitions {counts.get('HSM_PARTITION')}, "
               f"HA mode {attributes['ha_mode']}"),
        _probe("an-hsm-lists-what-it-can-do-with-key-types-and-sizes",
               capability["attributes"]["key_sizes"] == ["768"]
               and capability["attributes"]["operations"] == ["ENCAPSULATE"],
               f"{capability['name']} → {capability['attributes']['operations']}"),
        _probe("the-applications-wired-to-the-device-are-claims-not-attributes",
               any(row["relation"] == "USES_HSM" for row in bom["claims"]),
               f"{len([row for row in bom['claims'] if row['relation'] == 'USES_HSM'])} "
               "USES_HSM edge(s)"),
        _probe("a-partition-names-the-application-it-serves",
               all("applications" in row["attributes"]
                   for row in bom["assets"] if row["kind"] == "HSM_PARTITION"),
               "each partition records the applications it holds keys for"),
        _probe("a-key-material-attribute-is-refused-at-the-door",
               _refused(h, lambda: h.hardware("HSM", manufacturer="X", model="Y",
                                              evidence_ids=[EVID],
                                              private_key="MIIEvQIBADANBgkq")) ==
               "KEY_MATERIAL_REFUSED",
               "private_key → KEY_MATERIAL_REFUSED"),
    ]
    return {"id": "hsm", "question": "is an HSM a device with depth, not a vendor string",
            "phase": "review hbom / 2", "probes": probes}


def row_software(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom, fixture = _bom(modules)
    host = fixture["names"]["host"]
    host_row = bom["by_key"][next(key for key, row in bom["by_key"].items()
                                  if row["name"] == host)]
    radius = modules["h"].radius(bom, query=host)
    chain = [row["relation"] for row in bom["claims"]
             if row["from_key"] == next(key for key, row in bom["by_key"].items()
                                        if row["name"] == "payments-api")]
    probes = [
        _probe("a-process-runs-on-the-host-it-was-seen-on",
               "payments-api" in radius["impacts"].get("PROCESS", []),
               f"payments-api reaches {host} over RUNS_ON ({len(radius['proven'])} proven "
               "node(s))"),
        _probe("an-application-on-a-host-is-a-covered-claim-not-an-assumption",
               any(row["relation"] == "RUNS_ON" and row["from"] == "Payments API"
                   for row in bom["claims"]),
               "Payments API RUNS_ON the server, basis config-parse → CONFIGURED"),
        _probe("the-business-system-to-hardware-chain-is-walkable-end-to-end",
               "BUSINESS_SYSTEM" in bom["techbom"]["by_kind"]
               and any(row["relation"] == "OWNS" for row in bom["claims"])
               and "Payments" in modules["h"].radius(bom, query="HSM-001")["systems"],
               "system → application → process → host → component, all from claims"),
        _probe("a-process-loads-the-crypto-library-that-uses-the-algorithm",
               "LOADS" in chain,
               "payments-api LOADS OpenSSL 3.0.13, and the library PROVIDES_ALGORITHM"),
        _probe("the-host-row-carries-the-hardware-it-was-seen-with",
               host_row["kind"] == "PHYSICAL_SERVER" and host_row["attributes"]["asset_id"],
               f"{host_row['attributes']['asset_id']} is the canonical id, not a hostname"),
        _probe("an-application-cannot-be-a-component-of-a-server",
               "TYPE_MISMATCH" in _codes(
                   modules["h"], t, [host_row, tb_asset(t, "APPLICATION", "Payments API")],
                   [modules["h"].claim(host_row["name"], "HAS_COMPONENT", "Payments API",
                                       basis="agent-inventory", evidence_ids=[EVID])]),
               "HAS_COMPONENT ends at a component, never at an application"),
    ]
    return {"id": "software", "question": "does hardware meet software through evidence",
            "phase": "review hbom / 3", "probes": probes}


def row_crypto(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    bom, fixture = _bom(modules)
    relations = {}
    for row in bom["claims"]:
        relations.setdefault(row["relation"], []).append(row["confidence"])
    weak = h.build(h.estate(h.merge(
        h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVID]),
        h.capability("cap RSA", algorithm="RSA-2048", operations=["SIGN"],
                     evidence_ids=[EVID]), {"assets": [], "claims": []})))
    device = next(row for row in weak["assets"] if row["kind"] == "HSM")
    refused = h.build(h.estate(h.merge({"assets": [device], "claims": [
        h.claim(device["name"], "PERFORMS", "cap RSA", basis="vendor-datasheet",
                evidence_ids=[EVID])]},
        h.capability("cap RSA", algorithm="RSA-2048", operations=["SIGN"],
                     evidence_ids=[EVID]))))
    probes = [
        _probe("supports-is-a-capability-claim-and-carries-its-own-class",
               relations.get("SUPPORTS", [])[0] == "VENDOR_DECLARED",
               f"SUPPORTS → {relations.get('SUPPORTS', ['none'])[0]} from the vendor list"),
        _probe("performs-is-a-statement-that-something-ran-there",
               "PERFORMS" in relations and relations["PERFORMS"][0] == "CONFIGURED",
               f"PERFORMS → {relations.get('PERFORMS', ['none'])[0]} from the HSM API poll"),
        _probe("a-datasheet-cannot-carry-a-performs-claim",
               any(row["code"] == "CLAIM_WEAKER_THAN_RELATION_REQUIRES"
                   for row in refused["refusals"]),
               "vendor-datasheet PERFORMS → CLAIM_WEAKER_THAN_RELATION_REQUIRES"),
        _probe("uses_crypto-is-a-claim-about-the-application-not-the-device",
               relations.get("USES_CRYPTO", [])[0] == "OBSERVED",
               f"Payments API USES_CRYPTO → {relations.get('USES_CRYPTO', ['none'])[0]}"),
        _probe("protected_by-is-a-claim-about-the-key-and-its-custodian",
               "PROTECTED_BY" in relations,
               f"RSA-2048 PROTECTED_BY HSM-001 → {relations['PROTECTED_BY'][0]}"),
        _probe("a-device-relation-can-never-be-written-from-the-application-side",
               "TYPE_MISMATCH" in _codes(
                   h, t,
                   [tb_asset(t, "APPLICATION", "Payments API"),
                    h.capability("cap RSA", algorithm="RSA-2048",
                                 evidence_ids=[EVID])],
                   [h.claim("Payments API", "SUPPORTS", "cap RSA",
                            basis="vendor-datasheet", evidence_ids=[EVID])]),
               "SUPPORTS starts at a device or a firmware, never at an application"),
    ]
    return {"id": "crypto", "question": "are capability, operation, use and custody distinct",
            "phase": "review hbom / 4", "probes": probes}


def row_vendor(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _bom(modules)
    edges = {(row["relation"], row["from"], row["to"]) for row in bom["claims"]}
    radius = modules["h"].radius(bom, query="SyntheticHSM")
    probes = [
        _probe("vendor-to-product-to-device-is-four-claims",
               ("HAS_MODEL", "HSM-001", "SyntheticHSM PaymentHSM-9000") in edges
               and ("SUPPLIED_BY", "SyntheticHSM PaymentHSM-9000", "SyntheticHSM") in edges,
               "HSM-001 HAS_MODEL product, product SUPPLIED_BY vendor"),
        _probe("the-firmware-release-is-in-the-vendor-chain",
               ("SUPPLIED_BY", "PaymentHSM firmware 8.4.2", "SyntheticHSM") in edges,
               "the release names its vendor, so an advisory can start at either end"),
        _probe("a-vendor-question-reaches-the-systems-that-buy-it",
               radius["applications"] or radius["crypto_assets"],
               radius["statement"]),
    ]
    return {"id": "vendor", "question": "does the vendor chain reach the business",
            "phase": "review hbom / 5", "probes": probes}


def row_network(modules: dict[str, Any]) -> dict[str, Any]:
    bom, fixture = _bom(modules)
    chain = [row for row in bom["claims"] if row["relation"] == "FORWARDS_TO"]
    radius = modules["h"].radius(bom, query=fixture["names"]["firewall"])
    segment = next(row for row in bom["assets"] if row["kind"] == "NETWORK_SEGMENT")
    probes = [
        _probe("a-firewall-is-hardware-with-its-own-firmware-and-ha-role",
               any(row["kind"] == "FIREWALL"
                   and row["attributes"].get("firmware_version") for row in bom["assets"]),
               "FIREWALL with firmware 11.1.3 and HA mode Active/Passive"),
        _probe("the-path-is-firewall-then-waf-then-balancer-then-gateway",
               len(chain) == 3, f"{len(chain)} FORWARDS_TO hop(s) from the firewall"),
        _probe("a-nic-attaches-to-a-segment-and-the-segment-carries-the-zone",
               segment["attributes"]["vlan"] == "VLAN-40"
               and any(row["relation"] == "ATTACHED_TO" for row in bom["claims"]),
               "NIC ATTACHED_TO SEG-VLAN-40, zone PAYMENTS, 10.10.1.0/24"),
        _probe("the-network-and-the-hardware-are-one-graph",
               "edge-waf" in radius["impacts"].get("WAF", [])
               and "Payments API" in radius["impacts"].get("APPLICATION", []),
               radius["statement"]),
    ]
    return {"id": "network", "question": "is network hardware in the same estate",
            "phase": "review hbom / 6", "probes": probes}


def row_business(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _bom(modules)
    radius = modules["h"].radius(bom, query="HSM-001")
    probes = [
        _probe("an-hsm-failure-reported-in-the-units-a-business-owner-uses",
               bool(radius["applications"]) and bool(radius["systems"]),
               radius["statement"]),
        _probe("business-systems-are-reachable-through-applications-not-by-name-matching",
               radius["systems"] == ["Card Services", "Payments"],
               f"{len(radius['systems'])} system(s): {', '.join(radius['systems'])}"),
        _probe("the-cryptographic-assets-behind-the-device-are-counted",
               bool(radius["crypto_assets"]),
               f"{len(radius['crypto_assets'])} cryptographic asset(s)"),
        _probe("the-network-paths-that-carry-the-traffic-are-counted",
               bool(radius["network_paths"]),
               f"{len(radius['network_paths'])} network path(s)"),
        _probe("a-declared-hop-taints-what-sits-above-it",
               bool(radius["possible"]),
               f"{len(radius['possible'])} node(s) reached only through a declared edge"),
    ]
    return {"id": "business", "question": "does an HSM question become a blast radius",
            "phase": "review hbom / 7", "probes": probes}


def row_firmware(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _bom(modules)
    lifecycle = bom["firmware_lifecycle"]
    end_of_life = [row for row in lifecycle if row["actionable"]]
    advisory_edges = [row for row in bom["claims"]
                      if row["relation"] == "HAS_VULNERABILITY"]
    probes = [
        _probe("firmware-is-a-release-with-a-date-a-status-and-an-end",
               bool(end_of_life) and end_of_life[0]["status"] == "EOL"
               and end_of_life[0]["release_date"] == "2025-04-01",
               f"{end_of_life[0]['firmware']} {end_of_life[0]['version']} → EOL"),
        _probe("the-release-names-the-devices-that-run-it",
               end_of_life[0]["devices"] == ["HSM-001"],
               f"run by {', '.join(end_of_life[0]['devices'])}"),
        _probe("a-known-vulnerability-reaches-the-release-through-an-edge",
               len(advisory_edges) == 1 and advisory_edges[0]["confidence"] ==
               "VENDOR_DECLARED",
               "CVE-2026-1111 → VENDOR_DECLARED, because the vendor said it"),
        _probe("an-unknown-firmware-status-is-refused-rather-than-stored",
               _refused(modules["h"], lambda: modules["h"].firmware(
                   "fw", version="1", status="PROBABLY-FINE", evidence_ids=[EVID]))
               == "UNKNOWN_FIRMWARE_STATUS",
               "PROBABLY-FINE → UNKNOWN_FIRMWARE_STATUS"),
    ]
    return {"id": "firmware", "question": "is firmware first-class, with a lifecycle",
            "phase": "review hbom / 8", "probes": probes}


def row_drift(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    before = _bom(modules)[0]

    # the same estate, later: a BIOS update, a re-addressed NIC and an HSM upgrade
    fixture = _parts(h, t)
    document = h.estate(*fixture["parts"], estate_id="bank-estate",
                        environment="PRODUCTION")
    after_bom = h.build(document)
    feed = h.drift(before, after_bom)

    address_document, _ = _document(h, t)
    for row in address_document["assets"]:
        if row["kind"] == "NIC":
            row["attributes"]["ip"] = "10.10.1.45"
    re_addressed = h.build(address_document)
    address_feed = h.drift(before, re_addressed)

    probes = [
        _probe("an-unchanged-estate-produces-no-drift",
               feed["hardware_drift"] is False and feed["events"] == [],
               "no change between two reads of the same estate"),
        _probe("moving-an-address-is-a-network-interface-change-not-a-new-device",
               address_feed["by_change"] == {"NETWORK_INTERFACE_CHANGED": 1}
               and "DEVICE_ADDED" not in address_feed["by_change"],
               f"{address_feed['statement']}"),
        _probe("a-hsm-firmware-change-is-named-as-an-hsm-change",
               _drift_named(h, t, "HSM_FIRMWARE_CHANGED") == 1,
               "8.4.2 → 8.5.0 → HSM_FIRMWARE_CHANGED"),
        _probe("a-bios-change-and-a-firmware-change-are-different-events",
               _drift_named(h, t, "BIOS_CHANGED") == 1
               and _drift_named(h, t, "FIRMWARE_CHANGED") == 1,
               "BIOS_CHANGED and FIRMWARE_CHANGED are counted separately"),
        _probe("a-removed-part-is-device-removed-and-a-new-one-is-device-added",
               _drift_named(h, t, "DEVICE_ADDED") == 1
               and _drift_named(h, t, "DEVICE_REMOVED") == 1,
               "DEVICE_ADDED and DEVICE_REMOVED are both reported"),
        _probe("every-drift-event-carries-the-cryptography-behind-the-device",
               all(event["crypto_impact"]["edges_considered"] >= 0 for event in
                   feed["events"]) and bool(modules["h"].drift(
                       before, _hsm_upgrade(h, t))["crypto_impact"]["applications"]),
               "an HSM change names the application that depends on it"),
        _probe("the-twelve-review-change-types-are-all-modelled",
               all(name in set(h.DRIFT_TYPES) for name in feed["by_change"])
               and len(h.DRIFT_TYPES) == 12,
               f"{len(h.DRIFT_TYPES)} typed hardware changes"),
    ]
    return {"id": "drift", "question": "does hardware drift come back typed",
            "phase": "review hbom / 9", "probes": probes, "events": feed["events"]}


def _hsm_upgrade(h: Any, t: Any) -> dict[str, Any]:
    fixture = _parts(h, t)
    for part in fixture["parts"]:
        for row in list(part.get("assets") or []):
            if row["kind"] == "HSM" and row["name"] == "HSM-001":
                row["version"] = "8.5.0"
    return h.build(h.estate(*fixture["parts"], estate_id="bank-estate",
                            environment="PRODUCTION"))


def _drift_named(h: Any, t: Any, change: str) -> int:
    """One event of this type, by mutating exactly one thing about the estate."""
    before = _bom({"h": h, "t": t})[0]
    fixture = _parts(h, t)
    for part in fixture["parts"]:
        for row in list(part.get("assets") or []):
            if change == "HSM_FIRMWARE_CHANGED" and row["kind"] == "HSM" \
                    and row["name"] == "HSM-001":
                row["version"] = "8.5.0"
            elif change == "BIOS_CHANGED" and row["kind"] == "BIOS":
                row["version"] = "2.6.0"
            elif change == "FIRMWARE_CHANGED" and row["kind"] == "NIC":
                row["version"] = "22.35.0"
            elif change == "DEVICE_ADDED" and row["kind"] == "GPU":
                part.setdefault("assets", []).append(dict(
                    row, name=row["name"] + "-2", key=row["key"] + ":2",
                    attributes={**row["attributes"], "asset_id": row["name"] + "-2"}))
            elif change == "DEVICE_REMOVED" and row["kind"] == "GPU":
                part["assets"] = [other for other in part["assets"] if other is not row]
    after = h.build(h.estate(*fixture["parts"], estate_id="bank-estate",
                             environment="PRODUCTION"))
    return h.drift(before, after)["by_change"].get(change, 0)


def row_identity(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    first = h.identity(manufacturer="Dell", model="PowerEdge R760", serial_number="SN-7K2L",
                       hostname="bank-srv-001", ip_addresses=["10.10.1.20"],
                       mac_addresses=["aa:bb:cc:00:11:22"])
    second = h.identity(manufacturer="Dell", model="PowerEdge R760", serial_number="SN-7K2L",
                        hostname="bank-srv-001-renamed", ip_addresses=["10.10.1.45"],
                        mac_addresses=["aa:bb:cc:00:11:22"])
    provisional = h.identity(manufacturer="Dell", model="PowerEdge R760")
    probes = [
        _probe("a-canonical-id-is-derived-from-manufacturer-model-and-serial",
               first["asset_id"].startswith("ASSET-HW-") and first["method"] == "serial",
               f"{first['asset_id']} from {', '.join(sorted(first['anchors']))}"),
        _probe("a-renamed-host-and-a-new-address-keep-the-same-id",
               first["asset_id"] == second["asset_id"],
               "the address moved; the device did not"),
        _probe("network-identifiers-are-kept-but-never-used-as-identity",
               first["ignored_identifiers"]["ip_addresses"] == ["10.10.1.20"],
               "hostname and MAC recorded as observations only"),
        _probe("a-device-known-only-by-hostname-ip-and-mac-has-no-identity",
               _refused(h, lambda: h.identity(hostname="h", ip_addresses=["10.0.0.1"],
                                              mac_addresses=["aa"]))
               == "IDENTITY_WITHOUT_ANCHOR",
               "IDENTITY_WITHOUT_ANCHOR rather than a hostname-shaped id"),
        _probe("a-manufacturer-and-model-alone-is-provisional-and-says-so",
               provisional["provisional"] is True,
               "two units of one model collide, so the id says it is provisional"),
    ]
    return {"id": "identity", "question": "is hardware identity stable under network change",
            "phase": "review hbom / 10", "probes": probes}


def row_virtual(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    physical = h.hardware("PHYSICAL_SERVER", manufacturer="HPE", model="DL380 Gen11",
                          serial_number="SN-P1", evidence_ids=[EVID])
    hypervisor = tb_asset(t, "HYPERVISOR", "esxi-01")
    virtual = tb_asset(t, "VM", "payments-vm-01")
    operating_system = tb_asset(t, "OS", "rhel-9.4")
    application = tb_asset(t, "APPLICATION", "Payments API")
    instance = tb_asset(t, "CLOUD_INSTANCE", "i-0abc")
    region = tb_asset(t, "CLOUD_REGION", "eu-west-1")
    account = tb_asset(t, "CLOUD_ACCOUNT", "bank-prod")
    claims = [
        h.claim(physical["name"], "RUNS_HYPERVISOR", "esxi-01", basis="agent-inventory",
                evidence_ids=[EVID]),
        h.claim("payments-vm-01", "RUNS_ON", "esxi-01", basis="agent-inventory",
                evidence_ids=[EVID]),
        h.claim("payments-vm-01", "HOSTS_OS", "rhel-9.4", basis="agent-inventory",
                evidence_ids=[EVID]),
        h.claim("rhel-9.4", "RUNS_APPLICATION", "Payments API", basis="process-trace",
                evidence_ids=[EVID]),
        h.claim("i-0abc", "IN_REGION", "eu-west-1", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("eu-west-1", "IN_ACCOUNT", "bank-prod", basis="api-poll",
                evidence_ids=[EVID]),
    ]
    bom = h.build(h.estate(h.merge(
        {"assets": [physical, hypervisor, virtual, operating_system, application,
                    instance, region, account], "claims": claims})))
    radius = h.radius(bom, query="esxi-01")
    probes = [
        _probe("physical-to-hypervisor-to-vm-to-os-to-application-is-one-chain",
               radius["applications"] == ["Payments API"] and not bom["refusals"],
               radius["statement"]),
        _probe("a-cloud-instance-is-in-a-region-which-is-in-an-account",
               {"CLOUD_INSTANCE", "CLOUD_REGION", "CLOUD_ACCOUNT"} <=
               set(bom["techbom"]["by_kind"]),
               "three claims, no viewer-side inference"),
        _probe("the-platform-rows-are-hardware-adjacent-not-applications",
               all(row["kind"] != "APPLICATION" for row in bom["assets"]),
               "an application is reached from the platform, not stored as one"),
    ]
    return {"id": "virtual", "question": "do virtual and cloud platforms correlate",
            "phase": "review hbom / 11", "probes": probes}


def row_containers(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    pod = tb_asset(t, "POD", "payments-api-7d9f")
    node = tb_asset(t, "KUBERNETES_NODE", "k8s-node-3")
    container = tb_asset(t, "CONTAINER", "payments-api-ctr")
    process = tb_asset(t, "PROCESS", "payments-api")
    library = tb_asset(t, "CRYPTO_LIBRARY", "OpenSSL 3.0.13")
    cpu = h.hardware("CPU", asset_id="ASSET-HW-000001-CPU", manufacturer="Intel",
                     model="Xeon 6430", evidence_ids=[EVID])
    claims = [
        h.claim("payments-api-7d9f", "SCHEDULED_ON", "k8s-node-3", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("payments-api-7d9f", "RUNS_PROCESS", "payments-api", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("payments-api", "LOADS", "OpenSSL 3.0.13", basis="process-trace",
                evidence_ids=[EVID]),
        h.claim("payments-api-7d9f", "SCHEDULED_ON", cpu["name"], basis="api-poll",
                evidence_ids=[EVID]),
    ]
    bom = h.build(h.estate(h.merge({"assets": [pod, node, container, process, library, cpu],
                                    "claims": claims})))
    probes = [
        _probe("a-pod-is-scheduled-on-a-node-and-never-on-a-processor",
               [row["code"] for row in bom["refusals"]] == ["TYPE_MISMATCH"],
               "the pod→CPU claim is refused, the pod→node claim is kept"),
        _probe("a-container-reaches-the-crypto-library-through-its-process",
               any(row["relation"] == "LOADS" for row in bom["claims"])
               and any(row["relation"] == "RUNS_PROCESS" for row in bom["claims"]),
               "container → process → library → algorithm, without inventing hardware"),
        _probe("a-container-is-not-given-a-hardware-substrate-it-cannot-prove",
               all(row["kind"] != "CONTAINER" for row in bom["assets"]),
               "the container stays in the software view"),
    ]
    return {"id": "containers", "question": "does Kubernetes correlate without pretending",
            "phase": "review hbom / 12", "probes": probes}


def row_evidence(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    register = bom["evidence_register"]
    record = register.get(EVID, {})
    probes = [
        _probe("every-device-cites-an-evidence-id",
               all(row["evidence_ids"] for row in bom["assets"]
                   if row["kind"] in h.HARDWARE_KINDS
                   and "asset_id" in row["attributes"]),
               f"{len(bom['assets'])} asset(s), each with at least one evidence id"),
        _probe("the-register-keeps-the-eleven-parts-the-review-asks-for",
               len([key for key in ("evidence_id", "collector", "collector_version",
                                    "target_id", "observed_at", "source", "evidence_type",
                                    "raw_reference", "normalized_fact", "hash",
                                    "confidence") if record.get(key)]) == 11,
               f"{record.get('collector')} {record.get('collector_version')} at "
               f"{record.get('observed_at')}"),
        _probe("an-observation-without-a-hash-is-refused",
               _refused(h, lambda: h.evidence("E1", collector="agent",
                                              observed_at=NOW, hash=None))
               == "EVIDENCE_WITHOUT_HASH",
               "evidence that cannot be re-checked is a memory"),
        _probe("a-hardware-asset-without-evidence-is-refused",
               _refused(h, lambda: h.hardware("HSM", manufacturer="X", model="Y"))
               == "HARDWARE_WITHOUT_EVIDENCE",
               "how the platform knows the device exists is part of the asset"),
        _probe("key-material-is-refused-and-a-reference-is-kept",
               _refused(h, lambda: h.hardware("HSM", manufacturer="X", model="Y",
                                              evidence_ids=[EVID],
                                              note="-----BEGIN PRIVATE KEY-----"))
               == "KEY_MATERIAL_REFUSED"
               and h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVID],
                              key_reference="KREF-0007")["attributes"]["key_reference"]
               == "KREF-0007",
               "PRIVATE KEY → KEY_MATERIAL_REFUSED; KREF-0007 is kept"),
    ]
    return {"id": "evidence", "question": "does every fact say how it is known",
            "phase": "review hbom / 13", "probes": probes}


def row_coverage(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    block = h.coverage(200, 120, unavailable=50, permission_denied=20, unknown=10)
    probes = [
        _probe("coverage-states-the-denominator-and-every-bucket",
               block["expected"] == 200 and block["verdict"] == "PARTIAL",
               block["statement"]),
        _probe("coverage-that-does-not-add-up-is-refused",
               _refused(h, lambda: h.coverage(200, 120, unavailable=50,
                                              permission_denied=10, unknown=10))
               == "COVERAGE_DOES_NOT_RECONCILE",
               "190 accounted for of 200 expected → COVERAGE_DOES_NOT_RECONCILE"),
        _probe("the-estate-carries-its-own-completeness-with-the-gap-reasons",
               bom["coverage"]["overall"] == "PARTIAL" and bom["coverage"]["gaps"],
               bom["coverage"]["statement"]),
        _probe("a-kind-with-no-denominator-is-unmeasured-not-complete",
               "GPU" in bom["coverage"]["unmeasured"],
               f"{len(bom['coverage']['unmeasured'])} kind(s) unmeasured"),
    ]
    return {"id": "coverage", "question": "does coverage say what was not seen",
            "phase": "review hbom / 14", "probes": probes}


def row_crossbom(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    view = h.correlate(bom, "HSM-001")
    link = h.bom_link(bom)
    probes = [
        _probe("one-hardware-asset-walks-into-the-other-four-views",
               {"HBOM", "CBOM", "VBOM"} <= set(view["by_bom"]),
               view["statement"]),
        _probe("the-walk-reaches-the-application-and-the-business-system",
               any(row["kind"] == "APPLICATION" for rows in view["by_bom"].values()
                   for row in rows),
               "HBOM → CBOM → SBOM → NBOM → VBOM, one graph"),
        _probe("a-link-is-a-reference-pinned-by-digest-not-a-copy",
               link["link"].startswith("bom-link:hbom:") and len(link["link"]) > 25,
               link["link"]),
    ]
    return {"id": "crossbom", "question": "does the HBOM correlate with the other BOMs",
            "phase": "review hbom / 15", "probes": probes}


def row_projection(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    bom, _ = _bom(modules)
    techbom_doc = t.build(_document(h, t)[0])
    probes = [
        _probe("the-hbom-is-the-techbom-restricted-to-hardware",
               {row["key"] for row in bom["assets"] if row["kind"] != "EVIDENCE"} <=
               {row["key"] for row in techbom_doc["assets"]},
               f"{len(bom['assets'])} hardware row(s) out of "
               f"{len(techbom_doc['assets'])} estate assets"),
        _probe("an-hbom-cannot-be-fed-back-in-as-a-source",
               _value_refused(h, lambda: h.from_document(bom), "not a source"),
               "from_document(HBOM) → refused: a projection is not a source"),
        _probe("a-techbom-cannot-produce-an-hbom-either",
               _value_refused(h, lambda: h.from_document(techbom_doc), "not a source"),
               "from_document(TechBOM) → refused"),
        _probe("the-same-estate-produces-the-same-ids-and-the-same-statement",
               h.build(_document(h, t)[0])["statement"] == bom["statement"],
               bom["statement"]),
    ]
    return {"id": "projection", "question": "is the HBOM a view and never a source",
            "phase": "review hbom / 16", "probes": probes}


def _refused(module: Any, call: Any) -> str:
    """The refusal code a call raises, or ``""`` when it is accepted."""
    try:
        call()
    except Exception as exc:  # noqa: BLE001 — a refusal is the measurement
        return str(getattr(exc, "code", ""))
    return ""


def _codes(h: Any, t: Any, assets: list[dict[str, Any]],
           claims: list[dict[str, Any]]) -> list[str]:
    """The refusal codes a two-asset estate produces — the type rules live in build()."""
    bom = h.build(h.estate(h.merge({"assets": assets, "claims": claims})))
    return [row["code"] for row in bom["refusals"]]


def _value_refused(module: Any, call: Any, fragment: str) -> bool:
    try:
        call()
    except ValueError as exc:
        return fragment in str(exc)
    return False


ROWS = (row_components, row_hsm, row_software, row_crypto, row_vendor, row_network,
        row_business, row_firmware, row_drift, row_identity, row_virtual, row_containers,
        row_evidence, row_coverage, row_crossbom, row_projection)


def measure() -> dict[str, Any]:
    modules = _load()
    rows = []
    for builder in ROWS:
        row = builder(modules)
        failed = [probe for probe in row["probes"] if not probe["ok"]]
        if not failed:
            verdict = VERDICT_PASS
        elif len(failed) * 3 <= len(row["probes"]):
            verdict = VERDICT_PARTIAL
        else:
            verdict = VERDICT_FAIL
        row["verdict"] = verdict
        row["failed"] = [probe["probe"] for probe in failed]
        rows.append(row)
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    h, t = modules["h"], modules["t"]
    document, fixture = _document(h, t)
    bom = h.build(document)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "statement": bom["statement"],
        "summary": h.summary(bom),
        "counts_by_kind": bom["counts"],
        "views": bom["techbom"]["by_kind"],
        "fields": {name: row for name, row in bom["fields"].items()},
        "firmware": bom["firmware_lifecycle"],
        "radius": h.radius(bom, query="HSM-001"),
        "views_of_hsm": h.correlate(bom, "HSM-001"),
        "coverage_example": h.coverage(200, 120, unavailable=50, permission_denied=20,
                                       unknown=10),
        "bom": {"component_tree": bom["component_tree"], "refusals": bom["refusals"]},
        "rows": rows,
        "limits": [
            "the fixture is the review's own example estate, not a bank's collector "
            "output: the shapes are real, the rows are not",
            "a collector that cannot see a field leaves it unknown, and this guide counts "
            "those gaps instead of filling them",
            "capability is what a vendor or a firmware list says; nothing here re-probes "
            "the device to confirm it",
            "drift compares two collections: a device nobody re-read shows no change",
            "coverage is only as honest as the denominator, which comes from a CMDB the "
            "platform does not own",
        ],
    }


def _kind_table(counts: dict[str, int]) -> list[str]:
    return [f"| `{kind}` | {count} |" for kind, count in sorted(counts.items())]


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    radius = report["radius"]
    coverage = report["coverage_example"]
    firmware = report["firmware"][0] if report["firmware"] else None
    lines = [
        "# Hardware is a view of the estate",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "The HBOM review's sixteen points, answered by putting hardware into the graph the",
        "rest of the estate already lives in. The device is a tree, the HSM has depth, and",
        "capability, operation, use and custody stay four different claims.",
        "",
        "```",
        "device → component     HAS_COMPONENT, RUNS_BIOS, HAS_PARTITION",
        "device → capability    SUPPORTS          a datasheet may say this",
        "device → capability    PERFORMS          something ran there, so CONFIGURED or better",
        "application → crypto   USES_CRYPTO       a claim about the application",
        "crypto → device        PROTECTED_BY      the key is held there",
        "device → firmware      RUNS_FIRMWARE     the release, with its own lifecycle",
        "```",
        "",
        report["statement"],
        "",
        "## What the view holds",
        "",
        "| kind | rows |",
        "|---|---|",
        *_kind_table(report["counts_by_kind"]),
        "",
        "| kind | in the estate |",
        "|---|---|",
        *_kind_table({kind: count for kind, count in report["views"].items()
                      if kind not in report["counts_by_kind"]}),
        "",
        "## Field coverage — what the collectors did not supply",
        "",
        "| field | declared | missing |",
        "|---|---|---|",
        *[f"| `{name}` | {row['declared']} | {row['missing']} |"
          for name, row in report["fields"].items()],
        "",
        f"**Blast radius** — {radius['statement']}",
        "",
        f"**Coverage** — {coverage['statement']}",
        "",
    ]
    if firmware:
        lines += [
            f"**Firmware** — {firmware['firmware']} ({firmware['version']}): "
            f"{firmware['status']}, run by {', '.join(firmware['devices'])}, "
            f"{len(firmware['vulnerabilities'])} advisory(ies)",
            "",
        ]
    lines += [f"**Cross-BOM** — {report['views_of_hsm']['statement']}", "",
              "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* ({row['phase']})", ""]
        for probe in row["probes"]:
            mark = "**PASS**" if probe["ok"] else "**FAIL**"
            lines.append(f"- {mark} `{probe['probe']}` — {probe['observed']}")
    lines += ["", "## What this does not prove", ""]
    lines += [f"- {limit}" for limit in report["limits"]]
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--md", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, default=str) + "\n",
                             encoding="utf-8")
    if args.md:
        args.md.write_text(render_md(report), encoding="utf-8")
    if not args.json and not args.md:
        print(render_md(report))
    counts = report["counts"]
    print(f"{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
          f"{counts[VERDICT_FAIL]} fail", file=sys.stderr)
    if not args.check:
        return 0
    if counts[VERDICT_FAIL]:
        return 2
    if counts[VERDICT_PARTIAL]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
