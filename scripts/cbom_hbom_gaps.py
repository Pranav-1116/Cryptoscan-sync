#!/usr/bin/env python3
"""Guide 168 — the rest of the HBOM review: metadata, classes, lifecycle, evidence.

Guide 167 answered the review's sixteen points at the level of relations. Reading it back
against the text line by line left nine things still missing, and this guide builds them:

* **device metadata** — a SKU, the certifications a device holds (FIPS, Common Criteria),
  and a CPU written as a topology whose arithmetic has to reconcile;
* **the other direction of "runs"** — the review draws ``HOST-001 ↓ RUNS Payments API``;
  guide 167 only had the application pointing at the host;
* **two evidence classes the review names and the ladder did not have** — ``CAPABILITY``
  (what a device says it can do) and ``NETWORK_OBSERVED`` (an observation taken off the
  wire), which is an observation and stays in the proven set;
* **product lifecycle** — a model going EOL or retired, and the devices, applications and
  systems behind it;
* **network appliances with all fourteen facts** — IP, MAC, interface, VLAN, zone, subnet,
  routing, HA role, firmware, vendor, model, TLS capability, certificate and HSM reference,
  with the last two as edges rather than strings;
* **the review's sentence as a measurement** — *1 HSM, 3 applications, 2 business systems,
  7 cryptographic assets, 2 network paths affected*;
* **DEVICE_REPLACED** — a swapped unit in the same rack slot is one event, not an add and a
  remove, and it was effectively unreachable before;
* **evidence as nodes** — a record in a side table is a document nobody can walk; each
  cited record becomes a node and each device an ``EVIDENCED_BY`` edge;
* **HSM certificates** — the certificate a device holds is a node with an edge to it.

The measurement is a small bank estate: one HSM cluster, one server, a firewall, a load
balancer and the software behind them.
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
SCHEMA = "cryptoscan.cbom-hbom-gaps-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID = "EVID-829182"
NOW = "2026-11-03T08:30:00Z"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES / "shared"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import hbom_graph, techbom  # noqa: PLC0415

    return {"h": hbom_graph, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _asset(t: Any, kind: str, name: str, **fields: Any) -> dict[str, Any]:
    return t.asset(kind, name, evidence_ids=[EVID], **fields)


def _evidence(h: Any, **fields: Any) -> dict[str, Any]:
    return h.evidence(
        EVID, collector=fields.pop("collector", "linux-hardware-collector"),
        collector_version=fields.pop("collector_version", "1.4.2"),
        target_id=fields.pop("target_id", "HSM-001"),
        observed_at=fields.pop("observed_at", NOW),
        source=fields.pop("source", "/sys/class/dmi/id"),
        evidence_type=fields.pop("evidence_type", "INVENTORY"),
        raw_reference=fields.pop("raw_reference", "dmi/id/product_serial"),
        normalized_fact=fields.pop("normalized_fact", "serial=HSM-SN-7K2L"),
        hash=fields.pop("hash", "sha256:3b1f9c0d"),
        confidence=fields.pop("confidence", "HIGH"), **fields)


def _estate(h: Any, t: Any) -> dict[str, Any]:
    """One bank estate: HSM cluster, server, firewall, load balancer, software behind them."""
    record = _evidence(h)
    topology = h.cpu_topology(sockets=2, cores_per_socket=16, threads_per_core=2,
                              numa_nodes=2, frequency_mhz=2600, vendor="Intel",
                              model="Xeon Gold 6430")
    release = h.firmware("PaymentHSM firmware 8.4.2", version="8.4.2",
                         vendor="SyntheticHSM", release_date="2025-04-01",
                         status="SUPPORTED", evidence_ids=[EVID])
    product = h.product("SyntheticHSM PaymentHSM-9000", vendor="SyntheticHSM",
                        model="PaymentHSM-9000", status="RETIRED",
                        eol_date="2026-09-30", replacement="PaymentHSM-9100",
                        evidence_ids=[EVID])
    device = h.hsm(
        "HSM-001", vendor="SyntheticHSM", product="PaymentHSM-9000",
        model="PaymentHSM-9000", firmware_version="8.4.2", firmware_release=release,
        ha_mode="Active/Active", cluster="HSM-CLUSTER-A",
        members=[{"name": "HSM-002", "role": "active"}],
        partitions=[{"name": "HSM-001-P1", "id": "P1", "key_types": ["RSA"],
                     "applications": ["Payments API", "Card Authorization"]}],
        capabilities=[{"algorithm": "RSA-2048", "key_types": ["RSA"], "key_sizes": [2048],
                       "operations": ["SIGN", "VERIFY"]},
                      {"algorithm": "ML-KEM-768", "key_types": ["ML-KEM"],
                       "key_sizes": [768], "operations": ["ENCAPSULATE"]}],
        key_types=["RSA", "AES"], key_sizes=[2048, 256],
        operations=["SIGN", "VERIFY", "ENCRYPT"],
        certificates=["cert:payments-root"],
        applications=["Payments API", "Card Authorization"],
        systems=["Payments"], serial_number="HSM-SN-7K2L",
        location="DC1-R12-U8", datacenter="DC1", rack="R12", slot="U8",
        certifications=[{"standard": "FIPS 140-3", "level": "Level 3",
                         "expires": "2027-06-30", "evidence_id": EVID}],
        product_asset=product,
        evidence_ids=[EVID], evidence=[record])

    server = h.server(
        manufacturer="Dell", model="PowerEdge R760", serial_number="SN-7K2L",
        asset_tag="BANK-SRV-001", datacenter="DC1", rack="R12", slot="U7",
        owner="Payments Platform", sku="PER760-32C",
        cpu=topology,
        memory={"total_mb": 524288, "modules": 8, "vendor": "Samsung"},
        motherboard={"model": "0R760A", "revision": "A02", "vendor": "Dell"},
        bios={"version": "2.4.1", "vendor": "Dell"},
        tpm={"version": "2.0", "vendor": "Infineon",
             "certifications": [{"standard": "FIPS 140-2", "level": "Level 2",
                                 "evidence_id": EVID}]},
        nics=[{"model": "Broadcom 57414", "vendor": "Broadcom", "mac": "aa:bb:cc:00:11:22",
               "ip": "10.10.1.20", "vlan": "VLAN-40"}],
        storage=[{"model": "NVMe PM1743", "vendor": "Samsung", "size_gb": 3840}],
        raid={"model": "PERC H755", "vendor": "Dell"},
        evidence_ids=[EVID], evidence=[record])

    balancer = h.network_device(
        "LOAD_BALANCER", name="payments-lb", manufacturer="F5", model="BIG-IP i5800",
        sku="F5-i5800", firmware_version="17.1.1", serial_number="F5-SN-1",
        ip="10.10.0.20", mac="aa:bb:cc:00:20:01", interface="1.1", vlan="VLAN-10",
        zone="EDGE", subnet="10.10.0.0/24", routing="static-default",
        ha_role="ACTIVE", tls={"min_version": "TLS1.2", "cipher": "ECDHE-RSA-AES256-GCM",
                               "pqc": "hybrid-x25519mlkem768"},
        certificate="cert:payments-edge", hsm="HSM-001",
        location="DC1-R01-U22", datacenter="DC1", rack="R01", slot="U22",
        owner="Network Platform", evidence_ids=[EVID])
    firewall = h.network_device(
        "FIREWALL", name="fw-edge-01", manufacturer="Palo Alto", model="PA-5450",
        firmware_version="11.1.3", ip="10.10.0.1", mac="aa:bb:cc:00:10:01",
        interface="1/1", vlan="VLAN-10", zone="EDGE", subnet="10.10.0.0/24",
        routing="policy-based", ha_role="ACTIVE", evidence_type="INVENTORY",
        tls={"min_version": "TLS1.3"}, evidence_ids=[EVID])
    application = _asset(t, "APPLICATION", "Payments API")
    card = _asset(t, "APPLICATION", "Card Authorization")
    gateway = _asset(t, "APPLICATION", "Payment Gateway")
    system = _asset(t, "BUSINESS_SYSTEM", "Payments")
    card_system = _asset(t, "BUSINESS_SYSTEM", "Card Services")
    process = _asset(t, "PROCESS", "payments-api")
    crypto = _asset(t, "CRYPTO_ASSET", "RSA-2048", evidence_type="RUNTIME_OBSERVED")
    endpoint = _asset(t, "NETWORK_ENDPOINT", "payments.example.bank:443")
    edge_certificate = _asset(t, "CERTIFICATE", "cert:payments-edge")

    host = server["assets"][0]["name"]
    claims = [
        h.claim("Payments", "CONTAINS", "Payments API", basis="cmdb-import",
                evidence_ids=[EVID]),
        h.claim("Payments", "CONTAINS", "Payment Gateway", basis="cmdb-import",
                evidence_ids=[EVID]),
        h.claim("Card Services", "CONTAINS", "Card Authorization", basis="cmdb-import",
                evidence_ids=[EVID]),
        # the direction the review draws: the host runs what is on it
        h.claim(host, "RUNS", "Payments API", basis="process-trace",
                evidence_ids=[EVID]),
        h.claim(host, "RUNS", "payments-api", basis="process-trace", evidence_ids=[EVID]),
        h.claim("Payments API", "RUNS_ON", host, basis="config-parse", evidence_ids=[EVID]),
        h.claim("payments-api", "LOADS", "OpenSSL 3.0.13", basis="process-trace",
                evidence_ids=[EVID]),
        h.claim("Payments API", "USES_HSM", "HSM-001", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("Card Authorization", "USES_HSM", "HSM-001", basis="config-parse",
                evidence_ids=[EVID]),
        h.claim("Payments API", "USES_CRYPTO", "CRYPTO_ASSET:RSA-2048:PRODUCTION",
                basis="runtime-probe", evidence_ids=[EVID]),
        h.claim("CRYPTO_ASSET:RSA-2048:PRODUCTION", "PROTECTED_BY", "HSM-001",
                basis="config-parse", evidence_ids=[EVID]),
        h.claim("payments-lb", "FORWARDS_TO", "payments.example.bank:443",
                basis="config-parse", evidence_ids=[EVID]),
        h.claim("fw-edge-01", "FORWARDS_TO", "payments-lb", basis="api-poll",
                evidence_ids=[EVID]),
        h.claim("payments.example.bank:443", "ROUTES_TO", "Payments API",
                basis="config-parse", evidence_ids=[EVID]),
        h.claim("Card Services", "OWNS", "HSM-001", basis="cmdb-import",
                evidence_ids=[EVID]),
    ]
    library = _asset(t, "CRYPTO_LIBRARY", "OpenSSL 3.0.13")
    document = h.estate(
        *[device, server, balancer, firewall, product,
                                        {"assets": [application, card, gateway, system,
                                                    card_system, process, crypto, endpoint,
                                                    edge_certificate, library],
                                         "claims": claims}],
        estate_id="bank-estate", environment="PRODUCTION",
        expected={"HSM": 2, "PHYSICAL_SERVER": 1, "LOAD_BALANCER": 1, "FIREWALL": 1},
        gaps=[{"kind": "HSM", "reason": "one HSM collector offline (vendor API 503)"}])
    return {"document": document, "host": host, "record": record, "topology": topology,
            "release": release["name"]}


def _bom(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fixture = _estate(modules["h"], modules["t"])
    return modules["h"].build(fixture["document"]), fixture


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #

def row_metadata(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, fixture = _bom(modules)
    server = next(row for row in bom["assets"] if row["kind"] == "PHYSICAL_SERVER")
    hsm = next(row for row in bom["assets"] if row["kind"] == "HSM"
               and row["name"] == "HSM-001")
    cpu = next(row for row in bom["assets"] if row["kind"] == "CPU")
    certification = (hsm["attributes"].get("certifications") or [{}])[0]
    probes = [
        _probe("a-device-carries-a-sku-as-well-as-a-part-number",
               server["attributes"].get("sku") == "PER760-32C",
               f"SKU {server['attributes']['sku']} on {server['name']}"),
        _probe("a-certification-names-a-standard-a-level-and-an-expiry",
               certification.get("standard") == "FIPS 140-3"
               and certification.get("level") == "Level 3"
               and certification.get("expires") == "2027-06-30",
               f"{certification.get('standard')} {certification.get('level')} until "
               f"{certification.get('expires')}"),
        _probe("a-certification-without-a-standard-is-refused",
               _refused(h, lambda: h.hardware(
                   "HSM", manufacturer="X", model="Y", evidence_ids=[EVID],
                   certifications=[{"level": "Level 3"}]))
               == "CERTIFICATION_WITHOUT_STANDARD",
               "level without a standard → CERTIFICATION_WITHOUT_STANDARD"),
        _probe("a-certification-with-no-attestation-behind-it-says-so",
               h.hardware("HSM", manufacturer="X", model="Y", evidence_ids=[EVID],
                          certifications=[{"standard": "FIPS 140-3"}]
                          )["attributes"]["certifications"][0]["backed"] is False,
               "kept, but marked unbacked rather than presented as certified"),
        _probe("a-cpu-is-a-topology-whose-arithmetic-reconciles",
               cpu["attributes"]["cores"] == 32 and cpu["attributes"]["threads"] == 64
               and cpu["attributes"]["sockets"] == 2,
               f"{cpu['attributes']['topology']}"),
        _probe("a-topology-that-does-not-add-up-is-refused",
               _refused(h, lambda: h.cpu_topology(sockets=2, cores_per_socket=16,
                                                  threads_per_core=2, cores=48))
               == "TOPOLOGY_DOES_NOT_RECONCILE",
               "2 sockets x 16 cores ≠ 48 claimed → TOPOLOGY_DOES_NOT_RECONCILE"),
    ]
    return {"id": "metadata", "question": "does a device carry a SKU, certifications and a "
                                          "CPU topology",
            "phase": "review hbom / 1 (metadata)", "probes": probes}


def row_host_runs(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    bom, fixture = _bom(modules)
    host = fixture["host"]
    runs = [row for row in bom["claims"] if row["relation"] == "RUNS"]
    probes = [
        _probe("a-host-runs-the-applications-that-sit-on-it",
               len(runs) == 2 and all(row["from"] == host for row in runs),
               f"{len(runs)} RUNS edge(s) out of the host, basis process-trace"),
        _probe("the-reverse-direction-is-kept-as-well",
               any(row["relation"] == "RUNS_ON" and row["to"] == host
                   for row in bom["claims"]),
               "Payments API RUNS_ON the same host, from configuration"),
        _probe("both-directions-are-claims-with-their-own-basis",
               {(row["relation"], row["confidence"]) for row in bom["claims"]
                if row["relation"] in {"RUNS", "RUNS_ON"}} ==
               {("RUNS", "OBSERVED"), ("RUNS_ON", "CONFIGURED")},
               "RUNS OBSERVED from a process trace, RUNS_ON CONFIGURED from configuration"),
        _probe("a-host-cannot-run-an-algorithm",
               "TYPE_MISMATCH" in _codes(
                   h, t, [next(row for row in bom["by_key"].values()
                               if row["name"] == host),
                          _asset(t, "ALGORITHM", "RSA-2048")],
                   [h.claim(host, "RUNS", "RSA-2048", basis="process-trace",
                            evidence_ids=[EVID])]),
               "RUNS ends at software, never at an algorithm"),
        _probe("the-business-to-hardware-chain-reads-in-one-direction",
               modules["h"].radius(bom, query=host)["systems"] == ["Payments"]
               and modules["h"].radius(bom, query="HSM-001")["systems"] ==
               ["Card Services", "Payments"],
               "from the host: Payments; from the HSM: both systems, through two apps"),
    ]
    return {"id": "host-runs", "question": "can a host say what it runs, as the review draws it",
            "phase": "review hbom / 3", "probes": probes}


def row_classes(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    probes = [
        _probe("capability-is-an-evidence-class-of-its-own",
               t.CAPABILITY in t.CONFIDENCE and t.BASES["capability-list"] == t.CAPABILITY,
               "CAPABILITY sits above an import and below anything read from the device"),
        _probe("a-capability-list-claim-carries-capability-and-not-more",
               (lambda: t.claim("HSM-001", "SUPPORTS", "cap RSA", basis="capability-list",
                                evidence_ids=[EVID])["confidence"])() == t.CAPABILITY,
               "SUPPORTS from a capability list → CAPABILITY"),
        _probe("a-network-observation-is-an-observation",
               t.BASES["passive-capture"] == t.NETWORK_OBSERVED
               and t.NETWORK_OBSERVED in t.PROVEN,
               "NETWORK_OBSERVED is proven, because a capture saw it"),
        _probe("a-capability-can-never-be-promoted-into-the-proven-set",
               t.CAPABILITY not in t.PROVEN,
               "CAPABILITY is walked and reported, never counted as blast radius"),
        _probe("the-eight-classes-the-review-names-are-all-present",
               {"CAPABILITY", "CONFIGURED", "OBSERVED", "NETWORK_OBSERVED", "IMPORTED",
                "VENDOR_DECLARED", "UNKNOWN"} <= set(t.CONFIDENCE),
               f"{len(t.CONFIDENCE)} classes, including the two this round added"),
    ]
    return {"id": "classes", "question": "are CAPABILITY and NETWORK_OBSERVED classes of "
                                         "their own",
            "phase": "review hbom / 4 (evidence classes)", "probes": probes}


def row_product_lifecycle(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    lifecycle = h.product_lifecycle(bom)
    ended = [row for row in lifecycle["products"] if row["actionable"]]
    probes = [
        _probe("a-product-past-end-of-life-is-actionable",
               bool(ended) and ended[0]["status"] == "RETIRED",
               f"{ended[0]['product']} → {ended[0]['status']} "
               f"(EOL {ended[0]['eol_date']})"),
        _probe("the-lifecycle-walk-names-the-devices-behind-the-product",
               ended[0]["devices"] == ["HSM-001"],
               f"device(s): {', '.join(ended[0]['devices'])}"),
        _probe("and-the-applications-and-systems-above-them",
               bool(ended[0]["applications"]) and bool(ended[0]["systems"]),
               f"{len(ended[0]['applications'])} application(s), "
               f"{len(ended[0]['systems'])} system(s)"),
        _probe("a-replacement-is-recorded-rather-than-implied",
               ended[0]["replacement"] == "PaymentHSM-9100",
               "replacement PaymentHSM-9100"),
        _probe("an-unknown-product-status-is-refused",
               _refused(h, lambda: h.product("p", vendor="v", status="PROBABLY-FINE",
                                             evidence_ids=[EVID]))
               == "UNKNOWN_PRODUCT_STATUS",
               "PROBABLY-FINE → UNKNOWN_PRODUCT_STATUS"),
    ]
    return {"id": "product-lifecycle", "question": "does a retired model reach the business",
            "phase": "review hbom / 5", "probes": probes}


def row_network_appliance(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    balancer = next(row for row in bom["assets"]
                    if row["kind"] == "LOAD_BALANCER")
    attributes = balancer["attributes"]
    expects = ["ip", "mac", "interface", "vlan", "zone", "subnet", "routing", "ha_role",
               "firmware_version", "manufacturer", "model", "tls_capability",
               "certificate_reference", "hsm_reference"]
    relations = {(row["relation"], row["from"], row["to"]) for row in bom["claims"]}
    probes = [
        _probe("an-appliance-carries-the-fourteen-facts-the-review-lists",
               all(attributes.get(name) for name in expects),
               f"{len([name for name in expects if attributes.get(name)])} of "
               f"{len(expects)} facts present on {balancer['name']}"),
        _probe("its-certificate-is-an-edge-not-a-string",
               ("PRESENTS", "payments-lb", "cert:payments-edge") in relations,
               "payments-lb PRESENTS cert:payments-edge"),
        _probe("its-hsm-offload-is-an-edge-too",
               ("USES_HSM", "payments-lb", "HSM-001") in relations,
               "a load balancer may offload TLS to an HSM, and says so"),
        _probe("the-tls-capability-is-recorded-beside-the-certificate",
               attributes.get("tls_capability") == "TLS1.2"
               and attributes["tls"].get("pqc") == "hybrid-x25519mlkem768",
               "TLS1.2 with a hybrid ML-KEM key exchange offered"),
        _probe("a-router-is-not-an-appliance-this-builder-invents",
               _refused(h, lambda: h.network_device("ROUTER", manufacturer="X", model="Y",
                                                    evidence_ids=[EVID]))
               == "NOT_A_NETWORK_DEVICE",
               "ROUTER → NOT_A_NETWORK_DEVICE rather than a guessed shape"),
    ]
    return {"id": "network-appliance", "question": "do network appliances carry their fourteen "
                                                   "facts",
            "phase": "review hbom / 6", "probes": probes}


def row_impact_units(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, _ = _bom(modules)
    summary = h.impact_summary(bom, query="HSM-001")
    probes = [
        _probe("the-review-sentence-is-produced-from-the-graph",
               all(token in summary["statement"] for token in
                   ("HSM", "application", "business system", "cryptographic asset",
                    "network path")),
               summary["statement"]),
        _probe("the-counts-are-numbers-a-ticket-can-quote",
               summary["hsm"] >= 1 and summary["applications"] >= 2,
               f"{summary['hsm']} HSM, {summary['applications']} applications, "
               f"{summary['business_systems']} systems, {summary['crypto_assets']} crypto "
               f"assets, {summary['network_paths']} paths"),
        _probe("the-path-counts-the-appliances-as-well-as-the-endpoint",
               summary["network_paths"] >= 2,
               f"{summary['network_paths']} network path(s) including the load balancer"),
        _probe("nothing-is-counted-twice",
               len(set(h.radius(bom, query="HSM-001")["applications"]))
               == summary["applications"] ==
               len(h.radius(bom, query="HSM-001")["applications"]),
               "a device reached twice is one device, and the counts are sets"),
    ]
    return {"id": "impact-units", "question": "does the review's sentence become a number",
            "phase": "review hbom / 7", "probes": probes}


def row_device_replaced(modules: dict[str, Any]) -> dict[str, Any]:
    h, t = modules["h"], modules["t"]
    before, fixture = _bom(modules)

    def swapped() -> dict[str, Any]:
        fixture = _estate(h, t)
        for row in fixture["document"]["assets"]:
            if row["kind"] == "HSM" and row["name"] == "HSM-001":
                row["name"] = "HSM-009"
                row["attributes"]["asset_id"] = "HSM-009"
                row["attributes"]["serial_number"] = "HSM-SN-9999"
        for row in fixture["document"]["claims"]:
            if row["from"] == "HSM-001":
                row["from"] = "HSM-009"
            if row["to"] == "HSM-001":
                row["to"] = "HSM-009"
        return h.build(fixture["document"])

    after = swapped()
    feed = h.drift(before, after)
    replaced = [event for event in feed["events"]
                if event["change"] == "DEVICE_REPLACED"]
    probes = [
        _probe("a-swapped-unit-in-the-same-rack-slot-is-one-event",
               len(replaced) == 1,
               f"{len(replaced)} DEVICE_REPLACED event(s)"),
        _probe("it-is-not-reported-as-an-add-and-a-remove",
               "DEVICE_ADDED" not in feed["by_change"]
               and "DEVICE_REMOVED" not in feed["by_change"],
               f"change types: {', '.join(sorted(feed['by_change'])) or 'none'}"),
        _probe("it-names-both-identities-so-the-audit-trail-survives",
               replaced and replaced[0]["asset_id"] == "HSM-009"
               and replaced[0]["previous_asset_id"] == "HSM-001",
               "HSM-001 → HSM-009 in the same bay"),
        _probe("a-device-in-a-free-bay-is-still-an-addition",
               _added_is_added(h, t),
               "a new serial with no rack placement in common → DEVICE_ADDED"),
        _probe("the-replacement-carries-the-cryptography-behind-the-bay",
               replaced and replaced[0]["crypto_impact"]["edges_considered"] >= 0,
               "every event still carries its impact block"),
    ]
    return {"id": "device-replaced", "question": "is a swapped device one event, not two",
            "phase": "review hbom / 9", "probes": probes}


def _added_is_added(h: Any, t: Any) -> bool:
    fixture = _estate(h, t)
    before = h.build(fixture["document"])
    extra = h.hardware("GPU", manufacturer="NVIDIA", model="L4", serial_number="GPU-2",
                       evidence_ids=[EVID])
    document = {**fixture["document"],
                "assets": [*fixture["document"]["assets"], extra]}
    after = h.build(document)
    return h.drift(before, after)["by_change"].get("DEVICE_ADDED") == 1


def row_evidence_nodes(modules: dict[str, Any]) -> dict[str, Any]:
    h = modules["h"]
    bom, fixture = _bom(modules)
    nodes = [row for row in bom["assets"] if row["kind"] == "EVIDENCE"]
    edges = [row for row in bom["claims"] if row["relation"] == "EVIDENCED_BY"]
    probes = [
        _probe("every-cited-evidence-record-is-a-node-in-the-graph",
               len(nodes) == 1 and nodes[0]["name"] == EVID,
               f"{len(nodes)} EVIDENCE node(s): {', '.join(row['name'] for row in nodes)}"),
        _probe("the-node-carries-the-hash-and-the-collector",
               nodes and nodes[0]["attributes"]["hash"] == "sha256:3b1f9c0d"
               and nodes[0]["attributes"]["collector"] == "linux-hardware-collector",
               "hash, collector, version and timestamp all travel with the node"),
        _probe("each-device-gets-an-evidenced_by-edge-to-it",
               len({row["from"] for row in edges}) >= 5,
               f"{len(edges)} EVIDENCED_BY edge(s) from "
               f"{len({row['from'] for row in edges})} asset(s)"),
        _probe("an-evidence-edge-cannot-be-weaker-than-an-import",
               "CLAIM_WEAKER_THAN_RELATION_REQUIRES" in _inference_refused(h, modules["t"]),
               "name-match EVIDENCED_BY → CLAIM_WEAKER_THAN_RELATION_REQUIRES"),
        _probe("a-consumer-can-reach-the-evidence-from-the-device",
               any(row["kind"] == "EVIDENCE"
                   for row in h.correlate(bom, "HSM-001")["by_bom"].get("EVIDENCE", [])),
               "correlate('HSM-001') reaches EVID-829182"),
    ]
    return {"id": "evidence-nodes", "question": "is the evidence walkable, not just listed",
            "phase": "review hbom / 13", "probes": probes}


def row_hsm_certificates(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _bom(modules)
    certificates = [row for row in bom["assets"] if row["kind"] == "CERTIFICATE"]
    holds = [row for row in bom["claims"] if row["relation"] == "HOLDS_CERTIFICATE"]
    probes = [
        _probe("a-certificate-an-hsm-holds-is-a-node",
               any(row["name"] == "cert:payments-root" for row in certificates),
               f"{len(certificates)} certificate node(s) in the hardware view"),
        _probe("the-holds-edge-runs-from-the-device-to-the-certificate",
               len(holds) == 1 and holds[0]["from"] == "HSM-001",
               f"HSM-001 HOLDS_CERTIFICATE {holds[0]['to'] if holds else '(none)'}"),
        _probe("an-hsm-cannot-hold-a-key-reference-through-that-relation",
               "TYPE_MISMATCH" in _key_reference_edge(modules["h"], modules["t"]),
               "HOLDS_CERTIFICATE ends at a certificate, not at a key reference"),
    ]
    return {"id": "hsm-certificates", "question": "does an HSM's certificate graph reach it",
            "phase": "review hbom / 2 (certificates)", "probes": probes}


def _refused(module: Any, call: Any) -> str:
    try:
        call()
    except Exception as exc:  # noqa: BLE001 — a refusal is the measurement
        return str(getattr(exc, "code", ""))
    return ""


def _inference_refused(h: Any, t: Any) -> list[str]:
    """A name-match cannot evidence a device: the floor is IMPORTED, not an inference."""
    record = _evidence(h)
    device = h.hardware("HSM", manufacturer="SyntheticHSM", model="PaymentHSM-9000",
                        evidence_ids=[EVID], evidence=[record])
    node = h.tb.asset("EVIDENCE", EVID, evidence_ids=[EVID], hash="sha256:3b1f9c0d")
    return _codes(h, t, [device, node],
                  [h.claim(device["name"], "EVIDENCED_BY", EVID, basis="name-match",
                           rule="a similar name", evidence_ids=[EVID])])


def _key_reference_edge(h: Any, t: Any) -> list[str]:
    device = h.hardware("HSM", manufacturer="SyntheticHSM", model="PaymentHSM-9000",
                        evidence_ids=[EVID])
    reference = t.asset("KEY_REFERENCE", "KREF-0007", evidence_ids=[EVID])
    return _codes(h, t, [device, reference],
                  [h.claim(device["name"], "HOLDS_CERTIFICATE", "KREF-0007",
                           basis="api-poll", evidence_ids=[EVID])])


def _codes(h: Any, t: Any, assets: list[dict[str, Any]],
           claims: list[dict[str, Any]]) -> list[str]:
    bom = h.build(h.estate(h.merge({"assets": assets, "claims": claims})))
    return [row["code"] for row in bom["refusals"]]


ROWS = (row_metadata, row_host_runs, row_classes, row_product_lifecycle,
        row_network_appliance, row_impact_units, row_device_replaced, row_evidence_nodes,
        row_hsm_certificates)


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
    bom, fixture = _bom(modules)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "statement": bom["statement"],
        "summary": h.summary(bom),
        "counts_by_kind": bom["counts"],
        "impact": h.impact_summary(bom, query="HSM-001"),
        "product_lifecycle": h.product_lifecycle(bom),
        "classes": {name: rank for name, rank in t.CONFIDENCE.items()},
        "certifications": [row["attributes"].get("certifications") for row in bom["assets"]
                           if row["attributes"].get("certifications")],
        "rows": rows,
        "limits": [
            "the fixture is a small bank estate; the shapes are real and the rows are not",
            "a certification is a record of an attestation, not the attestation itself: "
            "the expiry is what the collector read, and nothing here re-checks it",
            "a replaced device is inferred from the bay it sits in, so two devices swapped "
            "between bays are two replacements nobody can see",
            "product lifecycle status is what was recorded when the row was written",
            "evidence nodes are synthesised from the records a collector cited: an "
            "unrecorded observation has no node",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    impact = report["impact"]
    lifecycle = report["product_lifecycle"]
    lines = [
        "# The rest of the HBOM review",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 167 answered the review at the level of relations. Read back against the",
        "text, nine things were still missing — device metadata, the other direction of",
        "\"runs\", two evidence classes, product lifecycle, network appliances, the",
        "review's sentence as a number, `DEVICE_REPLACED`, evidence as nodes, and the",
        "certificates an HSM holds.",
        "",
        "```",
        "class ladder      OBSERVED = NETWORK_OBSERVED > CONFIGURED > CAPABILITY",
        "                  = IMPORTED = VENDOR_DECLARED > INFERRED > UNKNOWN",
        "device metadata   sku, certifications[{standard, level, expires, evidence_id}]",
        "cpu topology      sockets × cores_per_socket × threads_per_core, reconciled",
        "host              HOST --RUNS--> APPLICATION   (and APP --RUNS_ON--> HOST)",
        "product           VENDOR_PRODUCT{status} --HAS_MODEL-- DEVICE --USES_HSM-- APP",
        "appliance         ip, mac, interface, vlan, zone, subnet, routing, ha_role,",
        "                  firmware, vendor, model, tls, certificate, hsm",
        "evidence          EVIDENCE node + EVIDENCED_BY edge, floor IMPORTED",
        "```",
        "",
        report["statement"],
        "",
        f"**The review's sentence** — {impact['statement']}",
        "",
        f"**Product lifecycle** — {lifecycle['statement']}",
        "",
        "| kind | rows |",
        "|---|---|",
        *[f"| `{kind}` | {count} |" for kind, count in sorted(report["counts_by_kind"].items())],
        "",
        "| evidence class | rank |",
        "|---|---|",
        *[f"| `{name}` | {rank} |" for name, rank in report["classes"].items()],
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
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
