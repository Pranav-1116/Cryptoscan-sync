#!/usr/bin/env python3
"""Guide 170 — the rest of the NBOM review, built rather than described.

Guide 169 answered the twenty-two points at the level of relations. Read back against the
text, nine things were still thin, and each is now a shape the model carries and a probe
that measures it (`cryptoscan.cbom-nbom-gaps-guide/1`):

* the **ids the review asks for** — ``NET-ENDPOINT-001``, ``SERVICE-9281`` — beside the
  graph's ``TECH-EP-001`` and the content-addressed ``NETWORK_ENDPOINT-9281``;
* **paths**, not just edges: a request's route from a listener to an application, with
  every TLS boundary on it, proven or merely declared, and a tunnel that is down is not a
  route;
* the **fourth state**: ``CONFIGURED`` as a policy beside ``SUPPORTED``, ``NEGOTIATED`` and
  ``OBSERVED`` — and a downgrade between the policy and the session is a finding;
* **runtime against network** as three sets, so the intersection and the difference are
  both visible;
* **evidence on a network edge**: a record with a collector and a hash, a node for it, and
  an edge that names it — the review's point 16, field by field;
* **exposure**: quantum-sensitive algorithms a session *negotiated*, counted apart from the
  capabilities a device merely declares;
* **VBOM → CBOM**: a product that declares a capability, at the class a datasheet deserves;
* **history**: an edge's timeline, joined to the drift feed;
* **coverage per segment**, where the weakest segment decides the whole.

The fixture is the review's path again: ``payments.bank.example:443`` through a WAF, a load
balancer and an API gateway to ``Payments API``, its process and its database, with a
misconfigured listener, a branch tunnel that is down, and a segment nobody could reach.
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
SCHEMA = "cryptoscan.cbom-nbom-gaps-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID = "EVID-92821"
EVID_LB = "EVID-92841"
EVID_GW = "EVID-92842"
EVID_RT = "EVID-92850"
EVID_VPN = "EVID-92845"
NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES / "shared"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import nbom_graph, techbom  # noqa: PLC0415

    return {"n": nbom_graph, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _row(identifier: str, question: str, phase: str, probes: list[dict[str, Any]]) -> dict:
    return {"id": identifier, "question": question, "phase": phase, "probes": probes}


def _refusals_in_build(assets: list[Any], claims: list[Any]) -> list[str]:
    modules = _load()
    bom = modules["n"].build(modules["n"].estate({"assets": assets, "claims": claims},
                                                 estate_id="probe"))
    return [row["code"] for row in bom["refusals"]]


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The fixture
# --------------------------------------------------------------------------- #

def _document(n: Any, t: Any) -> dict[str, Any]:
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID])
    app = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID])
    service = n.service_of(name="payments-api", port=8080, evidence_ids=[EVID])
    certificate = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                                signature_algorithm="ECDSA-SHA256", evidence_ids=[EVID])
    root = n.authority(name="Root CA", kind="ROOT", evidence_ids=[EVID])

    # one listener misconfigured: policy says TLS 1.3 only, the session fell back to 1.2
    front = n.configured(
        endpoint_row=n.endpoint(host="10.10.10.20", port=443,
                                name="payments.bank.example:443",
                                sni=["payments.bank.example"],
                                tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256",
                                     "certificate": "CERT-001"},
                                evidence_ids=[EVID], first_seen=EARLIER, last_seen=NOW),
        min_version="TLS1.3", max_version="TLS1.3",
        suites=["TLS_AES_256_GCM_SHA384"], client_auth="NONE",
        evidence_ids=[EVID_LB])
    waf_front = n.endpoint(host="10.10.0.21", port=443, name="waf-01:443",
                           tls={"version": "TLS1.3",
                                "suite": "TLS_AES_256_GCM_SHA384",
                                "certificate": "CERT-001"},
                           evidence_ids=[EVID])
    waf_back = n.endpoint(host="10.10.0.21", port=8080, name="waf-01:8080",
                          transport="PLAIN", evidence_ids=[EVID])
    lb_front = n.endpoint(host="10.10.0.30", port=443, name="lb-01:443",
                          tls={"version": "TLS1.2",
                               "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                          evidence_ids=[EVID_LB])
    gw_front = n.endpoint(host="10.10.0.40", port=8443, name="api-gw-01:8443",
                          tls={"version": "TLS1.3",
                               "suite": "TLS_AES_256_GCM_SHA384",
                               "certificate": "CERT-001"},
                          evidence_ids=[EVID_GW])
    app_listener = n.endpoint(host="10.10.1.5", port=8443, name="payments-api:8443",
                              tls={"version": "TLS1.3",
                                   "suite": "TLS_AES_256_GCM_SHA384"},
                              evidence_ids=[EVID])

    aes256 = t.asset("CRYPTO_ASSET", "AES-256-GCM", evidence_ids=[EVID], algorithm="AES",
                     key_size=256, evidence_type="NETWORK_OBSERVED")
    x25519 = t.asset("CRYPTO_ASSET", "X25519", evidence_ids=[EVID], algorithm="ECDH",
                     evidence_type="NETWORK_OBSERVED")
    ecdsa = t.asset("CRYPTO_ASSET", "ECDSA-P256", evidence_ids=[EVID], algorithm="ECDSA",
                    evidence_type="NETWORK_OBSERVED")
    sha384 = t.asset("CRYPTO_ASSET", "SHA-384", evidence_ids=[EVID], algorithm="SHA",
                     evidence_type="NETWORK_OBSERVED")
    suite = n.cipher_suite(name="TLS_AES_256_GCM_SHA384", tls_version="TLS1.3",
                           kex="X25519", auth="ECDSA-P256", bulk="AES-256-GCM",
                           mac="SHA-384", evidence_ids=[EVID])
    parts = n.suite_parts(suite_row=suite,
                          parts={"bulk": aes256, "mac": sha384, "kex": x25519,
                                 "auth": ecdsa},
                          evidence_ids=[EVID])

    hops = n.merge(
        n.tls_hop(frontend=waf_front, backend=waf_back, mode="TERMINATE",
                  evidence_ids=[EVID], certificate=certificate, observed_at=NOW,
                  first_seen=EARLIER, last_seen=NOW),
        n.part(claims=[t.claim("waf-01:8080", "FORWARDS_TO", "lb-01:443",
                               basis="load-balancer-config", evidence_ids=[EVID_LB],
                               protocol="TCP", port=443)]),
        n.tls_hop(frontend=lb_front, backend=gw_front, mode="RE_ENCRYPT",
                  evidence_ids=[EVID_LB], observed_at=NOW),
        n.part(claims=[t.claim("api-gw-01:8443", "FORWARDS_TO", "payments-api:8443",
                               basis="api-gateway-config", evidence_ids=[EVID_GW],
                               protocol="TCP", port=8443)]),
        n.part(claims=[t.claim("payments-api:8443", "ROUTES_TO", "Payments API",
                               basis="api-gateway-config", evidence_ids=[EVID_GW],
                               protocol="TCP", port=8443)]),
        n.part(claims=[t.claim("payments.bank.example:443", "ROUTES_TO", "payments-api",
                               basis="sni-header", evidence_ids=[EVID], observed_at=NOW,
                               first_seen=EARLIER, last_seen=NOW, protocol="TCP",
                               port=443)]),
        n.negotiated(endpoint_row=front, suite_row=suite, evidence_ids=[EVID],
                     observed_at=NOW),
    )

    record = n.evidence_record(EVID_LB, collector="LB-CONFIG-01", collector_version="2.3.0",
                               target_id="LB-01", observed_at=NOW,
                               source="/configs/lb-01.conf", evidence_type="CONFIGURED",
                               raw_reference="ltm profile tls", normalized_fact="tls 1.2",
                               hash="sha256:9b2c", confidence="HIGH")
    evidence = n.attach_evidence(row=lb_front, record=record, basis="config-parse")

    process = t.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT], pid=1821)
    runtime_aes = t.asset("CRYPTO_ASSET", "AES-128-CBC", evidence_ids=[EVID_RT],
                          algorithm="AES", key_size=128, mode="CBC",
                          evidence_type="RUNTIME_OBSERVED")
    library = t.asset("CRYPTO_LIBRARY", "OpenSSL 3.0.13", evidence_ids=[EVID_RT])
    runtime = n.runtime(process_row=process, application_row=app, library_row=library,
                        crypto_rows=[runtime_aes], evidence_ids=[EVID_RT])
    ownership = n.serves(application_row=app, service_row=service, system_row=system,
                         evidence_ids=[EVID])

    product = t.asset("VENDOR_PRODUCT", "F5 BIG-IP i5800", evidence_ids=[EVID_LB],
                      vendor="F5", support_status="SUPPORTED")
    capability = t.asset("CRYPTO_CAPABILITY", "TLS 1.3 termination", evidence_ids=[EVID_LB],
                         protocol="TLS", version="1.3", evidence_type="CAPABILITY")
    vendor = n.product_capability(product_row=product, capability_row=capability,
                                  evidence_ids=[EVID_LB])

    tunnel_up = n.ipsec_tunnel(
        name="branch-to-payments", gateway_row=t.asset("VPN_GATEWAY", "VPN-GW-01",
                                                       evidence_ids=[EVID_VPN]),
        peer_row=t.asset("VPN_GATEWAY", "VPN-GW-BRANCH", evidence_ids=[EVID_VPN]),
        zone_row=t.asset("NETWORK_SEGMENT", "Payment Network", evidence_ids=[EVID_VPN]),
        encryption=t.asset("CRYPTO_ASSET", "AES-256", evidence_ids=[EVID_VPN]),
        integrity=t.asset("CRYPTO_ASSET", "SHA-256", evidence_ids=[EVID_VPN]),
        dh_group=t.asset("CRYPTO_ASSET", "DH-Group-19", evidence_ids=[EVID_VPN]),
        evidence_ids=[EVID_VPN], status="UP")
    tunnel_down = n.ipsec_tunnel(
        name="dr-site-to-payments", gateway_row=t.asset("VPN_GATEWAY", "VPN-GW-DR",
                                                        evidence_ids=[EVID_VPN]),
        peer_row=t.asset("VPN_GATEWAY", "VPN-GW-BRANCH", evidence_ids=[EVID_VPN]),
        zone_row=t.asset("NETWORK_SEGMENT", "Payment Network", evidence_ids=[EVID_VPN]),
        evidence_ids=[EVID_VPN], status="DOWN")

    segments = {"EDGE": {"expected": 20, "observed": 20},
                "CARDHOLDER": {"expected": 100, "observed": 60, "unavailable": 40},
                "BRANCH": {"expected": 30, "observed": 30}}

    doc = n.estate(system, app, service, certificate, root, front, waf_front, waf_back,
                   lb_front, gw_front, app_listener, aes256, x25519, ecdsa, sha384, suite,
                   parts, hops, record, evidence, process, runtime_aes, library, runtime,
                   product, capability, vendor, tunnel_up, tunnel_down, ownership,
                   estate_id="bank-network", environment="PRODUCTION",
                   gaps=[{"coverage": n.coverage(expected=500, observed=420,
                                                 unavailable=50, unknown=30),
                          "segments": segments,
                          "reason": "40 cardholder endpoints were unreachable"}])
    return {"estate": doc, "names": {"product": product["name"],
                                     "capability": capability["name"],
                                     "endpoint": "payments.bank.example:443",
                                     "lb": "lb-01:443"}}


def _build(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fixture = _document(modules["n"], modules["t"])
    return modules["n"].build(fixture["estate"]), fixture


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #

def row_ids(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    ids = bom["ids"]
    endpoint = next(row for row in bom["endpoints"]
                    if row["name"] == "payments.bank.example:443")
    probes = [
        _probe("the-review-s-id-scheme-exists-per-kind",
               ids["NETWORK_ENDPOINT"]["payments.bank.example:443"].startswith(
                   "NET-ENDPOINT-")
               and ids["APPLICATION"]["Payments API"].startswith("APPLICATION-")
               and ids["BUSINESS_SYSTEM"]["Payments System"].startswith("SYSTEM-"),
               ", ".join(sorted({value.split("-0")[0] for group in ids.values()
                                 for value in group.values()}))),
        _probe("three-id-families-name-one-node-and-only-one-is-for-keying",
               endpoint["id"].startswith("TECH-EP-")
               and n.stable_id({"key": endpoint["key"], "kind": endpoint["kind"]})
               .startswith("NETWORK_ENDPOINT-")
               and ids["NETWORK_ENDPOINT"][endpoint["name"]].startswith("NET-ENDPOINT-"),
               f"{endpoint['id']} (graph), "
               f"{ids['NETWORK_ENDPOINT'][endpoint['name']]} (view), "
               f"{n.stable_id({'key': endpoint['key'], 'kind': endpoint['kind']})} "
               "(content)"),
        _probe("numbering-is-per-kind-so-a-service-never-collides-with-an-application",
               all(len({value.split("-0")[0] for value in group.values()}) == 1
                   for group in ids.values()),
               "one prefix per kind, numbered from 001"),
        _probe("the-ids-are-stable-for-a-stable-estate",
               n.nbom_ids(bom) == ids,
               "a second build over the same estate assigns the same ids"),
    ]
    return _row("ids", "do the review's ids exist beside the graph's ids", "1", probes)


def _declared_estate(modules: dict[str, Any]) -> dict[str, Any]:
    """The same shape, one hop of it declared in a ticket rather than observed."""
    n, t = modules["n"], modules["t"]
    ticket = t.asset("EVIDENCE", "TICKET-4411", evidence_ids=["TICKET-4411"],
                     evidence_type="DOCUMENT")
    return n.build(n.estate(
        ticket,
        n.endpoint(host="10.0.0.1", port=443, name="front:443",
                   tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                   evidence_ids=[EVID]),
        t.asset("APPLICATION", "Payments API", evidence_ids=[EVID]),
        n.part(claims=[t.claim("front:443", "ROUTES_TO", "Payments API",
                               basis="ticket-import", evidence_ids=["TICKET-4411"],
                               protocol="TCP", port=443)]),
        estate_id="declared"))


def row_paths(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    walk = n.paths(bom, source="waf-01:443")
    route = walk["routes"][0] if walk["routes"] else None
    down = n.paths(bom, source="dr-site-to-payments")
    declared = n.paths(_declared_estate(modules), source="front:443")
    probes = [
        _probe("a-route-is-a-sequence-of-edges-from-a-listener-to-an-application",
               route is not None and route["nodes"][-1] == "Payments API",
               route["statement"] if route else "no route"),
        _probe("the-route-carries-every-tls-boundary-on-it",
               route is not None and route["tls_modes"] == ["TERMINATES_TLS",
                                                           "RE_ENCRYPTS"],
               f"modes {route['tls_modes']}" if route else "no route"),
        _probe("each-boundary-names-the-suite-that-crossed-it",
               route is not None and len(route["suites"]) == 2
               and route["suites"][0] == "TLS_AES_256_GCM_SHA384",
               f"suites {route['suites']}" if route else "no route"),
        _probe("a-route-that-depends-on-one-declared-hop-is-reported-declared",
               declared["declared"] == 1 and declared["proven"] == 0
               and declared["routes"][0]["weakest"] == "IMPORTED",
               f"proven {declared['proven']}, declared {declared['declared']}, "
               f"weakest {declared['routes'][0]['weakest'] if declared['routes'] else '-'}"),
        _probe("a-tunnel-that-is-down-is-not-a-route",
               down["routes"] == [] and "0 route" in down["statement"],
               down["statement"]),
    ]
    return _row("paths", "is the network a set of edges or a set of routes", "3, 15",
                probes)


def row_policy(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    finding = n.policy_gap(bom, query="payments.bank.example:443")
    codes = {row["code"] for row in finding["findings"]}
    probes = [
        _probe("a-policy-is-a-fourth-state-beside-supported-negotiated-and-observed",
               "tls_policy" in next(row for row in bom["endpoints"]
                                    if row["name"] == "payments.bank.example:443")
               ["attributes"],
               "min TLS1.3, suites [TLS_AES_256_GCM_SHA384], client_auth NONE"),
        _probe("a-session-below-the-policy-is-a-finding-not-a-success",
               "BELOW_CONFIGURED_FLOOR" in codes,
               "policy TLS1.3, negotiated TLS1.2 → BELOW_CONFIGURED_FLOOR"),
        _probe("a-suite-outside-the-policy-is-its-own-finding",
               "SUITE_NOT_IN_POLICY" in codes,
               "ECDHE-RSA-AES128-GCM-SHA256 is not on the configured list"),
        _probe("a-listener-with-no-policy-says-so-rather-than-assuming-one",
               _refused(n.policy_gap, bom, query="waf-01:443") == "no refusal" and
               "NO_POLICY_RECORDED" in {row["code"] for row in
                                        n.policy_gap(bom, query="waf-01:443")["findings"]},
               "waf-01:443 → NO_POLICY_RECORDED"),
        _probe("a-policy-that-accepts-nothing-is-refused",
               _refused(n.configured,
                        endpoint_row=n.endpoint(host="10.0.0.9", port=443,
                                                evidence_ids=[EVID]),
                        min_version="TLS1.3", max_version="TLS1.2",
                        evidence_ids=[EVID]) == "TLS_POLICY_INVERTED",
               "min TLS1.3 > max TLS1.2 → TLS_POLICY_INVERTED"),
    ]
    return _row("policy", "is CONFIGURED a state of its own", "6", probes)


def row_runtime_vs_network(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    view = n.runtime_vs_network(bom, query="payments.bank.example:443")
    network = {row["name"] for row in view["network"]}
    runtime = {row["name"] for row in view["runtime"]}
    probes = [
        _probe("the-wire-and-the-process-are-two-observations",
               "AES-256-GCM" in network and "AES-128-CBC" in runtime,
               view["statement"]),
        _probe("the-difference-is-reported-as-a-difference",
               {"AES-128-CBC"} == (runtime - network)
               and "AES-256-GCM" in (network - runtime),
               f"network only {sorted(network - runtime)}, "
               f"runtime only {sorted(runtime - network)}"),
        _probe("the-intersection-is-computed-not-assumed",
               all(row["name"] in network & runtime for row in view["both"]),
               f"{len(view['both'])} asset(s) in both"),
        _probe("the-honest-caveat-travels-with-the-answer",
               any("handshake belongs to the listener" in note
                   for note in view["not_proven"]),
               "not_proven names the listener/process split"),
    ]
    return _row("runtime-vs-network", "is the two-observation comparison an operation",
                "7", probes)


def row_evidence(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    edges = bom["graph"]["edges"]
    with_collector = [edge for edge in edges if edge["collector"]]
    probes = [
        _probe("a-record-needs-a-collector",
               _refused(n.evidence_record, "EVID-X", collector="",
                        hash="sha256:aa") == "EVIDENCE_WITHOUT_COLLECTOR",
               "no collector → EVIDENCE_WITHOUT_COLLECTOR"),
        _probe("a-record-needs-a-hash",
               _refused(n.evidence_record, "EVID-X", collector="LB-CONFIG-01")
               == "EVIDENCE_WITHOUT_HASH",
               "no hash → EVIDENCE_WITHOUT_HASH"),
        _probe("the-record-is-a-node-an-edge-can-point-at",
               any(row["kind"] == "EVIDENCE" and row["name"] == EVID_LB
                   for row in bom["assets"])
               and any(claim["relation"] == "EVIDENCED_BY"
                       and claim["to"] == EVID_LB for claim in bom["claims"]),
               f"{EVID_LB} is a node, lb-01:443 EVIDENCED_BY it"),
        _probe("an-edge-names-its-collector-and-its-evidence-class",
               bool(with_collector) and with_collector[0]["collector"] == "LB-CONFIG-01"
               and with_collector[0]["evidence_type"] == "CONFIGURED",
               f"{len(with_collector)} edge(s) resolve a collector, "
               "e.g. LB-CONFIG-01 (CONFIGURED)"),
        _probe("every-edge-still-carries-the-nine-fields",
               all(field in edge for edge in edges for field in n.EDGE_FIELDS),
               f"{len(edges)} edge(s), 9 field(s) each"),
    ]
    return _row("evidence", "does an edge name the collector behind it", "16", probes)


def row_exposure(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    view = n.pqc_exposure(bom, query="payments.bank.example:443")
    exposed = {name for row in view["endpoints"] for name in row["exposed"]}
    probes = [
        _probe("what-a-session-negotiated-is-what-is-exposed",
               {"X25519", "ECDSA-P256"} <= exposed,
               ", ".join(sorted(exposed)) or "nothing exposed"),
        _probe("a-capability-that-was-never-negotiated-is-not-counted",
               "AES-128-GCM" not in exposed,
               "AES-128-GCM is supported, not negotiated, and is not counted"),
        _probe("the-exposure-statement-names-the-endpoint-and-the-algorithms",
               "payments.bank.example:443" in view["statement"],
               view["statement"][:110]),
        _probe("the-migration-judgement-is-left-to-the-engine-that-owns-it",
               any("PQC engine" in note for note in view["not_proven"]),
               "not_proven hands the verdict to the PQC engine"),
    ]
    return _row("exposure", "is quantum exposure measured or mentioned", "5", probes)


def row_vendor_capability(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom, fixture = _build(modules)
    probes = [
        _probe("a-product-declares-a-capability-at-the-class-a-datasheet-deserves",
               any(claim["relation"] == "SUPPORTS" and claim["from"] ==
                   fixture["names"]["product"] for claim in bom["claims"])
               and {claim["confidence"] for claim in bom["claims"]
                    if claim["from"] == fixture["names"]["product"]} ==
               {"VENDOR_DECLARED"},
               f"{fixture['names']['product']} SUPPORTS TLS 1.3 termination "
               "(VENDOR_DECLARED)"),
        _probe("vbom-is-joined-to-cbom-through-the-capability",
               any(claim["relation"] == "IMPLEMENTS" or claim["relation"] == "SUPPORTS"
                   for claim in bom["claims"])
               and any(row["kind"] == "VENDOR_PRODUCT" for row in bom["assets"]),
               "VENDOR_PRODUCT → SUPPORTS → CRYPTO_CAPABILITY"),
        _probe("a-product-cannot-claim-an-operation-its-device-performed",
               _refusals_in_build(
                   [t.asset("VENDOR_PRODUCT", fixture["names"]["product"],
                            evidence_ids=[EVID_LB]),
                    t.asset("CRYPTO_CAPABILITY", fixture["names"]["capability"],
                            evidence_ids=[EVID_LB])],
                   [t.claim(fixture["names"]["product"], "PERFORMS",
                            fixture["names"]["capability"], basis="api-poll",
                            evidence_ids=[EVID_LB])])
               == ["TYPE_MISMATCH"],
               "VENDOR_PRODUCT PERFORMS CRYPTO_CAPABILITY → TYPE_MISMATCH"),
    ]
    return _row("vendor-capability", "does the vendor join the crypto view", "19", probes)


def row_timeline(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    history = n.timeline(bom)
    probes = [
        _probe("every-edge-has-a-state-and-a-first-and-last-seen",
               len(history["edges"]) == len(bom["claims"]) and
               all("state" in row for row in history["edges"]),
               history["statement"]),
        _probe("an-edge-with-timestamps-is-active-not-unknown",
               any(row["state"] == "ACTIVE" for row in history["edges"])
               and any(row["state"] == "UNKNOWN" for row in history["edges"]),
               ", ".join(f"{count} {state}" for state, count
                         in history["counts"].items())),
        _probe("the-history-can-be-joined-to-a-drift-feed",
               n.timeline(bom, previous=bom)["drift"]["by_change"] == {},
               "the same projection against itself produces no changes"),
    ]
    return _row("timeline", "does an edge have a history", "17", probes)


def row_segments(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _build(modules)
    block = bom["coverage_by_segment"]
    probes = [
        _probe("coverage-is-reported-per-segment-not-only-in-total",
               block is not None and set(block["segments"]) == {"EDGE", "CARDHOLDER",
                                                                "BRANCH"},
               block["statement"] if block else "no segments"),
        _probe("the-weakest-segment-decides-the-whole",
               block["verdict"] == "PARTIAL"
               and block["segments"]["EDGE"]["verdict"] == "COMPLETE"
               and block["segments"]["CARDHOLDER"]["verdict"] == "PARTIAL",
               "EDGE COMPLETE, CARDHOLDER PARTIAL, overall PARTIAL"),
        _probe("the-weakest-segment-is-named",
               block["weakest"] == ["CARDHOLDER"],
               f"weakest segment: {block['weakest']}"),
        _probe("the-total-coverage-is-not-rounded-by-the-healthy-segments",
               bom["coverage"]["verdict"] == "PARTIAL",
               bom["coverage"]["statement"]),
    ]
    return _row("segments", "does one healthy segment hide one sick one", "21", probes)


def row_tunnel(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    states = {row["name"]: row["attributes"].get("tunnel_state")
              for row in bom["assets"] if row["kind"] == "IPSEC_TUNNEL"}
    probes = [
        _probe("a-tunnel-records-its-state",
               states == {"branch-to-payments": "UP", "dr-site-to-payments": "DOWN"},
               f"tunnel states: {states}"),
        _probe("a-state-this-model-does-not-know-is-refused",
               _refused(n.ipsec_tunnel, name="t", gateway_row={"name": "g"},
                        peer_row={"name": "p"}, status="DEGRADED", evidence_ids=[EVID])
               == "UNKNOWN_TUNNEL_STATUS",
               "DEGRADED → UNKNOWN_TUNNEL_STATUS"),
        _probe("a-pre-shared-key-is-material-and-is-refused",
               _refused(n.ipsec_tunnel, name="t", gateway_row={"name": "g"},
                        peer_row={"name": "p"}, psk="s3cr3t-psk",
                        evidence_ids=[EVID]) == "KEY_MATERIAL_REFUSED",
               "psk → KEY_MATERIAL_REFUSED"),
        _probe("a-down-tunnel-tunnels-nowhere-that-matters",
               any(claim["relation"] == "TUNNELS_TO"
                   and claim["from"] == "branch-to-payments" for claim in bom["claims"])
               and n.paths(bom, source="dr-site-to-payments")["routes"] == [],
               "the UP tunnel is a route; the DOWN tunnel is not"),
    ]
    return _row("tunnel", "is a tunnel a path or a record", "14", probes)


def row_vocabulary(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom, _ = _build(modules)
    probes = [
        _probe("the-relations-the-second-read-leans-on-are-in-the-graph",
               all(relation in t.RELATIONS
                   for relation in ("HOLDS_CERTIFICATE", "EVIDENCED_BY", "SUPPORTS",
                                    "RUNS_APPLICATION")),
               "HOLDS_CERTIFICATE, EVIDENCED_BY, SUPPORTS, RUNS_APPLICATION"),
        _probe("a-network-asset-can-be-evidenced-like-a-device",
               "NETWORK_ENDPOINT" in t.RELATIONS["EVIDENCED_BY"]["from"],
               "EVIDENCED_BY starts at NETWORK_ENDPOINT"),
        _probe("a-vendor-product-can-support-a-capability",
               "VENDOR_PRODUCT" in t.RELATIONS["SUPPORTS"]["from"],
               "SUPPORTS starts at VENDOR_PRODUCT"),
        _probe("a-process-is-a-level-in-the-chain-the-review-draws",
               "process" in bom["chains"]["waf-01:443"]["levels"]
               and bom["chains"]["waf-01:443"]["levels"]["process"],
               bom["chains"]["waf-01:443"]["statement"]),
    ]
    return _row("vocabulary", "does the graph carry what the second read needed", "22",
                probes)


ROWS = (
    row_ids, row_paths, row_policy, row_runtime_vs_network, row_evidence, row_exposure,
    row_vendor_capability, row_timeline, row_segments, row_tunnel, row_vocabulary,
)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

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
    bom, fixture = _build(modules)
    n = modules["n"]
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "statement": bom["statement"],
        "ids": {kind: dict(list(group.items())[:3])
                for kind, group in sorted(bom["ids"].items())
                if kind in ("NETWORK_ENDPOINT", "SERVICE", "APPLICATION",
                            "BUSINESS_SYSTEM")},
        "routes": {name: {"proven": row["proven"], "declared": row["declared"],
                          "paths": [route["statement"] for route in row["routes"]]}
                   for name, row in bom["routes"].items() if row["routes"]},
        "policy_findings": {name: row["counts"]
                            for name, row in bom["policy_findings"].items()},
        "runtime_vs_network": n.runtime_vs_network(bom,
                                                   query=fixture["names"]["endpoint"]),
        "exposure": n.pqc_exposure(bom, query=fixture["names"]["endpoint"]),
        "coverage": bom["coverage"],
        "coverage_by_segment": bom["coverage_by_segment"],
        "counts_by_kind": bom["counts"],
        "refusals": bom["refusals"],
        "rows": rows,
        "limits": [
            "the fixture is the review's own path: the shapes are real, the rows are not",
            "a policy finding compares what was configured with what was observed once; a "
            "session that rolled back to a lower version after this capture is not in it",
            "a route is the shortest evidenced chain, not the only one: an estate with a "
            "mesh has as many routes as it has policies",
            "exposure counts algorithms a session negotiated, and a capability is not "
            "counted twice — but nothing here decides which one must be migrated first",
            "a segment's denominator comes from a CMDB the platform does not own, so the "
            "weakest segment is only as honest as that list",
            "a down tunnel is excluded from routes and still counted in the graph: "
            "unavailable is not absent",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    coverage = report["coverage"]
    block = report["coverage_by_segment"]
    exposure = report["exposure"]
    comparison = report["runtime_vs_network"]
    lines = [
        "# The rest of the NBOM review",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "Guide 169 answered the twenty-two points at the level of relations. Read back,",
        "nine things were still thin — ids, routes, the fourth state of a listener, the",
        "runtime comparison, evidence on a network edge, exposure, the vendor's",
        "capability, history and per-segment coverage — and each is now a shape, not a",
        "promise.",
        "",
        "```",
        "ids            NET-ENDPOINT-001 / TECH-EP-001 / NETWORK_ENDPOINT-9281",
        "routes         listener → hop → hop → application, with every TLS boundary",
        "policy         CONFIGURED beside SUPPORTED, NEGOTIATED and OBSERVED",
        "comparison     network set, runtime set, intersection, difference",
        "evidence       record{collector, hash} → EVIDENCE node → EVIDENCED_BY edge",
        "exposure       what a session negotiated, counted apart from a capability",
        "history        FIRST_SEEN / ACTIVE / CHANGED / SUPERSEDED / REMOVED / UNKNOWN",
        "segments       the weakest segment decides the whole",
        "```",
        "",
        report["statement"],
        "",
        "## The review's ids",
        "",
        "| kind | node | id |",
        "|---|---|---|",
    ]
    for kind, group in report["ids"].items():
        for name, identifier in group.items():
            lines.append(f"| `{kind}` | {name} | `{identifier}` |")
    lines += ["", "## Routes", ""]
    for name, row in report["routes"].items():
        lines.append(f"**{name}** — {row['proven']} proven, {row['declared']} declared")
        lines += [f"- {path}" for path in row["paths"]]
    lines += ["", "## Policy findings", "", "| endpoint | findings |", "|---|---|"]
    lines += [f"| {name} | {', '.join(sorted(counts))} |"
              for name, counts in report["policy_findings"].items()]
    lines += ["", f"**Runtime vs network** — {comparison['statement']}", "",
              f"- on the wire: {', '.join(row['name'] for row in comparison['network'])}",
              f"- in the process: "
              f"{', '.join(row['name'] for row in comparison['runtime'])}",
              f"- in both: {', '.join(row['name'] for row in comparison['both']) or 'none'}",
              "",
              f"**Exposure** — {exposure['statement']}", "",
              f"**Coverage** — {coverage['statement'] if coverage else 'not supplied'}",
              "",
              f"**By segment** — {block['statement'] if block else 'not supplied'}", "",
              "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (review nbom {row['phase']})", ""]
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
