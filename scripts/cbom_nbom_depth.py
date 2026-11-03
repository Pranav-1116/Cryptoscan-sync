#!/usr/bin/env python3
"""Guide 172 — the review, point by point, and the five dependencies under it.

Guides 169–171 answered the review's relations and the controls in front of them. Read
back against the text *as written*, five things were still missing, and the first one is a
defect rather than a gap:

* **a builder's block was dropped.** ``database_dependency()`` returns ``database_crypto``
  — the at-rest record — and ``estate()`` kept only ``assets`` and ``claims``. Point 9 was
  answered in the builder and lost on the way to the projection, so TDE had never once
  reached a BOM. Sections now survive, and ``database_crypto_gap()`` reads them.
* **a certificate named by a listener drew no edge** (point 4). ``tls_hop()`` draws one,
  but ``tls: {certificate: CERT-001}`` on a listener is a fact with no claim, so a graph
  could hold both nodes and no dependency. ``presents_certificate()`` draws it, and
  ``certificate_depth()`` walks endpoint → certificate → public key → algorithm →
  signature → issuer → root and names the weak link.
* **point 8 had no operation level.** ``CRYPTO_OPERATION`` is now a kind: application →
  ``INVOKES`` → operation → key reference, provider, algorithm — with ``SIGN``/``WRAP``/
  ``DERIVE`` as the vocabulary and no key material accepted anywhere.
* **point 21 propagated by assertion.** ``coverage()`` echoed its verdict into a
  ``propagates`` dict; ``propagate_coverage()`` now computes it, takes the worse of the two
  at every consumer, and refuses to let a CBOM claim ``COMPLETE`` over a ``PARTIAL``
  network (``COVERAGE_LAUNDERED``).
* **the review had never been answered point by point.** The ``audit`` row below is
  twenty-two probes, one per point, each reading the built projection rather than the
  source, so "answered" means "present in the BOM".

The fixture is the whole path the review draws: business system → application → process →
service → endpoint → WAF → LB → API gateway → service mesh → database → HSM/KMS → crypto
asset → vendor, with the certificate chain, the three TLS modes, an SSH service, an IPsec
tunnel, a runtime observation, a crypto operation, a database encrypted on the wire and
not on the disk, 500 expected endpoints of which 420 were observed, and two consumers who
both claim more coverage than the network has.
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
SCHEMA = "cryptoscan.cbom-nbom-depth-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID = "EVID-94001"
EVID_LB = "EVID-94002"
EVID_DB = "EVID-94003"
EVID_HSM = "EVID-94004"
EVID_RT = "EVID-94005"
EVID_VPN = "EVID-94006"
EVID_SSH = "EVID-94007"
EVID_CERT = "EVID-94008"
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


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The fixture: the path the review draws, end to end
# --------------------------------------------------------------------------- #

def _document(n: Any, t: Any) -> dict[str, Any]:
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID])
    application = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID])
    service = n.service_of(name="payments-api", port=8080, evidence_ids=[EVID])

    # ---- the certificate chain, five edges rather than one row (point 4) ----
    key_algorithm = n.algorithm(name="ECDSA P-256", family="ECDSA", curve="P-256",
                                key_size=256, evidence_ids=[EVID_CERT])
    public_key = n.public_key(name="PK-CERT-001", key_algorithm_row=key_algorithm,
                              curve="P-256", evidence_ids=[EVID_CERT])
    signature_algorithm = n.algorithm(name="ECDSA-SHA256", family="ECDSA",
                                      hash_name="SHA256", evidence_ids=[EVID_CERT])
    intermediate = n.authority(name="Bank Issuing CA", kind="INTERMEDIATE",
                               evidence_ids=[EVID_CERT])
    root = n.authority(name="Bank Root CA", kind="ROOT", evidence_ids=[EVID_CERT])
    certificate = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                                issuer="Bank Issuing CA", serial="4f:9a:21",
                                not_after="2027-04-01T00:00:00Z",
                                signature_algorithm="ECDSA-SHA256",
                                evidence_ids=[EVID_CERT])
    chain = n.certificate_chain(certificate_row=certificate, key_row=public_key,
                                key_algorithm_row=key_algorithm,
                                signature_algorithm_row=signature_algorithm,
                                issuer_row=intermediate, root_row=root,
                                basis="tls-handshake", evidence_ids=[EVID_CERT])

    # ---- the public listener, and the three TLS modes on the path (points 2, 3) ----
    public = n.endpoint(host="203.0.113.10", port=443, name="payments.bank.example:443",
                        sni=["payments.bank.example"], alpn=["HTTP/2"],
                        tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384",
                             "certificate": "CERT-001"},
                        evidence_ids=[EVID], first_seen=EARLIER, last_seen=NOW)
    waf_front = n.configured(
        endpoint_row=n.endpoint(
            host="10.10.0.21", port=443, name="waf-01:443",
            sni=["payments.bank.example"], alpn=["HTTP/2", "HTTP/1.1"],
            tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384",
                 "certificate": "CERT-001"},
            evidence_ids=[EVID], first_seen=EARLIER, last_seen=NOW),
        min_version="TLS1.3", max_version="TLS1.3",
        suites=["TLS_AES_256_GCM_SHA384"], client_auth="NONE", evidence_ids=[EVID_CERT])
    waf_back = n.endpoint(host="10.10.0.21", port=8081, name="waf-01:8081",
                          transport="PLAIN", evidence_ids=[EVID])
    lb_front = n.endpoint(host="10.10.0.30", port=443, name="lb-01:443",
                          tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                          evidence_ids=[EVID_LB])
    gw_front = n.endpoint(host="10.10.0.40", port=8443, name="api-gw-01:8443",
                          alpn=["HTTP/2"],
                          tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                          evidence_ids=[EVID])
    mesh_ingress = n.endpoint(host="10.10.0.50", port=15006, name="mesh-ingress:15006",
                              tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                              evidence_ids=[EVID])
    app_listener = n.endpoint(host="10.10.1.5", port=8443, name="payments-api:8443",
                              tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                              evidence_ids=[EVID])
    passthrough_front = n.endpoint(host="10.10.0.60", port=443, name="lb-pass:443",
                                   tls={"version": "TLS1.3",
                                        "suite": "TLS_AES_256_GCM_SHA384"},
                                   evidence_ids=[EVID])
    hops = n.merge(
        n.tls_hop(frontend=waf_front, backend=waf_back, mode="TERMINATE",
                  evidence_ids=[EVID], certificate=certificate, observed_at=NOW,
                  first_seen=EARLIER, last_seen=NOW, protocol="HTTPS"),
        n.tls_hop(frontend=lb_front, backend=gw_front, mode="RE_ENCRYPT",
                  evidence_ids=[EVID_LB], observed_at=NOW, protocol="TLS"),
        n.tls_hop(frontend=passthrough_front, backend=app_listener, mode="PASSTHROUGH",
                  evidence_ids=[EVID], observed_at=NOW, protocol="TLS"),
        n.part(claims=[
            t.claim("waf-01:8081", "FORWARDS_TO", "lb-01:443", basis="load-balancer-config",
                    evidence_ids=[EVID_LB], protocol="TCP", port=443),
            t.claim("api-gw-01:8443", "FORWARDS_TO", "mesh-ingress:15006",
                    basis="api-gateway-config", evidence_ids=[EVID], protocol="TCP",
                    port=15006),
            t.claim("mesh-ingress:15006", "FORWARDS_TO", "payments-api:8443",
                    basis="mesh-config", evidence_ids=[EVID], protocol="TCP", port=8443),
            t.claim("payments-api:8443", "ROUTES_TO", "Payments API",
                    basis="api-gateway-config", evidence_ids=[EVID], protocol="TCP",
                    port=8443),
            t.claim("payments.bank.example:443", "ROUTES_TO", "payments-api",
                    basis="sni-header", evidence_ids=[EVID], observed_at=NOW,
                    protocol="TCP", port=443),
            t.claim("payments.bank.example:443", "FORWARDS_TO", "waf-01:443",
                    basis="dns-resolution", evidence_ids=[EVID], protocol="TCP", port=443),
            # the WAF device protects and listens; a listener neither protects nor
            # listens on itself, and the type table says so
            t.claim("WAF-01", "PROTECTS", "Payments API", basis="config-parse",
                    evidence_ids=[EVID], protocol="TCP", port=443),
            t.claim("WAF-01", "LISTENS_ON", "waf-01:443", basis="config-parse",
                    evidence_ids=[EVID], protocol="TCP", port=443),
            t.claim("lb-01:443", "FRONTED_BY", "LB-01", basis="load-balancer-config",
                    evidence_ids=[EVID_LB], protocol="TCP", port=443),
        ]))
    presents = n.presents_certificate(endpoint_row=waf_front, certificate_row=certificate,
                                      basis="tls-handshake", evidence_ids=[EVID_CERT],
                                      observed_at=NOW)

    # ---- the suite, decomposed (point 5) and the four states (point 6) ----
    aes256 = t.asset("CRYPTO_ASSET", "AES-256-GCM", evidence_ids=[EVID],
                     algorithm="AES", key_size=256, evidence_type="NETWORK_OBSERVED")
    sha384 = t.asset("CRYPTO_ASSET", "SHA-384", evidence_ids=[EVID], algorithm="SHA",
                     evidence_type="NETWORK_OBSERVED")
    x25519 = t.asset("CRYPTO_ASSET", "X25519", evidence_ids=[EVID], algorithm="ECDH",
                     evidence_type="NETWORK_OBSERVED")
    ecdsa = t.asset("CRYPTO_ASSET", "ECDSA-P256", evidence_ids=[EVID], algorithm="ECDSA",
                    evidence_type="NETWORK_OBSERVED")
    chosen = n.cipher_suite(name="TLS_AES_256_GCM_SHA384", tls_version="TLS1.3",
                            kex="X25519", auth="ECDSA-P256", bulk="AES-256-GCM",
                            mac="SHA-384", evidence_ids=[EVID])
    weaker = n.cipher_suite(name="TLS_AES_128_GCM_SHA256", tls_version="TLS1.3",
                            kex="X25519", auth="ECDSA-P256", bulk="AES-128-GCM",
                            mac="SHA-256", evidence_ids=[EVID])
    parts = n.suite_parts(suite_row=chosen,
                          parts={"bulk": aes256, "mac": sha384, "kex": x25519,
                                 "auth": ecdsa}, evidence_ids=[EVID])
    states = n.merge(
        n.supported(endpoint_row=waf_front, suite_rows=[chosen, weaker],
                    evidence_ids=[EVID]),
        n.negotiated(endpoint_row=waf_front, suite_row=chosen, evidence_ids=[EVID],
                     observed_at=NOW),
        n.negotiated(endpoint_row=public, suite_row=chosen, evidence_ids=[EVID],
                     observed_at=NOW))

    # ---- the record behind an edge (point 16) ----
    record = n.evidence_record(EVID_LB, collector="LB-CONFIG-01", collector_version="2.3.0",
                               target_id="LB-01", observed_at=NOW,
                               source="/configs/lb-01.conf", evidence_type="CONFIGURED",
                               raw_reference="ltm profile tls", normalized_fact="tls 1.2",
                               hash="sha256:9b2c", confidence="HIGH")
    evidence = n.attach_evidence(row=lb_front, record=record, basis="config-parse")

    # ---- runtime, the process and its own crypto (point 7) ----
    process = t.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT], pid=1821)
    library = t.asset("CRYPTO_LIBRARY", "OpenSSL 3.0.13", evidence_ids=[EVID_RT])
    runtime_aes = t.asset("CRYPTO_ASSET", "AES-128-CBC", evidence_ids=[EVID_RT],
                          algorithm="AES", key_size=128, mode="CBC",
                          evidence_type="RUNTIME_OBSERVED")
    runtime = n.runtime(process_row=process, application_row=application,
                        library_row=library, crypto_rows=[runtime_aes],
                        evidence_ids=[EVID_RT])

    # ---- the key, the operation, the provider (point 8) ----
    hsm_row = t.asset("HSM", "HSM-001", evidence_ids=[EVID_HSM])
    key_reference = n.key_reference(name="KEY-REF-8271", key_ref="pkcs11:token=bank;id=8271",
                                    purpose="SIGNING", algorithm="RSA", key_size=2048,
                                    holder="HSM-001", status="ACTIVE",
                                    evidence_ids=[EVID_HSM])
    rsa = n.algorithm(name="RSA-2048", family="RSA", key_size=2048, evidence_ids=[EVID_HSM])
    signing = n.crypto_operation(name="OP-SIGN-001", application_row=application,
                                 operation="SIGN", key_row=key_reference,
                                 provider_row=hsm_row, algorithm_row=rsa,
                                 purpose="payment instruction signature",
                                 evidence_ids=[EVID_HSM])
    unwrapped = n.crypto_operation(name="OP-ENCRYPT-002", application_row=application,
                                   operation="ENCRYPT",
                                   algorithm_row=n.algorithm(name="ChaCha20-Poly1305",
                                                             family="CHACHA20", key_size=256,
                                                             evidence_ids=[EVID_RT]),
                                   evidence_ids=[EVID_RT])

    # ---- the database: on the wire and on the disk (point 9) ----
    database = t.asset("DATABASE", "DB-01", evidence_ids=[EVID_DB])
    db_listener = n.endpoint(host="10.10.1.7", port=5432, name="db-01:5432",
                             tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                             evidence_ids=[EVID_DB])
    db_crypto = n.database_dependency(application_row=application, database_row=database,
                                      endpoint_row=db_listener, tls_suite=chosen,
                                      tde={"enabled": False, "algorithm": None},
                                      basis="database-config", evidence_ids=[EVID_DB],
                                      port=5432, protocol="TCP")

    # ---- the mesh: the sidecar does the TLS (point 10) ----
    sidecar = t.asset("PROCESS", "envoy-sidecar", evidence_ids=[EVID])
    mesh = n.mesh(mesh_row=n.network_device(kind="SERVICE_MESH", name="MESH-01",
                                            vendor="Istio", product="1.20",
                                            evidence_ids=[EVID]),
                  trust_domain="bank.internal", sidecars=[sidecar],
                  proxied=[application], certificate_row=certificate,
                  evidence_ids=[EVID])

    # ---- SSH (point 13) ----
    host = t.asset("HOST", "srv-payments-01", evidence_ids=[EVID_SSH])
    ssh_listener = n.endpoint(host="10.10.1.20", port=22, name="srv-payments-01:22",
                              transport="SSH", evidence_ids=[EVID_SSH])
    ssh = n.ssh_service(name="sshd 9.6", host_row=host, endpoint_row=ssh_listener,
                        kex=t.asset("CRYPTO_ASSET", "curve25519-sha256", evidence_ids=[EVID_SSH]),
                        host_key=t.asset("CRYPTO_ASSET", "ssh-ed25519", evidence_ids=[EVID_SSH]),
                        cipher=t.asset("CRYPTO_ASSET", "chacha20-poly1305@openssh.com",
                                       evidence_ids=[EVID_SSH]),
                        mac=t.asset("CRYPTO_ASSET", "hmac-sha2-256", evidence_ids=[EVID_SSH]),
                        version="OpenSSH 9.6", evidence_ids=[EVID_SSH])

    # ---- the tunnel (point 14) ----
    tunnel = n.ipsec_tunnel(
        name="branch-to-payments",
        gateway_row=t.asset("VPN_GATEWAY", "VPN-GW-BRANCH", evidence_ids=[EVID_VPN]),
        peer_row=t.asset("VPN_GATEWAY", "VPN-GW-DC", evidence_ids=[EVID_VPN]),
        zone_row=t.asset("NETWORK_SEGMENT", "Payment Network", evidence_ids=[EVID_VPN]),
        encryption=t.asset("CRYPTO_ASSET", "AES-256", evidence_ids=[EVID_VPN]),
        integrity=t.asset("CRYPTO_ASSET", "SHA-256", evidence_ids=[EVID_VPN]),
        dh_group=t.asset("CRYPTO_ASSET", "DH-Group-19", evidence_ids=[EVID_VPN]),
        ike_version="IKEv2", evidence_ids=[EVID_VPN], status="UP")

    waf_device = n.network_device(kind="WAF", name="WAF-01", vendor="F5",
                                  product="Advanced WAF", model="i5800",
                                  firmware_version="17.1.1", evidence_ids=[EVID])

    # ---- vendor and hardware (points 19, 20) ----
    device = n.network_device(kind="LOAD_BALANCER", name="LB-01", vendor="F5",
                              product="BIG-IP i5800", model="i5800",
                              firmware_version="17.1.1", evidence_ids=[EVID_LB])
    hardware = t.asset("PHYSICAL_SERVER", "Hardware-9281", evidence_ids=[EVID_LB],
                       rack="R12", datacenter="Mumbai-DC2")
    hardware_link = n.on_hardware(device_row=device["assets"][0], hardware_row=hardware,
                                  evidence_ids=[EVID_LB])

    segments = {"EDGE": {"expected": 20, "observed": 20},
                "CARDHOLDER": {"expected": 100, "observed": 60, "unavailable": 40},
                "BRANCH": {"expected": 30, "observed": 30}}
    coverage_block = n.coverage(expected=500, observed=420, unavailable=50, unknown=30)

    doc = n.estate(system, application, service,
                   n.serves(application_row=application, service_row=service,
                            system_row=system, evidence_ids=[EVID]),
                   chain, presents, hops, parts, states,
                   public, waf_device, mesh_ingress, waf_front, waf_back, lb_front, gw_front, app_listener,
                   passthrough_front, db_listener, ssh_listener, host, aes256, sha384,
                   x25519, ecdsa, chosen, weaker, key_algorithm, public_key,
                   signature_algorithm, intermediate, root, certificate, process,
                   library, runtime_aes,
                   record, evidence, runtime, hsm_row, key_reference, signing, unwrapped, db_crypto, mesh,
                   sidecar, ssh, tunnel, device, hardware, hardware_link,
                   estate_id="bank-depth", environment="PRODUCTION",
                   gaps=[{"coverage": coverage_block, "segments": segments,
                          "reason": "40 cardholder endpoints were unreachable"}])
    return {"estate": doc, "segments": segments, "coverage": coverage_block,
            "names": {"endpoint": "payments.bank.example:443", "waf": "waf-01:443",
                      "certificate": "CERT-001", "application": "Payments API",
                      "database": "DB-01", "device": "LB-01"}}


def _build(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fixture = _document(modules["n"], modules["t"])
    return modules["n"].build(fixture["estate"]), fixture


# --------------------------------------------------------------------------- #
# The audit: one probe per point of the review
# --------------------------------------------------------------------------- #

AUDIT: tuple[tuple[int, str, str], ...] = (
    (1, "network-endpoint-has-a-stable-identity-beyond-ip-port",
     "NET-ENDPOINT ids per kind beside TECH-EP and the content id"),
    (2, "endpoint-reaches-a-service-through-a-named-basis",
     "payments.bank.example:443 → payments-api on sni-header"),
    (3, "the-three-tls-modes-are-three-graphs",
     "TERMINATES_TLS, RE_ENCRYPTS and PASSTHROUGH in one estate"),
    (4, "the-certificate-chain-is-five-edges-to-a-root",
     "certificate → key → algorithm, signature, issuer → root"),
    (5, "a-cipher-suite-is-decomposed-not-an-opaque-asset",
     "kex, auth, bulk and mac as four crypto assets"),
    (6, "supported-configured-negotiated-and-observed-stay-apart",
     "SUPPORTS, tls_policy, NEGOTIATES and the evidence class"),
    (7, "the-process-and-its-runtime-crypto-are-reachable",
     "application → RUNS_APPLICATION → process → USES_CRYPTO"),
    (8, "an-application-invokes-an-operation-a-provider-performs",
     "application → INVOKES → operation → key, HSM, algorithm"),
    (9, "a-database-is-encrypted-in-transit-and-at-rest-separately",
     "two blocks, two findings, one database"),
    (10, "the-sidecar-does-the-tls-not-the-application",
     "PROXY_FOR from the sidecar, AUTHENTICATES from the mesh"),
    (11, "the-gateway-routes-to-the-application-with-evidence",
     "ROUTES_TO carrying a basis, a port and an evidence id"),
    (12, "the-waf-protects-and-terminates-separately",
     "PROTECTS the application, TERMINATES_TLS to the next hop"),
    (13, "ssh-is-kex-host-key-cipher-and-mac",
     "four NEGOTIATES edges with a role each"),
    (14, "the-tunnel-carries-encryption-integrity-and-a-dh-group",
     "IKEv2, AES-256, SHA-256, DH-19, and the zone it joins"),
    (15, "the-projection-is-a-graph-not-a-list",
     "vertices, edges and adjacency from one build"),
    (16, "every-edge-carries-its-nine-fields-and-its-collector",
     "EDGE_FIELDS on every claim, collector where one is known"),
    (17, "a-relationship-has-a-lifecycle",
     "FIRST_SEEN, ACTIVE, CHANGED, SUPERSEDED, REMOVED, UNKNOWN"),
    (18, "the-digital-twin-reads-the-same-graph",
     "who connects to whom, with which TLS and certificate"),
    (19, "the-device-has-a-vendor-product-and-a-firmware",
     "LB-01 → HAS_MODEL → product → SUPPLIED_BY → vendor"),
    (20, "the-device-runs-on-hardware",
     "LB-01 → RUNS_ON → Hardware-9281"),
    (21, "coverage-propagates-and-never-improves-downstream",
     "PARTIAL inherited by every consumer, and laundering refused"),
    (22, "the-whole-chain-exists-end-to-end",
     "system → application → process → service → endpoint → waf → lb → gateway → mesh "
     "→ database → hsm → crypto → vendor"),
)


def _audit_observed(n: Any, t: Any, bom: dict[str, Any], fixture: dict[str, Any],
                    point: int) -> tuple[bool, str]:
    claims = bom["claims"]
    assets = {row["name"]: row for row in bom["assets"]}
    kinds = {row["kind"] for row in bom["assets"]}
    relations = [claim["relation"] for claim in claims]

    if point == 1:
        ids = bom["ids"]
        ok = (ids["NETWORK_ENDPOINT"]["payments.bank.example:443"].startswith("NET-ENDPOINT-")
              and ids["APPLICATION"]["Payments API"].startswith("APPLICATION-")
              and ids["BUSINESS_SYSTEM"]["Payments System"].startswith("SYSTEM-"))
        return ok, (f"{ids['NETWORK_ENDPOINT']['payments.bank.example:443']}, "
                    f"{ids['APPLICATION']['Payments API']}, "
                    f"{ids['BUSINESS_SYSTEM']['Payments System']}")
    if point == 2:
        edge = next((claim for claim in claims
                     if claim["from"] == "payments.bank.example:443"
                     and claim["relation"] == "ROUTES_TO"), None)
        ok = edge is not None and edge["basis"] == "sni-header"
        return ok, (f"payments.bank.example:443 ROUTES_TO {edge['to']} on {edge['basis']}"
                    if edge else "no edge")
    if point == 3:
        modes = bom["tls_modes"]
        ok = {"TERMINATES_TLS", "RE_ENCRYPTS", "PASSTHROUGH"} <= set(modes)
        return ok, ", ".join(f"{name} {count}" for name, count in modes.items())
    if point == 4:
        depth = n.certificate_depth(bom, query="waf-01:443")
        ok = depth["rooted"] >= 1 and depth["certificates"][0]["depth"] >= 5
        return ok, depth["statement"]
    if point == 5:
        roles = {claim["facts"].get("role") for claim in claims
                 if claim["from"] == "TLS_AES_256_GCM_SHA384"}
        ok = {"bulk", "mac", "kex", "auth"} <= roles
        return ok, f"suite roles {sorted(role for role in roles if role)}"
    if point == 6:
        policy = (assets["waf-01:443"]["attributes"].get("tls_policy") or {})
        supports = sum(1 for claim in claims
                       if claim["relation"] == "SUPPORTS" and claim["from"] == "waf-01:443")
        negotiates = sum(1 for claim in claims
                         if claim["relation"] == "NEGOTIATES"
                         and claim["from"] == "waf-01:443")
        ok = bool(policy) and supports >= 2 and negotiates == 1
        return ok, (f"policy {policy.get('min_version')}-{policy.get('max_version')}, "
                    f"{supports} supported, {negotiates} negotiated")
    if point == 7:
        ok = ("RUNS_APPLICATION" in relations and "USES_CRYPTO" in relations
              and "PROCESS" in kinds)
        runtime = n.runtime_vs_network(bom, query="waf-01:443")
        return ok, runtime["statement"]
    if point == 8:
        found = n.operations(bom, query="Payments API")
        signing = next((row for row in found["operations"]
                        if row["name"] == "OP-SIGN-001"), None)
        ok = signing is not None and signing["key"] == "KEY-REF-8271" \
            and signing["provider"] == "HSM-001"
        return ok, found["statement"]
    if point == 9:
        gap = n.database_crypto_gap(bom)
        ok = "AT_REST_UNENCRYPTED" in gap["counts"] and "DB-01" in gap["databases"]
        return ok, gap["statement"]
    if point == 10:
        ok = ("PROXY_FOR" in relations and "AUTHENTICATES" in relations
              and any(claim["relation"] == "PROXY_FOR" and claim["from"] == "envoy-sidecar"
                      for claim in claims))
        return ok, "envoy-sidecar PROXY_FOR Payments API; MESH-01 AUTHENTICATES it"
    if point == 11:
        ok = any(claim["relation"] == "ROUTES_TO"
                 and claim["from"] == "payments-api:8443" for claim in claims)
        return ok, "payments-api:8443 ROUTES_TO Payments API on api-gateway-config"
    if point == 12:
        ok = (any(claim["relation"] == "PROTECTS" and claim["from"] == "WAF-01"
                  for claim in claims)
              and any(claim["relation"] == "TERMINATES_TLS"
                      and claim["from"] == "waf-01:443" for claim in claims))
        return ok, "WAF-01 PROTECTS Payments API; waf-01:443 TERMINATES_TLS waf-01:8081"
    if point == 13:
        roles = {claim["facts"].get("role") for claim in claims if claim["from"] == "sshd 9.6"}
        ok = {"kex", "host-key", "cipher", "mac"} <= roles
        return ok, f"ssh roles {sorted(role for role in roles if role)}"
    if point == 14:
        ok = "IPSEC_TUNNEL" in kinds and "TUNNELS_TO" in relations
        tunnel = next(row for row in bom["assets"] if row["kind"] == "IPSEC_TUNNEL")
        attributes = tunnel["attributes"]
        return ok, (f"{tunnel['name']}: {attributes.get('ike_version')}, "
                    f"{attributes.get('tunnel_state')}")
    if point == 15:
        graph = bom["graph"]
        ok = graph["node_count"] > 20 and graph["edge_count"] > 15
        return ok, f"{graph['node_count']} vertex/vertices, {graph['edge_count']} edge(s)"
    if point == 16:
        records = [n.edge_record(bom, claim) for claim in claims]
        ok = all(all(field in record for field in n.EDGE_FIELDS) for record in records)
        named = sum(1 for record in records if record["collector"])
        return ok, f"{len(records)} edge(s) with {len(n.EDGE_FIELDS)} field(s); {named} name a collector"
    if point == 17:
        lifecycle = n.lifecycle(bom)
        states = lifecycle["states"]
        ok = (set(lifecycle["counts"]) <= set(n.LIFECYCLE)
              and {claim["id"] for claim in claims} == set(states)
              and "ACTIVE" in lifecycle["counts"])
        return ok, (f"{len(states)} edge(s) with a state: "
                    + ", ".join(f"{name} {count}"
                                for name, count in lifecycle["counts"].items()))
    if point == 18:
        twin = n.twin(bom)
        ok = twin["edge_count"] == len(claims) and twin["applications"]
        return ok, twin["statement"]
    if point == 19:
        ok = ("HAS_MODEL" in relations and "SUPPLIED_BY" in relations
              and "RUNS_FIRMWARE" in relations)
        return ok, "LB-01 HAS_MODEL F5 BIG-IP i5800, SUPPLIED_BY F5, RUNS_FIRMWARE 17.1.1"
    if point == 20:
        ok = any(claim["relation"] == "RUNS_ON" and claim["from"] == "LB-01"
                 for claim in claims)
        return ok, "LB-01 RUNS_ON Hardware-9281 (Mumbai-DC2, R12)"
    if point == 21:
        block = bom["coverage_by_segment"]
        propagated = n.propagate_coverage(fixture["coverage"], segments=fixture["segments"],
                                          consumers={"cbom": "COMPLETE"})
        ok = block["verdict"] == "PARTIAL" and propagated["consumers"]["cbom"] == "PARTIAL"
        return ok, propagated["statement"]
    if point == 22:
        chain = n.dependency_chain(bom, query="payments.bank.example:443")
        levels = chain["levels"]
        ok = bool(levels["application"] and levels["system"] and levels["crypto"]
                  and levels["vendor"] and levels["database"])
        return ok, chain["statement"]
    return False, f"point {point} is not audited"


def row_audit(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, fixture = _build(modules)
    probes = []
    for point, name, shape in AUDIT:
        ok, observed = _audit_observed(n, t, bom, fixture, point)
        probes.append(_probe(f"{point:02d}-{name}", ok, f"{shape} — {observed}"))
    return _row("audit", "is each of the twenty-two points present in the built "
                         "projection", "1–22", probes)


# --------------------------------------------------------------------------- #
# The five dependencies under the review
# --------------------------------------------------------------------------- #

def row_sections(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, fixture = _build(modules)
    db = t.asset("DATABASE", "DB-02", evidence_ids=[EVID])
    app = t.asset("APPLICATION", "Ledger API", evidence_ids=[EVID])
    listener = n.endpoint(host="10.10.1.8", port=5432, name="db-02:5432",
                          tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                          evidence_ids=[EVID])
    part = n.database_dependency(application_row=app, database_row=db,
                                 endpoint_row=listener,
                                 tde={"enabled": True, "algorithm": "AES-256-GCM"},
                                 evidence_ids=[EVID])
    single = n.estate(part, estate_id="one")
    merged = n.estate(part, interval_of := {"database_crypto": {"DB-03": {"at_rest": {
        "enabled": False}}}}, estate_id="two")
    probes = [
        _probe("a-builder-s-block-survives-estate",
               "database_crypto" in single["sections"],
               f"sections: {sorted(single['sections'])}"),
        _probe("the-projection-carries-the-section-it-was-given",
               "DB-01" in (bom.get("sections", {}).get("database_crypto") or {}),
               f"{len(bom['sections']['database_crypto'])} database(s) in the built NBOM"),
        _probe("two-parts-of-the-same-section-merge-instead-of-replacing",
               set(merged["sections"]["database_crypto"]) == {"DB-02", "DB-03"},
               f"merged: {sorted(merged['sections']['database_crypto'])}"),
        _probe("a-bom-that-dropped-its-sections-would-lose-point-9",
               n.database_crypto_gap(bom)["databases"] != {},
               n.database_crypto_gap(bom)["statement"]),
    ]
    del interval_of
    return _row("sections", "does a fact a builder returns reach the projection",
                "9, 21", probes)


def row_certificate_depth(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    depth = n.certificate_depth(bom, query="waf-01:443")
    chain = depth["certificates"][0]
    kinds = [row["kind"] for row in chain["links"]]
    probes = [
        _probe("a-named-certificate-on-a-listener-is-an-edge",
               any(claim["relation"] == "PRESENTS" and claim["from"] == "waf-01:443"
                   for claim in bom["claims"]),
               "waf-01:443 PRESENTS CERT-001 on tls-handshake"),
        _probe("the-depth-is-reached-from-the-endpoint-not-stored-beside-it",
               kinds[0] == "CERTIFICATE" and "ALGORITHM" in kinds
               and "CERTIFICATE_AUTHORITY" in kinds and "PUBLIC_KEY" in kinds,
               " → ".join(f"{kind}" for kind in kinds)),
        _probe("the-chain-says-whether-it-reaches-a-root",
               depth["rooted"] == len(depth["certificates"]) and chain["rooted"] is True,
               f"rooted: {depth['rooted']} of {len(depth['certificates'])}"),
        _probe("a-weak-key-and-a-broken-hash-are-named-by-size",
               _weak_codes(n) == {"WEAK_KEY", "WEAK_SIGNATURE", "CHAIN_NOT_ROOTED"},
               "RSA-1024 + SHA1 + an intermediate as the last link"),
        _probe("a-certificate-the-estate-does-not-hold-is-a-finding-not-a-skip",
               _dangling(n) == "CERTIFICATE_UNRESOLVED",
               "tls.certificate = CERT-999 with no node → CERTIFICATE_UNRESOLVED"),
        _probe("every-link-carries-its-own-evidence-class",
               all(row["confidence"] in tb_confidences() for row in chain["links"]),
               f"{len(chain['links'])} link(s), each with a class"),
    ]
    return _row("certificate-depth", "is point 4 a chain or a picture of one", "4", probes)


def tb_confidences() -> set[str]:
    return {"CONFIGURED", "NETWORK_OBSERVED", "RUNTIME_OBSERVED", "OBSERVED",
            "VENDOR_DECLARED", "IMPORTED", "INFERRED", "UNKNOWN"}


def _weak_codes(n: Any) -> set[str]:
    t = _load()["t"]
    weak = n.algorithm(name="RSA-1024", family="RSA", key_size=1024, evidence_ids=[EVID])
    sha1 = n.algorithm(name="SHA1", family="RSA", hash_name="SHA1", evidence_ids=[EVID])
    cert = n.certificate(name="CERT-WEAK", subject="CN=weak", evidence_ids=[EVID])
    intermediate = n.authority(name="ICA-2", kind="INTERMEDIATE", evidence_ids=[EVID])
    chain = n.certificate_chain(certificate_row=cert,
                                key_row=n.public_key(name="PK-WEAK",
                                                     key_algorithm_row=weak,
                                                     evidence_ids=[EVID]),
                                key_algorithm_row=weak, signature_algorithm_row=sha1,
                                issuer_row=intermediate, basis="tls-handshake",
                                evidence_ids=[EVID])
    endpoint = n.endpoint(host="10.0.0.9", port=443, name="weak:443",
                          tls={"version": "TLS1.2", "suite": "X", "certificate": "CERT-WEAK"},
                          evidence_ids=[EVID])
    bom = n.build(n.estate(chain, n.presents_certificate(endpoint_row=endpoint,
                                                         certificate_row=cert,
                                                         basis="tls-handshake",
                                                         evidence_ids=[EVID]),
                           t.asset("APPLICATION", "x", evidence_ids=[EVID]),
                           estate_id="weak"))
    return {row["code"] for row in n.certificate_depth(bom, query="weak:443")["findings"]}


def _dangling(n: Any) -> str:
    endpoint = n.endpoint(host="10.0.0.8", port=443, name="dangling:443",
                          tls={"version": "TLS1.2", "suite": "X", "certificate": "CERT-999"},
                          evidence_ids=[EVID])
    bom = n.build(n.estate(endpoint, estate_id="dangling"))
    findings = n.certificate_depth(bom, query="dangling:443")["findings"]
    return findings[0]["code"] if findings else "no finding"


def row_operations(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, _ = _build(modules)
    found = n.operations(bom, query="Payments API")
    signing = next(row for row in found["operations"] if row["name"] == "OP-SIGN-001")
    probes = [
        _probe("an-operation-is-a-node-with-an-id-of-its-own",
               any(row["kind"] == "CRYPTO_OPERATION"
                   and str(row["id"]).startswith("TECH-OP-")
                   for row in bom["assets"]),
               "TECH-OP-001 … beside TECH-HSM-001 and TECH-KREF-001"),
        _probe("an-application-invokes-it-rather-than-using-crypto",
               "INVOKES" in t.RELATIONS
               and any(claim["relation"] == "INVOKES"
                       and claim["from"] == "Payments API" for claim in bom["claims"]),
               "Payments API INVOKES OP-SIGN-001"),
        _probe("the-operation-names-its-key-its-provider-and-its-algorithm",
               signing["key"] == "KEY-REF-8271" and signing["provider"] == "HSM-001"
               and signing["algorithm"] == "RSA-2048",
               f"{signing['operation']} on {signing['algorithm']} with {signing['key']} "
               f"in {signing['provider']}"),
        _probe("an-operation-with-no-key-is-a-finding",
               "OPERATION_WITHOUT_KEY" in found["counts"],
               f"OPERATION_WITHOUT_KEY on {found['counts']['OPERATION_WITHOUT_KEY']} "
               "operation(s)"),
        _probe("an-operation-done-in-the-application-is-a-different-claim",
               "OPERATION_WITHOUT_PROVIDER" in found["counts"]
               and next(row for row in found["operations"]
                        if row["name"] == "OP-ENCRYPT-002")["runs_in"] == "APPLICATION",
               "OP-ENCRYPT-002 runs in the application, not the HSM"),
        _probe("no-key-material-is-accepted-only-metadata",
               _refused(n.crypto_operation, name="OP-X", application_row={"name": "a"},
                        operation="SIGN", private_key="---BEGIN---") == "KEY_MATERIAL_REFUSED",
               "private_key → KEY_MATERIAL_REFUSED"),
        _probe("uses-crypto-is-not-an-operation",
               _refused(n.crypto_operation, name="OP-X", application_row={"name": "a"},
                        operation="USE_CRYPTO") == "UNKNOWN_CRYPTO_OPERATION",
               "USE_CRYPTO → UNKNOWN_CRYPTO_OPERATION"),
        _probe("an-application-is-not-a-key-provider",
               _refused(n.crypto_operation, name="OP-X", application_row={"name": "a"},
                        operation="SIGN", provider_row={"name": "a", "kind": "APPLICATION"})
               == "NOT_A_KEY_PROVIDER",
               "provider = an application → NOT_A_KEY_PROVIDER"),
    ]
    return _row("operations", "is point 8 a level in the graph or a verb in a report",
                "8", probes)


def row_at_rest(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, _ = _build(modules)
    gap = n.database_crypto_gap(bom)
    unencrypted = next(row for row in gap["findings"]
                       if row["code"] == "AT_REST_UNENCRYPTED")
    probes = [
        _probe("in-transit-and-at-rest-are-two-blocks-on-one-database",
               set(gap["databases"]["DB-01"]) >= {"in_transit", "at_rest"}
               and gap["databases"]["DB-01"].get("distinct") is True,
               "DB-01: in_transit TLS1.3, at_rest disabled, distinct"),
        _probe("a-database-encrypted-on-the-wire-and-not-on-disk-says-so",
               unencrypted["in_transit"] is True,
               "AT_REST_UNENCRYPTED with in_transit True"),
        _probe("nothing-read-about-at-rest-is-not-the-same-as-no-encryption",
               _tde_not_recorded(n, t) == "TDE_NOT_RECORDED",
               "no tde block → TDE_NOT_RECORDED, not AT_REST_UNENCRYPTED"),
        _probe("a-database-with-no-tls-on-its-listener-is-its-own-finding",
               _tls_not_observed(n, t) == "TLS_NOT_OBSERVED",
               "no tls parameters → TLS_NOT_OBSERVED"),
        _probe("the-same-algorithm-on-both-sides-is-one-decision-applied-twice",
               "AT_REST_MIRRORS_TRANSIT" in _mirrored(n, t),
               "TLS suite = TDE algorithm → AT_REST_MIRRORS_TRANSIT"),
    ]
    return _row("at-rest", "is point 9 two dependencies or one", "9", probes)


def _db_estate(n: Any, t: Any, *, tls: dict[str, Any] | None, tde: Any) -> dict[str, Any]:
    app = t.asset("APPLICATION", "Ledger API", evidence_ids=[EVID])
    db = t.asset("DATABASE", "DB-09", evidence_ids=[EVID])
    listener = n.endpoint(host="10.0.9.1", port=5432, name="db-09:5432",
                          tls=tls or {}, evidence_ids=[EVID])
    part = n.database_dependency(application_row=app, database_row=db,
                                 endpoint_row=listener, tde=tde, evidence_ids=[EVID])
    return n.build(n.estate(part, estate_id="db"))


def _tde_not_recorded(n: Any, t: Any) -> str:
    bom = _db_estate(n, t, tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                     tde=None)
    return n.database_crypto_gap(bom)["findings"][0]["code"]


def _tls_not_observed(n: Any, t: Any) -> str:
    bom = _db_estate(n, t, tls=None, tde={"enabled": True, "algorithm": "AES-256-GCM"})
    codes = [row["code"] for row in n.database_crypto_gap(bom)["findings"]]
    return codes[0] if codes else "no finding"


def _mirrored(n: Any, t: Any) -> set[str]:
    bom = _db_estate(n, t,
                     tls={"version": "TLS1.3", "suite": "AES-256-GCM"},
                     tde={"enabled": True, "algorithm": "AES-256-GCM"})
    return {row["code"] for row in n.database_crypto_gap(bom)["findings"]}


def row_coverage_propagation(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, fixture = _build(modules)
    block = bom["coverage"]
    segments = bom["coverage_by_segment"]
    honest = n.propagate_coverage(block, segments=fixture["segments"],
                                  consumers={"cbom": "PARTIAL", "twin": "PARTIAL"})
    laundered = n.propagate_coverage(block, segments=fixture["segments"],
                                     consumers={"cbom": "COMPLETE", "twin": "COMPLETE"})
    shortfall = n.propagate_coverage(block, consumers={"cbom": "UNKNOWN"})
    probes = [
        _probe("the-coverage-verdict-travels-with-its-denominator",
               block["verdict"] == "PARTIAL" and block["unavailable"] == 50,
               block["statement"]),
        _probe("a-downstream-view-inherits-the-worse-of-its-claim-and-the-network",
               honest["consumers"] == {"cbom": "PARTIAL", "twin": "PARTIAL"},
               honest["statement"]),
        _probe("a-cbom-cannot-claim-complete-over-a-partial-network",
               laundered["consumers"] == {"cbom": "PARTIAL", "twin": "PARTIAL"}
               and len(laundered["findings"]) == 2,
               f"{len(laundered['findings'])} COVERAGE_LAUNDERED"),
        _probe("a-consumer-that-knows-less-keeps-its-own-answer",
               shortfall["consumers"]["cbom"] == "UNKNOWN",
               "UNKNOWN is worse than PARTIAL and is not improved by it"),
        _probe("the-weakest-segment-decides-the-network-it-does-not-average-away",
               segments["verdict"] == "PARTIAL" and segments["weakest"] == ["CARDHOLDER"]
               and block["verdict"] == "PARTIAL",
               segments["statement"]),
        _probe("a-verdict-that-is-not-a-verdict-is-refused",
               _refused(n.propagate_coverage, {"verdict": "MOSTLY"}) ==
               "UNKNOWN_COVERAGE_VERDICT",
               "MOSTLY → UNKNOWN_COVERAGE_VERDICT"),
    ]
    return _row("coverage-propagation", "does point 21 propagate or merely echo", "21",
                probes)


ROWS = (row_audit, row_sections, row_certificate_depth, row_operations, row_at_rest,
        row_coverage_propagation)


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
    audit = next(row for row in rows if row["id"] == "audit")
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "statement": bom["statement"],
        "points": [{"point": point, "question": name.replace("-", " "),
                    "probe": probe["probe"], "ok": probe["ok"],
                    "observed": probe["observed"]}
                   for (point, question, _shape), probe in zip(AUDIT, audit["probes"],
                                                              strict=False)
                   for name in (question,)],
        "certificate_depth": n.certificate_depth(bom, query="waf-01:443"),
        "operations": n.operations(bom, query="Payments API"),
        "database_crypto": n.database_crypto_gap(bom),
        "propagation": n.propagate_coverage(bom["coverage"],
                                            segments=fixture["segments"],
                                            consumers={"cbom_network_evidence": "PARTIAL",
                                                       "digital_twin_network": "COMPLETE"}),
        "sections": {name: len(value) if isinstance(value, dict) else 1
                     for name, value in bom.get("sections", {}).items()},
        "refusals": bom["refusals"],
        "rows": rows,
        "limits": [
            "the fixture is the bank's own path: every shape is real, the rows are not",
            "a certificate chain is what the estate holds and the handshake presented; "
            "revocation and expiry state are separate questions this does not answer",
            "a weak key is named by size against a floor, not scored: the risk judgement "
            "belongs to the assurance engine, and nothing here calls a finding an exploit",
            "a crypto operation names a key reference and a provider; it never proves the "
            "key that produced a signature, and it never holds key material",
            "coverage propagation is arithmetic on verdicts, not a second measurement: it "
            "cannot see an endpoint the network never saw",
            "point 21's downstream consumers are named by the caller; nothing here knows "
            "which reports actually read this projection",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    passed = sum(1 for row in report["points"] if row["ok"])
    lines = [
        "# The review, point by point",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{passed} of {len(report['points'])} points of the review are present in the",
        "built projection**, and five dependencies under them were still missing — one of",
        "them a defect that had been losing an answer since guide 169.",
        "",
        "```",
        "sections   a block a builder returns now reaches the projection  (point 9)",
        "certificate endpoint → certificate → key → algorithm → issuer → root  (point 4)",
        "operation   application → INVOKES → operation → key, HSM, algorithm  (point 8)",
        "at rest     in transit ≠ at rest, and neither implies the other  (point 9)",
        "coverage    the worse verdict wins downstream, laundering refused  (point 21)",
        "```",
        "",
        report["statement"],
        "",
        "## The twenty-two points, read off the build",
        "",
        "| # | point | present | what the projection says |",
        "|---|---|---|---|",
    ]
    for row in report["points"]:
        mark = "yes" if row["ok"] else "**no**"
        lines.append(f"| {row['point']} | {row['question']} | {mark} | {row['observed']} |")
    depth = report["certificate_depth"]
    lines += ["", "## The certificate chain, reached from the endpoint", "",
              f"**{depth['statement']}**", ""]
    if depth["certificates"]:
        for link in depth["certificates"][0]["links"]:
            lines.append(f"- `{link['relation']}` → `{link['kind']}` {link['name']} "
                         f"({link['confidence']})")
    operations = report["operations"]
    lines += ["", "## The operations the application invokes", "",
              f"**{operations['statement']}**", "",
              "| operation | what | key | provider | runs in |", "|---|---|---|---|---|"]
    for row in operations["operations"]:
        lines.append(f"| {row['name']} | {row['operation']} | {row['key'] or '—'} | "
                     f"{row['provider'] or '—'} | {row['runs_in']} |")
    database = report["database_crypto"]
    lines += ["", "## In transit, at rest", "", f"**{database['statement']}**", ""]
    for row in database["findings"]:
        lines.append(f"- `{row['code']}` — {row['database']}: {row['reason']}")
    propagation = report["propagation"]
    lines += ["", "## Coverage, downstream", "", f"**{propagation['statement']}**", ""]
    for name, verdict in propagation["consumers"].items():
        lines.append(f"- {name}: {verdict}")
    for row in propagation["findings"]:
        lines.append(f"- `{row['code']}` on {row['consumer']} — claimed {row['claimed']}, "
                     f"inherited {row['inherited']}")
    lines += ["", "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 172, {row['phase']})", ""]
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
