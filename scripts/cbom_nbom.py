#!/usr/bin/env python3
"""Guide 169 — the network is a graph, and every edge says how it was read.

The NBOM review (`docs/bank-environment/nbom-review-2026-11-03.md`) makes twenty-two
points against a network layer that was, until now, a list of endpoints. This guide builds
the answer and measures it: ``cbom.nbom_graph`` puts the network into the *same* graph as
the CBOM, SBOM, HBOM and VBOM, so an endpoint is a node, what is behind it is a claim with
a named basis, and the TLS between two boxes is a topology rather than a flag.

What the measurement is about:

* **an address is a location** — ``10.10.10.20:443`` may be two virtual hosts, two
  certificates and two applications, so the endpoint is a node and the backend is reached
  by DNS, SNI, an ingress rule, a gateway route, a registry entry or a runtime observation.
  A matching name is refused as a basis, by name;
* **supported, negotiated and used are three relations** — a suite is decomposed into its
  key exchange, authentication, bulk cipher and hash, and a policy cannot claim a session;
* **termination is a topology** — ``TERMINATES_TLS``, ``RE_ENCRYPTS`` and ``PASSTHROUGH``
  are three graphs between the same two boxes, and a passthrough that presents a
  certificate is refused rather than drawn;
* **the sidecar does the TLS** — the certificate is on the proxy, not on the application
  behind it;
* **every edge carries its record** — source, target, relationship, basis, confidence,
  evidence id, protocol, port, first and last seen.

The fixture is the review's own estate: ``payments.bank.example:443`` through a WAF, a load
balancer, an API gateway and a service mesh to ``Payments API``, its process, its HSM key,
its database, an SSH listener and a branch IPsec tunnel.
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
SCHEMA = "cryptoscan.cbom-nbom-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID = "EVID-92821"
EVID_WAF = "EVID-92840"
EVID_LB = "EVID-92841"
EVID_GW = "EVID-92842"
EVID_DB = "EVID-92843"
EVID_SSH = "EVID-92844"
EVID_VPN = "EVID-92845"
EVID_RT = "EVID-92850"
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


def _refusals_in_build(n: Any, assets: list[Any], claims: list[Any]) -> list[str]:
    """Refusals happen when the estate is assembled, which is the point of them."""
    bom = n.build(n.estate({"assets": assets, "claims": claims}, estate_id="probe"))
    return [row["code"] for row in bom["refusals"]]


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The fixture: the review's estate
# --------------------------------------------------------------------------- #

def _document(n: Any, t: Any) -> dict[str, Any]:
    """The review's example estate, assembled from the builders the guide measures."""
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", owner="Payments",
                          evidence_ids=[EVID])
    app = n.service_of(name="Payments API", kind="APPLICATION", owner="Payments",
                       systems=["Payments System"], evidence_ids=[EVID])
    service = n.service_of(name="payments-api", port=8080, owner="Payments",
                           evidence_ids=[EVID])
    auth_app = n.service_of(name="Auth Service", kind="APPLICATION", evidence_ids=[EVID])
    auth_service = n.service_of(name="auth-api", port=8081, evidence_ids=[EVID])

    # 1–2: one address, two virtual hosts, two services
    public = n.endpoint(host="10.10.10.20", port=443, name="payments.bank.example:443",
                        sni=["payments.bank.example"], alpn=["h2", "http/1.1"],
                        tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384",
                             "certificate": "CERT-001"},
                        evidence_ids=[EVID], first_seen=EARLIER, last_seen=NOW)
    auth = n.endpoint(host="10.10.10.20", port=443, name="auth.bank.example:443",
                      sni=["auth.bank.example"], evidence_ids=[EVID])
    app_listener = n.endpoint(host="10.10.1.5", port=8443, name="payments-api:8443",
                              tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                              evidence_ids=[EVID])

    routing = [
        n.routed(endpoint_row=public, service_row=service, basis="sni-header",
                 evidence_ids=[EVID], observed_at=NOW, first_seen=EARLIER, last_seen=NOW,
                 protocol="TCP", port=443),
        n.routed(endpoint_row=auth, service_row=auth_service, basis="kubernetes-ingress",
                 evidence_ids=[EVID], observed_at=NOW, first_seen=NOW, last_seen=NOW),
        n.serves(application_row=app, service_row=service, system_row=system,
                 evidence_ids=[EVID]),
        n.serves(application_row=auth_app, service_row=auth_service, evidence_ids=[EVID]),
    ]

    # 3–4: WAF → LB → gateway → mesh → application, with the certificate chain
    waf = n.network_device(kind="WAF", name="WAF-01", vendor="Palo Alto",
                           product="PA-VM", model="PA-VM-300", firmware_version="11.1.3",
                           evidence_ids=[EVID_WAF])
    balancer = n.network_device(kind="LOAD_BALANCER", name="LB-01", vendor="F5",
                                product="BIG-IP i5800", model="i5800",
                                firmware_version="17.1.1", ha_role="ACTIVE",
                                evidence_ids=[EVID_LB])
    gateway = n.network_device(kind="API_GATEWAY", name="API-GW-01", vendor="Kong",
                               product="Kong Gateway", model="3.6",
                               firmware_version="3.6.1", evidence_ids=[EVID_GW])
    mesh_device = n.network_device(kind="SERVICE_MESH", name="MESH-01", vendor="Istio",
                                   product="Istio", model="1.20",
                                   firmware_version="1.20.3", evidence_ids=[EVID_GW])
    server = t.asset("PHYSICAL_SERVER", "SRV-PAY-01", manufacturer="Dell",
                     model="PowerEdge R760", asset_tag="SRV-PAY-01",
                     evidence_ids=[EVID_LB])
    hardware = n.on_hardware(device_row=balancer["assets"][0], hardware_row=server,
                             evidence_ids=[EVID_LB])

    ce = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                       issuer="Intermediate CA", serial="0F:31:9C",
                       not_before="2026-01-04", not_after="2027-01-04",
                       signature_algorithm="ECDSA-SHA256", evidence_ids=[EVID])
    key = n.public_key(name="KEY-CERT-001", key_algorithm_row=n.algorithm(
        name="ECDSA P-256", family="ECDSA", curve="P-256", key_size=256,
        evidence_ids=[EVID]), curve="P-256", evidence_ids=[EVID])
    key_alg = n.algorithm(name="ECDSA P-256", family="ECDSA", curve="P-256", key_size=256,
                          evidence_ids=[EVID])
    sig_alg = n.algorithm(name="ECDSA-SHA256", family="ECDSA", hash_name="SHA-256",
                          evidence_ids=[EVID])
    intermediate = n.authority(name="Intermediate CA", kind="INTERMEDIATE",
                               evidence_ids=[EVID])
    root = n.authority(name="Root CA", kind="ROOT", evidence_ids=[EVID])
    chain = n.certificate_chain(certificate_row=ce, key_row=key,
                                key_algorithm_row=key_alg,
                                signature_algorithm_row=sig_alg,
                                issuer_row=intermediate, root_row=root,
                                evidence_ids=[EVID])

    # 5–6: a suite is four dependencies, and only one of three supported suites was chosen
    aes256 = t.asset("CRYPTO_ASSET", "AES-256-GCM", evidence_ids=[EVID],
                     algorithm="AES", key_size=256, mode="GCM",
                     evidence_type="NETWORK_OBSERVED")
    aes128 = t.asset("CRYPTO_ASSET", "AES-128-GCM", evidence_ids=[EVID],
                     algorithm="AES", key_size=128, mode="GCM", evidence_type="CONFIGURED")
    chacha = t.asset("CRYPTO_ASSET", "ChaCha20-Poly1305", evidence_ids=[EVID],
                     algorithm="ChaCha20", key_size=256, evidence_type="CONFIGURED")
    sha384 = t.asset("CRYPTO_ASSET", "SHA-384", evidence_ids=[EVID], algorithm="SHA",
                     key_size=384, evidence_type="NETWORK_OBSERVED")
    x25519 = t.asset("CRYPTO_ASSET", "X25519", evidence_ids=[EVID], algorithm="ECDH",
                     curve="X25519", evidence_type="NETWORK_OBSERVED")
    ecdsa256 = t.asset("CRYPTO_ASSET", "ECDSA-P256", evidence_ids=[EVID], algorithm="ECDSA",
                       curve="P-256", evidence_type="NETWORK_OBSERVED")
    suite_1 = n.cipher_suite(name="TLS_AES_256_GCM_SHA384", tls_version="TLS1.3",
                             kex="X25519", auth="ECDSA-P256", bulk="AES-256-GCM",
                             mac="SHA-384", evidence_ids=[EVID])
    suite_2 = n.cipher_suite(name="TLS_AES_128_GCM_SHA256", tls_version="TLS1.3",
                             kex="X25519", auth="ECDSA-P256", bulk="AES-128-GCM",
                             mac="SHA-256", evidence_ids=[EVID])
    suite_3 = n.cipher_suite(name="TLS_CHACHA20_POLY1305_SHA256", tls_version="TLS1.3",
                             kex="X25519", auth="ECDSA-P256", bulk="ChaCha20-Poly1305",
                             mac="SHA-256", evidence_ids=[EVID])
    suite_parts = n.suite_parts(suite_row=suite_1,
                                parts={"bulk": aes256, "mac": sha384, "kex": x25519,
                                       "auth": ecdsa256},
                                evidence_ids=[EVID])
    negotiated = n.negotiated(endpoint_row=public, suite_row=suite_1, evidence_ids=[EVID],
                              observed_at=NOW)
    supported = n.supported(endpoint_row=public, suite_rows=[suite_1, suite_2, suite_3],
                            evidence_ids=[EVID], observed_at=NOW)

    # 3: the three TLS boundaries
    waf_front = n.endpoint(host="10.10.10.20", port=443, name="waf-01:443",
                           tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384",
                                "certificate": "CERT-001"},
                           evidence_ids=[EVID_WAF])
    waf_back = n.endpoint(host="10.10.0.21", port=8080, name="waf-01:8080",
                          transport="PLAIN", evidence_ids=[EVID_WAF])
    lb_front = n.endpoint(host="10.10.0.30", port=443, name="lb-01:443",
                          tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                          evidence_ids=[EVID_LB])
    gw_front = n.endpoint(host="10.10.0.40", port=8443, name="api-gw-01:8443",
                          tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                          evidence_ids=[EVID_GW])
    mesh_front = n.endpoint(host="10.10.1.4", port=15006, name="mesh-ingress:15006",
                            tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                            evidence_ids=[EVID_GW])
    hops = [
        n.tls_hop(frontend=waf_front, backend=waf_back, mode="TERMINATE",
                  basis="load-balancer-config", evidence_ids=[EVID_WAF],
                  certificate=ce, observed_at=NOW, first_seen=EARLIER, last_seen=NOW,
                  port=443),
        n.tls_hop(frontend=lb_front, backend=gw_front, mode="RE_ENCRYPT",
                  basis="load-balancer-config", evidence_ids=[EVID_LB], observed_at=NOW,
                  port=443),
        n.tls_hop(frontend=mesh_front, backend=app_listener, mode="PASSTHROUGH",
                  basis="mesh-config", evidence_ids=[EVID_GW], observed_at=NOW),
    ]

    # 7: the process, its library, and cryptography the network never saw
    openssl = t.asset("CRYPTO_LIBRARY", "OpenSSL 3.0.13", version="3.0.13",
                      evidence_ids=[EVID_RT])
    runtime_aes = t.asset("CRYPTO_ASSET", "AES-128-CBC", evidence_ids=[EVID_RT],
                          algorithm="AES", key_size=128, mode="CBC",
                          evidence_type="RUNTIME_OBSERVED")
    process = t.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT],
                      pid=1821, owner="payments")
    runtime = n.runtime(process_row=process, application_row=app, library_row=openssl,
                        crypto_rows=[runtime_aes], evidence_ids=[EVID_RT], pid=1821,
                        observed_at=NOW)

    # 8: the key, as metadata
    hsm = t.asset("HSM", "HSM-001", manufacturer="SyntheticHSM", model="PaymentHSM-9000",
                  evidence_ids=[EVID], location="DC1-R12-U8")
    capability = t.asset("CRYPTO_CAPABILITY", "RSA-2048 signing",
                         evidence_ids=[EVID], algorithm="RSA", key_size=2048,
                         operations=["SIGN"], evidence_type="CAPABILITY")
    key_ref = n.key_reference(name="KEY-REF-8271", key_ref="arn:key/8271",
                              purpose="SIGN", algorithm="RSA", key_size=2048,
                              holder="HSM-001", status="ACTIVE", evidence_ids=[EVID])
    keys = n.key_use(application_row=app, hsm_row=hsm, key_row=key_ref,
                     capability_row=capability, operation="SIGN", evidence_ids=[EVID])

    # 9: the database, TLS in transit and TDE at rest
    database = t.asset("DATABASE", "DB-01", evidence_ids=[EVID_DB],
                       engine="PostgreSQL", version="16.2")
    db_endpoint = n.endpoint(host="10.20.0.5", port=5432, name="db-01:5432",
                             tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                             evidence_ids=[EVID_DB])
    db = n.database_dependency(application_row=app, database_row=database,
                               endpoint_row=db_endpoint, tls_suite=suite_1,
                               tde={"algorithm": "AES-256-XTS", "enabled": True},
                               evidence_ids=[EVID_DB])

    # 10: the mesh, and the sidecar that owns the handshake
    sidecar = t.asset("PROCESS", "envoy-sidecar", evidence_ids=[EVID_GW],
                      trust_domain="bank.internal",
                      spiffe_id="spiffe://bank.internal/ns/payments/sa/payments-api")
    mesh_cert = n.certificate(name="CERT-MESH-001", subject="spiffe://bank.internal/ns/payments",
                              issuer="bank.internal CA", signature_algorithm="ECDSA-SHA256",
                              evidence_ids=[EVID_GW])
    mesh = n.mesh(mesh_row=mesh_device, trust_domain="bank.internal",
                  sidecars=[sidecar], proxied=[app, auth_app], certificate_row=mesh_cert,
                  evidence_ids=[EVID_GW], mtls=True)

    # 11–12: the gateway routes, the WAF protects
    gateway_route = n.part(
        gateway["assets"][0],
        claims=[t.claim("API-GW-01", "ROUTES_TO", "Payments API",
                        basis="api-gateway-config", evidence_ids=[EVID_GW],
                        observed_at=NOW, route="/v1/payments", port=8443),
                t.claim("WAF-01", "PROTECTS", "Payments API", basis="config-parse",
                        evidence_ids=[EVID_WAF], observed_at=NOW, rule="OWASP-CRS-4")])
    waf_listens = n.part(
        claims=[t.claim("Payments API", "LISTENS_ON", "payments-api:8443",
                        basis="deployment-metadata", evidence_ids=[EVID_GW], port=8443),
                t.claim("WAF-01", "LISTENS_ON", "waf-01:443", basis="config-parse",
                        evidence_ids=[EVID_WAF], port=443),
                t.claim("LB-01", "LISTENS_ON", "lb-01:443", basis="load-balancer-config",
                        evidence_ids=[EVID_LB], port=443),
                t.claim("API-GW-01", "LISTENS_ON", "api-gw-01:8443",
                        basis="api-gateway-config", evidence_ids=[EVID_GW], port=8443)])
    forwards = n.part(claims=[
        t.claim("waf-01:8080", "FORWARDS_TO", "lb-01:443", basis="load-balancer-config",
                evidence_ids=[EVID_LB], protocol="TCP", port=443),
        t.claim("lb-01:443", "FORWARDS_TO", "api-gw-01:8443", basis="load-balancer-config",
                evidence_ids=[EVID_LB], protocol="TCP", port=8443),
        t.claim("api-gw-01:8443", "FORWARDS_TO", "payments-api:8443",
                basis="api-gateway-config", evidence_ids=[EVID_GW], protocol="TCP",
                port=8443)])

    # 13: SSH, 14: the branch tunnel
    ssh_host = t.asset("HOST", "srv-payments-01", evidence_ids=[EVID_SSH], os="RHEL 9.3")
    ssh_endpoint = n.endpoint(host="10.10.2.11", port=22, name="srv-payments-01:22",
                              transport="SSH", evidence_ids=[EVID_SSH])
    ssh = n.ssh_service(name="sshd@srv-payments-01", host_row=ssh_host,
                        endpoint_row=ssh_endpoint,
                        kex=t.asset("CRYPTO_ASSET", "X25519-kex", evidence_ids=[EVID_SSH],
                                    algorithm="X25519"),
                        host_key=t.asset("CRYPTO_ASSET", "Ed25519-hostkey",
                                         evidence_ids=[EVID_SSH], algorithm="Ed25519"),
                        cipher=t.asset("CRYPTO_ASSET", "ChaCha20-Poly1305-ssh",
                                       evidence_ids=[EVID_SSH], algorithm="ChaCha20"),
                        mac=t.asset("CRYPTO_ASSET", "HMAC-SHA2-256",
                                    evidence_ids=[EVID_SSH], algorithm="HMAC-SHA2"),
                        version="OpenSSH_9.3", evidence_ids=[EVID_SSH])
    vpn_gateway = n.network_device(kind="VPN_GATEWAY", name="VPN-GW-01", vendor="Cisco",
                                   product="ASR 1001-X", firmware_version="17.9.4a",
                                   evidence_ids=[EVID_VPN])
    branch = t.asset("VPN_GATEWAY", "VPN-GW-BRANCH", evidence_ids=[EVID_VPN],
                     site="Coimbatore branch")
    zone = t.asset("NETWORK_SEGMENT", "Payment Network", evidence_ids=[EVID_VPN],
                   vlan=40, zone="PCI")
    tunnel = n.ipsec_tunnel(
        name="branch-to-payments", gateway_row=vpn_gateway["assets"][0], peer_row=branch,
        zone_row=zone, ike_version="IKEv2",
        encryption=t.asset("CRYPTO_ASSET", "AES-256", evidence_ids=[EVID_VPN],
                           algorithm="AES", key_size=256),
        integrity=t.asset("CRYPTO_ASSET", "SHA-256", evidence_ids=[EVID_VPN],
                          algorithm="SHA", key_size=256),
        dh_group=t.asset("CRYPTO_ASSET", "DH-Group-19", evidence_ids=[EVID_VPN],
                         algorithm="ECDH", curve="X25519"),
        authentication=n.certificate(name="CERT-VPN-001", subject="CN=vpn-gw-01",
                                     issuer="Intermediate CA", evidence_ids=[EVID_VPN]),
        proposals=[t.asset("CRYPTO_CAPABILITY", "AES-128 proposal",
                           evidence_ids=[EVID_VPN], algorithm="AES", key_size=128),
                   t.asset("CRYPTO_CAPABILITY", "SHA-1 proposal", evidence_ids=[EVID_VPN],
                           algorithm="SHA", key_size=160)],
        evidence_ids=[EVID_VPN])

    coverage = n.coverage(expected=500, observed=420, unavailable=50, unknown=30)
    doc = n.estate(
        system, app, service, auth_app, auth_service, public, auth, app_listener,
        *routing, waf, balancer, gateway, mesh_device, server, hardware, ce, key, chain,
        aes256, aes128, chacha, sha384, x25519, ecdsa256, suite_1, suite_2, suite_3,
        suite_parts, negotiated, supported, waf_front, waf_back, lb_front, gw_front,
        mesh_front, *hops, openssl, runtime_aes, process, runtime, hsm, capability,
        key_ref, keys, database, db_endpoint, db, sidecar, mesh_cert, mesh,
        gateway_route, waf_listens, forwards, ssh_host, ssh_endpoint, ssh, vpn_gateway,
        branch, zone, tunnel,
        estate_id="bank-network", environment="PRODUCTION",
        gaps=[{"coverage": coverage, "reason": "50 unhosted endpoints could not be reached"}],
    )
    names = {"system": "Payments System", "application": "Payments API",
             "service": "payments-api", "endpoint": "payments.bank.example:443",
             "auth_endpoint": "auth.bank.example:443", "db": "DB-01",
             "ssh": "srv-payments-01:22", "app_listener": "payments-api:8443"}
    return {"estate": doc, "names": names, "coverage": coverage, "hops": hops,
            "suite": suite_1, "suite_2": suite_2, "suite_3": suite_3}


def _build(modules: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fixture = _document(modules["n"], modules["t"])
    return modules["n"].build(fixture["estate"]), fixture


# --------------------------------------------------------------------------- #
# Rows
# --------------------------------------------------------------------------- #

def row_endpoint_identity(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    fixture = _document(n, t)
    bom = n.build(fixture["estate"])
    public, auth = "payments.bank.example:443", "auth.bank.example:443"
    chains = bom["chains"]
    siblings = [row for row in bom["endpoints"]
                if str(row["attributes"].get("host")) == "10.10.10.20"]
    first = next(row for row in bom["endpoints"] if row["name"] == public)
    probes = [
        _probe("an-endpoint-is-host-and-port-and-an-address-alone-is-refused",
               _refused(n.endpoint, host="10.10.10.20", port=None, evidence_ids=[EVID])
               == "ENDPOINT_WITHOUT_HOST_OR_PORT",
               "10.10.10.20 with no port → ENDPOINT_WITHOUT_HOST_OR_PORT"),
        _probe("one-address-hosts-two-virtual-hosts-as-two-endpoints",
               {next(row for row in bom["endpoints"]
                    if row["name"] == name)["attributes"]["sni"][0]
                for name in (public, auth)} == {"payments.bank.example",
                                                "auth.bank.example"}
               and len(siblings) >= 2,
               f"10.10.10.20 carries {len(siblings)} listener(s), two of them virtual "
               "hosts with their own SNI and their own service"),
        _probe("each-endpoint-reaches-its-own-service-not-the-first-one",
               [row["name"] for row in chains[public]["levels"]["service"]] ==
               ["payments-api"] and
               [row["name"] for row in chains[auth]["levels"]["service"]] == ["auth-api"],
               f"{public} → payments-api, {auth} → auth-api"),
        _probe("the-chain-reads-endpoint-service-process-application-system",
               [band for band, rows in chains[public]["levels"].items() if rows][:4] ==
               ["service", "process", "application", "system"],
               chains[public]["statement"]),
        _probe("a-stable-id-survives-renumbering-a-readable-one-does-not",
               n.stable_id(first) == n.stable_id({"key": first["key"],
                                                  "kind": first["kind"]})
               and n.stable_id(first).startswith("NETWORK_ENDPOINT-")
               and first["id"].startswith("TECH-EP-"),
               f"{first['id']} reads; {n.stable_id(first)} holds"),
    ]
    return _row("endpoint-identity", "is an address an identity, or a location", "1–2",
                probes)


def row_routing_evidence(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, fixture = _build(modules)
    route = next(edge for edge in bom["graph"]["edges"]
                 if edge["relationship"] == "ROUTES_TO"
                 and edge["source"] == fixture["names"]["endpoint"])
    review_bases = {"dns-resolution", "sni-header", "deployment-metadata",
                    "kubernetes-ingress", "api-gateway-config", "load-balancer-config",
                    "service-registry", "runtime-observation"}
    probes = [
        _probe("a-name-match-is-refused-as-a-routing-basis",
               _refused(n.routed, endpoint_row=n.endpoint(host="10.0.0.9", port=443,
                                                          evidence_ids=[EVID]),
                        service_row=n.service_of(name="x", evidence_ids=[EVID]),
                        basis="name-match", evidence_ids=[EVID])
               == "ROUTING_BASIS_NOT_EVIDENCE",
               "name-match → ROUTING_BASIS_NOT_EVIDENCE"),
        _probe("every-basis-the-review-names-is-a-basis-the-model-knows",
               review_bases <= set(t.BASES),
               f"{len(review_bases)} of {len(review_bases)} routing bases are classified"),
        _probe("the-routing-edge-carries-its-record",
               bool(route["basis"]) and bool(route["confidence"]) and
               bool(route["evidence_id"]) and route["port"] == 443 and
               route["protocol"] == "TCP" and route["first_seen"] == EARLIER,
               f"{route['relationship']} {route['source']} → {route['target']} "
               f"({route['basis']}, {route['confidence']}, port {route['port']})"),
        _probe("no-edge-in-the-projection-is-missing-its-record",
               bom["graph"]["edges_missing_a_record"] == [],
               f"{bom['graph']['edge_count']} edge(s), "
               f"{len(bom['graph']['edges_missing_a_record'])} incomplete"),
    ]
    return _row("routing-evidence", "what ties an endpoint to the application behind it",
                "2, 16", probes)


def row_tls_boundaries(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, fixture = _build(modules)
    front = n.endpoint(host="10.0.0.1", port=443, tls={"version": "TLS1.3",
                                                       "certificate": "C-1"},
                       evidence_ids=[EVID])
    plain = n.endpoint(host="10.0.0.2", port=80, transport="PLAIN", evidence_ids=[EVID])
    secure = n.endpoint(host="10.0.0.3", port=443, tls={"version": "TLS1.2"},
                        evidence_ids=[EVID])
    cert = n.certificate(name="C-1", subject="CN=x", evidence_ids=[EVID])
    probes = [
        _probe("the-three-modes-are-three-relations",
               set(n.TLS_MODES.values()) == {"TERMINATES_TLS", "RE_ENCRYPTS",
                                             "PASSTHROUGH"} and
               all(relation in t.RELATIONS for relation in n.TLS_MODES.values()),
               "TERMINATES_TLS, RE_ENCRYPTS, PASSTHROUGH"),
        _probe("each-mode-in-the-estate-is-counted-separately",
               bom["tls_modes"] == {"PASSTHROUGH": 1, "RE_ENCRYPTS": 1,
                                    "TERMINATES_TLS": 1},
               f"tls modes: {bom['tls_modes']}"),
        _probe("termination-with-a-tls-upstream-is-refused-as-a-re-encryption",
               _refused(n.tls_hop, frontend=front, backend=secure, mode="TERMINATE",
                        evidence_ids=[EVID]) == "TERMINATION_WITH_TLS_UPSTREAM",
               "TERMINATE with a TLS backend → TERMINATION_WITH_TLS_UPSTREAM"),
        _probe("re-encryption-without-upstream-tls-is-refused",
               _refused(n.tls_hop, frontend=front, backend=plain, mode="RE_ENCRYPT",
                        evidence_ids=[EVID]) == "RE_ENCRYPT_WITHOUT_UPSTREAM_TLS",
               "RE_ENCRYPT onto a plaintext backend → RE_ENCRYPT_WITHOUT_UPSTREAM_TLS"),
        _probe("a-passthrough-may-not-present-a-certificate",
               _refused(n.tls_hop, frontend=front, backend=secure, mode="PASSTHROUGH",
                        certificate=cert, evidence_ids=[EVID])
               == "PASSTHROUGH_WITH_CERTIFICATE",
               "PASSTHROUGH with a certificate → PASSTHROUGH_WITH_CERTIFICATE"),
        _probe("a-waf-that-terminates-tls-is-a-hop-and-a-protection-edge",
               any(edge["source"] == "WAF-01" and edge["relationship"] == "PROTECTS"
                   for edge in bom["graph"]["edges"]) and
               any(edge["source"] == "waf-01:443" and edge["relationship"] ==
                   "TERMINATES_TLS" for edge in bom["graph"]["edges"]),
               "WAF-01 PROTECTS Payments API, waf-01:443 TERMINATES_TLS waf-01:8080"),
    ]
    return _row("tls-boundaries", "is TLS termination a topology or a flag", "3, 12", probes)


def row_certificate_chain(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _build(modules)
    relations = {claim["relation"] for claim in bom["claims"]
                 if claim["from"] == "CERT-001" or claim["to"] == "CERT-001"}
    algorithm = next(row for row in bom["assets"] if row["name"] == "ECDSA P-256")
    probes = [
        _probe("the-certificate-chain-is-five-edges-not-one-row",
               {"CONTAINS_KEY", "USES_ALGORITHM", "SIGNED_WITH", "ISSUED_BY",
                "SIGNED_BY"} <= {claim["relation"] for claim in bom["claims"]},
               "CONTAINS_KEY, USES_ALGORITHM, SIGNED_WITH, ISSUED_BY, SIGNED_BY"),
        _probe("the-curve-and-the-key-size-live-on-the-algorithm-node",
               algorithm["attributes"]["curve"] == "P-256"
               and algorithm["attributes"]["key_size"] == 256,
               "ECDSA P-256: curve P-256, 256 bits"),
        _probe("the-signature-algorithm-is-its-own-dependency",
               any(claim["relation"] == "SIGNED_WITH" and claim["to"] == "ECDSA-SHA256"
                   for claim in bom["claims"]),
               "CERT-001 SIGNED_WITH ECDSA-SHA256"),
        _probe("the-chain-reaches-the-root",
               any(claim["relation"] == "SIGNED_BY" and claim["to"] == "Root CA"
                   for claim in bom["claims"]),
               "Intermediate CA SIGNED_BY Root CA"),
        _probe("the-endpoint-presents-the-certificate-it-was-observed-with",
               "PRESENTS" in relations,
               "waf-01:443 PRESENTS CERT-001"),
    ]
    return _row("certificate-chain", "does a certificate dependency go deeper than its name",
                "4", probes)


def row_negotiated_crypto(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, fixture = _build(modules)
    view = n.negotiated_crypto(bom, query=fixture["names"]["endpoint"])
    negotiated_suites = {row["name"] for row in view["negotiated"]}
    supported_only = {row["name"] for row in view["supported_only"]}
    crypto = {row["name"] for row in view["crypto"]}
    parts = {claim["facts"].get("role") for claim in bom["claims"]
             if claim["relation"] == "USES_CRYPTO" and claim["from"] ==
             "TLS_AES_256_GCM_SHA384"}
    probes = [
        _probe("a-cipher-suite-is-decomposed-into-four-crypto-dependencies",
               parts == {"bulk", "mac", "kex", "auth"} and
               crypto >= {"AES-256-GCM", "SHA-384", "X25519", "ECDSA-P256"},
               "TLS_AES_256_GCM_SHA384 → bulk, mac, kex, auth"),
        _probe("one-suite-was-negotiated-out-of-three-supported",
               negotiated_suites == {"TLS_AES_256_GCM_SHA384"} and
               supported_only == {"TLS_AES_128_GCM_SHA256",
                                  "TLS_CHACHA20_POLY1305_SHA256"},
               f"negotiated {sorted(negotiated_suites)}, supported only "
               f"{len(supported_only)}"),
        _probe("AES-128-is-supported-and-never-reported-as-used",
               "AES-128-GCM" not in crypto
               and any(row["name"] == "TLS_AES_128_GCM_SHA256"
                       for row in view["supported_only"])
               and "AES-128-CBC" in {row["name"] for row in view["runtime_crypto"]},
               "AES-128-GCM is supported-only; AES-128-CBC appears only from the process"),
        _probe("a-capability-list-cannot-claim-what-was-negotiated",
               _refusals_in_build(n, [
                   n.endpoint(host="10.0.0.1", port=443, evidence_ids=[EVID]),
                   fixture["suite_2"]],
                   [t.claim("10.0.0.1:443", "NEGOTIATES", "TLS_AES_128_GCM_SHA256",
                            basis="capability-list", evidence_ids=[EVID])])
               == ["CLAIM_WEAKER_THAN_RELATION_REQUIRES"],
               "capability-list → CLAIM_WEAKER_THAN_RELATION_REQUIRES"),
        _probe("a-configuration-file-cannot-claim-a-session",
               _refused(n.negotiated,
                        endpoint_row=n.endpoint(host="10.0.0.9", port=443,
                                                evidence_ids=[EVID]),
                        suite_row=fixture["suite_2"], basis="config-parse",
                        evidence_ids=[EVID]) == "NEGOTIATION_NEEDS_A_HANDSHAKE",
               "config-parse → NEGOTIATION_NEEDS_A_HANDSHAKE"),
    ]
    return _row("negotiated-crypto", "which cryptography did the session actually use",
                "5–6", probes)


def row_runtime(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, _ = _build(modules)
    runtime_edges = [claim for claim in bom["claims"]
                     if claim["basis"] == "runtime-observation"]
    handshakes = [claim for claim in bom["claims"] if claim["basis"] == "tls-handshake"]
    probes = [
        _probe("the-process-is-a-node-between-the-application-and-its-library",
               any(claim["relation"] == "LOADS" and claim["from"] == "payments-api[1821]"
                   for claim in bom["claims"]),
               "payments-api[1821] LOADS OpenSSL 3.0.13"),
        _probe("a-runtime-observation-is-its-own-class",
               t.RUNTIME_OBSERVED in t.CONFIDENCE and
               {claim["confidence"] for claim in runtime_edges} == {"RUNTIME_OBSERVED"} and
               {claim["confidence"] for claim in handshakes} == {"NETWORK_OBSERVED"},
               f"{len(runtime_edges)} edge(s) RUNTIME_OBSERVED, "
               f"{len(handshakes)} edge(s) NETWORK_OBSERVED"),
        _probe("the-network-cipher-and-the-internal-cipher-are-not-the-same-fact",
               {row["name"] for row in n.negotiated_crypto(
                   bom, query="payments.bank.example:443")["runtime_crypto"]} ==
               {"AES-128-CBC"},
               "443/TLS is AES-256-GCM; the process encrypts with AES-128-CBC"),
        _probe("a-runtime-claim-cannot-be-made-from-a-configuration-file",
               _refusals_in_build(n, [
                   t.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT]),
                   t.asset("CRYPTO_ASSET", "AES-128-CBC", evidence_ids=[EVID_RT],
                           evidence_type="RUNTIME_OBSERVED")],
                   [t.claim("payments-api[1821]", "USES_CRYPTO", "AES-128-CBC",
                            basis="config-parse", evidence_ids=[EVID_RT])])
               == ["EVIDENCE_CLASS_MISMATCH"],
               "config-parse on a RUNTIME_OBSERVED asset → EVIDENCE_CLASS_MISMATCH"),
    ]
    return _row("runtime", "does a network observation prove the application's crypto", "7",
                probes)


def row_keys(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    ref = next(row for row in bom["assets"] if row["kind"] == "KEY_REFERENCE")
    probes = [
        _probe("an-application-reaches-its-hsm-through-an-operation",
               any(claim["relation"] == "USES_HSM" and claim["to"] == "HSM-001"
                   for claim in bom["claims"]),
               "Payments API USES_HSM HSM-001 (operation SIGN)"),
        _probe("the-key-is-a-reference-with-metadata-and-nothing-else",
               ref["name"] == "KEY-REF-8271" and ref["status"] == "ACTIVE"
               and set(ref["attributes"]) >= {"key_ref", "purpose", "algorithm",
                                              "key_size"},
               "KEY-REF-8271: ref, purpose SIGN, RSA-2048, ACTIVE"),
        _probe("key-material-is-refused-by-name",
               _refused(n.key_reference, name="KEY-X", key_ref="arn:x", purpose="SIGN",
                        algorithm="RSA", private_key="MIIEv...") == "KEY_MATERIAL_REFUSED",
               "private_key → KEY_MATERIAL_REFUSED"),
        _probe("a-pem-in-a-fact-is-refused-too",
               _refused(n.key_reference, name="KEY-Y", key_ref="arn:y", purpose="SIGN",
                        algorithm="RSA", note="-----BEGIN PRIVATE KEY-----")
               == "KEY_MATERIAL_REFUSED",
               "a PEM body → KEY_MATERIAL_REFUSED"),
    ]
    return _row("keys", "does the HSM dependency carry keys or metadata", "8", probes)


def row_database(modules: dict[str, Any]) -> dict[str, Any]:
    bom, fixture = _build(modules)
    block = fixture["estate"] and next(
        (item["database_crypto"] for item in _parts_of(modules)), {})
    routes = [claim for claim in bom["claims"]
              if claim["relation"] == "STORES_IN" and claim["to"] == "DB-01"]
    probes = [
        _probe("the-application-reaches-the-database-and-its-port",
               len(routes) == 1 and any(
                   claim["relation"] == "LISTENS_ON" and claim["from"] == "DB-01"
                   and claim["facts"].get("port") == 5432 for claim in bom["claims"]),
               "Payments API STORES_IN DB-01, DB-01 LISTENS_ON db-01:5432"),
        _probe("the-database-session-negotiates-a-suite",
               any(claim["relation"] == "NEGOTIATES" and claim["from"] == "db-01:5432"
                   for claim in bom["claims"]),
               "db-01:5432 NEGOTIATES TLS_AES_256_GCM_SHA384"),
        _probe("tls-in-transit-and-tde-at-rest-are-two-dependencies",
               bool(block) and block["DB-01"]["in_transit"]["version"] == "TLS1.3"
               and block["DB-01"]["at_rest"]["algorithm"] == "AES-256-XTS"
               and block["DB-01"]["distinct"] is True,
               "in transit TLS1.3 / AES-256-GCM; at rest AES-256-XTS"),
        _probe("the-two-are-not-merged-into-one-encrypted-flag",
               block["DB-01"]["in_transit"]["suite"] !=
               block["DB-01"]["at_rest"]["algorithm"],
               "TLS_AES_256_GCM_SHA384 ≠ AES-256-XTS"),
    ]
    return _row("database", "is DB TLS the same dependency as DB TDE", "9", probes)


def _parts_of(modules: dict[str, Any]) -> list[dict[str, Any]]:
    n, t = modules["n"], modules["t"]
    return [n.database_dependency(
        application_row=t.asset("APPLICATION", "Payments API", evidence_ids=[EVID]),
        database_row=t.asset("DATABASE", "DB-01", evidence_ids=[EVID_DB]),
        endpoint_row=n.endpoint(host="10.20.0.5", port=5432, name="db-01:5432",
                                tls={"version": "TLS1.3",
                                     "suite": "TLS_AES_256_GCM_SHA384"},
                                evidence_ids=[EVID_DB]),
        tde={"algorithm": "AES-256-XTS", "enabled": True}, evidence_ids=[EVID_DB])]


def row_mesh(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    terminator = n.tls_terminator(bom, endpoint_query="payments-api:8443")
    probes = [
        _probe("the-sidecar-proxies-the-application",
               any(claim["relation"] == "PROXY_FOR" and
                   claim["from"] == "envoy-sidecar" for claim in bom["claims"]),
               "envoy-sidecar PROXY_FOR Payments API"),
        _probe("the-mesh-authenticates-what-it-proxies",
               any(claim["relation"] == "AUTHENTICATES" and
                   claim["from"] == "MESH-01" for claim in bom["claims"]),
               "MESH-01 AUTHENTICATES Payments API (mTLS, bank.internal)"),
        _probe("the-mtls-certificate-belongs-to-the-proxy-not-the-application",
               any(claim["relation"] == "USES_CERTIFICATE" and
                   claim["from"] == "envoy-sidecar" and claim["to"] == "CERT-MESH-001"
                   for claim in bom["claims"]) and
               not any(claim["relation"] == "USES_CERTIFICATE" and
                       claim["from"] == "Payments API" for claim in bom["claims"]),
               "envoy-sidecar USES_CERTIFICATE CERT-MESH-001; the application holds none"),
        _probe("the-trust-domain-travels-with-the-edge",
               any((claim["facts"] or {}).get("trust_domain") == "bank.internal"
                   for claim in bom["claims"] if claim["relation"] == "PROXY_FOR"),
               "trust_domain=bank.internal on PROXY_FOR"),
        _probe("who-terminated-the-handshake-is-a-question-with-an-answer",
               terminator["holders"] and all(
                   row["kind"] in ("NETWORK_ENDPOINT", "PROCESS", "LOAD_BALANCER",
                                   "API_GATEWAY", "WAF", "SERVICE_MESH", "DATABASE",
                                   "APPLICATION")
                   for row in terminator["holders"]),
               terminator["statement"]),
    ]
    return _row("mesh", "does the sidecar do the TLS, or the application", "10", probes)


def row_gateway_waf(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _build(modules)
    route = next((claim for claim in bom["claims"]
                  if claim["relation"] == "ROUTES_TO" and claim["from"] == "API-GW-01"),
                 None)
    probes = [
        _probe("the-gateway-routes-to-the-application-with-its-own-config-as-evidence",
               route is not None and route["basis"] == "api-gateway-config"
               and route["facts"].get("route") == "/v1/payments",
               "API-GW-01 ROUTES_TO Payments API via api-gateway-config"),
        _probe("the-waf-protects-what-it-fronts",
               any(claim["relation"] == "PROTECTS" and claim["from"] == "WAF-01"
                   and claim["to"] == "Payments API" for claim in bom["claims"]),
               "WAF-01 PROTECTS Payments API"),
        _probe("the-chain-from-the-internet-reaches-the-application-in-order",
               any(claim["relation"] == "TERMINATES_TLS" and claim["from"] == "waf-01:443"
                   for claim in bom["claims"])
               and any(claim["relation"] == "RE_ENCRYPTS" and claim["from"] == "lb-01:443"
                       for claim in bom["claims"])
               and any(claim["relation"] == "PASSTHROUGH"
                       and claim["from"] == "mesh-ingress:15006"
                       for claim in bom["claims"]),
               "waf terminate → lb re-encrypt → mesh passthrough"),
        _probe("every-listener-names-the-device-that-owns-it",
               {"WAF-01", "LB-01", "API-GW-01"} <= {claim["from"] for claim in bom["claims"]
                                                    if claim["relation"] == "LISTENS_ON"},
               "WAF-01, LB-01 and API-GW-01 each LISTENS_ON their own port"),
    ]
    return _row("gateway-waf", "do the boxes in the path say how they are in the path",
                "11–12", probes)


def row_ssh(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _build(modules)
    roles = {claim["facts"].get("role") for claim in bom["claims"]
             if claim["relation"] == "NEGOTIATES" and claim["from"] ==
             "sshd@srv-payments-01"}
    probes = [
        _probe("ssh-is-four-negotiated-parameters-not-a-version",
               roles == {"kex", "host-key", "cipher", "mac"},
               "X25519, Ed25519, ChaCha20-Poly1305, HMAC-SHA2-256"),
        _probe("the-ssh-service-listens-on-a-port-and-runs-on-a-host",
               any(claim["relation"] == "LISTENS_ON" and claim["from"] ==
                   "sshd@srv-payments-01" and claim["facts"].get("port") == 22
                   for claim in bom["claims"])
               and any(claim["relation"] == "RUNS_ON" and claim["from"] ==
                       "sshd@srv-payments-01" for claim in bom["claims"]),
               "sshd@srv-payments-01 LISTENS_ON :22 and RUNS_ON srv-payments-01"),
        _probe("the-ssh-parameters-are-network observations-not-capability-claims",
               {claim["confidence"] for claim in bom["claims"]
                if claim["relation"] == "NEGOTIATES" and claim["from"] ==
                "sshd@srv-payments-01"} == {"NETWORK_OBSERVED"},
               "banner-read parameters are NETWORK_OBSERVED"),
    ]
    return _row("ssh", "is SSH a port or a set of negotiated algorithms", "13", probes)


def row_vpn(modules: dict[str, Any]) -> dict[str, Any]:
    bom, _ = _build(modules)
    negotiated = {claim["to"] for claim in bom["claims"]
                  if claim["relation"] == "NEGOTIATES" and claim["from"] ==
                  "branch-to-payments"}
    supported = {claim["to"] for claim in bom["claims"]
                 if claim["relation"] == "SUPPORTS" and claim["from"] ==
                 "branch-to-payments"}
    probes = [
        _probe("the-tunnel-negotiates-encryption-integrity-and-a-dh-group",
               {"AES-256", "SHA-256", "DH-Group-19", "CERT-VPN-001"} == negotiated,
               f"negotiated {sorted(negotiated)}"),
        _probe("what-the-gateway-would-accept-is-kept-apart-from-what-it-uses",
               supported == {"AES-128 proposal", "SHA-1 proposal"}
               and not supported & negotiated,
               f"supported {sorted(supported)}, negotiated {sorted(negotiated)}"),
        _probe("the-tunnel-ends-in-a-network-zone",
               any(claim["relation"] == "TUNNELS_TO" and claim["to"] == "Payment Network"
                   for claim in bom["claims"]),
               "branch-to-payments TUNNELS_TO Payment Network"),
        _probe("the-tunnel-reads-its-ike-version-from-the-tunnel-not-from-prose",
               next(row for row in bom["assets"]
                    if row["name"] == "branch-to-payments")["attributes"]["ike_version"] ==
               "IKEv2",
               "IKEv2"),
    ]
    return _row("vpn", "does the IPsec dependency reach the zone and the algorithms", "14",
                probes)


def row_topology(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    edges = bom["graph"]["edges"]
    # a listener, a route or a TLS boundary is a claim about a port; a tunnel's IKE
    # parameters are not, so the rule is scoped to the relations that name one
    listener_relations = ("ROUTES_TO", "FORWARDS_TO", "LISTENS_ON", "TERMINATES_TLS",
                          "RE_ENCRYPTS", "PASSTHROUGH")
    network_edges = [edge for edge in edges
                     if edge["relationship"] in listener_relations or
                     (edge["relationship"] == "NEGOTIATES" and
                      edge["source_kind"] in ("NETWORK_ENDPOINT", "SSH_SERVICE",
                                              "DATABASE", "IPSEC_TUNNEL", "SSH_SERVICE"))]
    with_port = [edge for edge in network_edges if edge["port"] not in (None, "")]
    probes = [
        _probe("the-projection-is-a-graph-not-a-list",
               bom["graph"]["node_count"] > 20 and bom["graph"]["edge_count"] > 30,
               f"{bom['graph']['node_count']} node(s), {bom['graph']['edge_count']} edge(s)"),
        _probe("every-network-edge-carries-a-port-and-a-protocol",
               len(with_port) == len(network_edges),
               f"{len(with_port)} of {len(network_edges)} network edge(s) name a port"),
        _probe("the-adjacency-can-be-walked-from-the-internet-inward",
               any(row["to"] == "DB-01" for row in bom["graph"]["adjacency"].get(
                   "Payments API", []))
               and any(row["to"] == "HSM-001" for row in bom["graph"]["adjacency"].get(
                   "Payments API", [])),
               "Payments API → DB-01 and Payments API → HSM-001"),
        _probe("the-edge-record-carries-the-fields-the-review-names",
               all(field in edge for edge in edges for field in
                   ("source", "target", "relationship", "protocol", "port",
                    "evidence_id", "confidence", "first_seen", "last_seen")),
               f"{len(n.EDGE_FIELDS)} field(s) on each of {len(edges)} edge(s)"),
    ]
    return _row("topology", "is the network a list of endpoints or a graph", "15–16",
                probes)


def row_lifecycle(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, fixture = _build(modules)
    state = n.lifecycle(bom, reference=NOW)
    second = dict(fixture["estate"])
    second_claims = []
    for claim in fixture["estate"]["claims"]:
        row = dict(claim)
        if row["relation"] == "ROUTES_TO" and row["from"] == "payments.bank.example:443":
            row["to"] = "payments-api-v2"
        second_claims.append(row)
    second["claims"] = second_claims
    second["assets"] = [*second["assets"], t.asset("SERVICE", "payments-api-v2",
                                                   evidence_ids=[EVID])]
    moved = n.build(second)
    drift = n.drift(bom, moved, reference=NOW)
    probes = [
        _probe("an-edge-seen-once-and-an-edge-seen-twice-are-different-states",
               {"FIRST_SEEN", "ACTIVE"} <= set(state["counts"]),
               "lifecycle: " + ", ".join(f"{count} {name}" for name, count
                                         in state["counts"].items())),
        _probe("an-edge-with-no-timestamps-is-unknown-not-active",
               state["counts"].get("UNKNOWN", 0) > 0,
               f"{state['counts'].get('UNKNOWN', 0)} edge(s) UNKNOWN"),
        _probe("an-edge-that-moved-is-superseded-not-removed-and-added",
               drift["by_change"].get("EDGE_SUPERSEDED") == 1
               and "EDGE_REMOVED" not in drift["by_change"]
               and "EDGE_ADDED" not in drift["by_change"],
               drift["statement"]),
        _probe("the-superseded-edge-names-both-targets",
               next(event for event in drift["events"]
                    if event["change"] == "EDGE_SUPERSEDED")["previous_target"] ==
               "payments-api",
               "LB/SNI edge: payments-api → payments-api-v2"),
        _probe("every-change-carries-its-crypto-impact",
               all("crypto_impact" in event for event in drift["events"]),
               f"{len(drift['events'])} event(s), each with a crypto impact block"),
    ]
    return _row("lifecycle", "does a relationship have a life", "17", probes)


def row_twin(modules: dict[str, Any]) -> dict[str, Any]:
    n, t = modules["n"], modules["t"]
    bom, _ = _build(modules)
    twin = n.twin(bom)
    probes = [
        _probe("the-twin-knows-who-connects-to-whom-and-how",
               bool(twin["who_connects_to_whom"]) and bool(twin["how"]),
               f"{len(twin['who_connects_to_whom'])} pair(s), {len(twin['how'])} "
               "relationship/protocol combination(s)"),
        _probe("the-twin-carries-certificates-keys-and-applications",
               bool(twin["certificates"]) and twin["keys"] and twin["applications"],
               f"{len(twin['certificates'])} certificate edge(s), keys {twin['keys']}"),
        _probe("a-projection-cannot-be-its-own-source",
               _refused(n.from_document, bom) == "PROJECTION_AS_SOURCE",
               "NBOM as input → PROJECTION_AS_SOURCE"),
        _probe("a-techbom-cannot-build-an-nbom-either",
               _refused(n.build, {"schema": t.SCHEMA, "assets": [], "claims": []})
               == "ValueError",
               "TechBOM as estate → ValueError"),
    ]
    return _row("twin", "is NBOM a projection of the twin or a second database", "18",
                probes)


def row_vendor_hardware(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, _ = _build(modules)
    probes = [
        _probe("a-load-balancer-has-a-vendor-a-product-and-a-firmware",
               any(claim["relation"] == "HAS_MODEL" and claim["from"] == "LB-01"
                   for claim in bom["claims"])
               and any(claim["relation"] == "RUNS_FIRMWARE" and claim["from"] == "LB-01"
                       for claim in bom["claims"])
               and any(claim["relation"] == "SUPPLIED_BY" for claim in bom["claims"]),
               "LB-01 → F5 BIG-IP i5800 → firmware 17.1.1 → F5"),
        _probe("the-vendor-chain-reaches-the-vendor-node",
               any(row["kind"] == "VENDOR" and row["name"] == "F5"
                   for row in bom["assets"]),
               "VENDOR F5 in the estate"),
        _probe("a-network-device-sits-on-hardware",
               any(claim["relation"] == "RUNS_ON" and claim["from"] == "LB-01"
                   and claim["to"] == "SRV-PAY-01" for claim in bom["claims"]),
               "LB-01 RUNS_ON SRV-PAY-01"),
        _probe("the-endpoint-reaches-the-device-that-owns-it",
               any(claim["relation"] == "LISTENS_ON" and claim["to"] == "lb-01:443"
                   for claim in bom["claims"]),
               "LB-01 LISTENS_ON lb-01:443"),
        _probe("a-device-kind-the-model-does-not-build-is-refused",
               _refused(n.network_device, kind="ROUTER", name="R-01", vendor="Cisco",
                        product="ASR", evidence_ids=[EVID]) == "NOT_A_NETWORK_DEVICE",
               "ROUTER → NOT_A_NETWORK_DEVICE"),
    ]
    return _row("vendor-hardware", "does the network join VBOM and HBOM", "19–20", probes)


def row_coverage(modules: dict[str, Any]) -> dict[str, Any]:
    n = modules["n"]
    bom, fixture = _build(modules)
    coverage = bom["coverage"]
    probes = [
        _probe("coverage-is-reported-with-its-denominator",
               coverage["expected"] == 500 and coverage["observed"] == 420,
               coverage["statement"]),
        _probe("an-unavailable-endpoint-makes-the-verdict-partial",
               coverage["verdict"] == "PARTIAL",
               "PARTIAL with 50 unavailable and 30 unknown"),
        _probe("partial-propagates-to-every-view-that-reads-the-projection",
               set(coverage["propagates"].values()) == {"PARTIAL"},
               "nbom, cbom network evidence and the twin all PARTIAL"),
        _probe("coverage-that-does-not-add-up-is-refused",
               _refused(n.coverage, expected=100, observed=80, unavailable=40)
               == "COVERAGE_DOES_NOT_RECONCILE",
               "80 + 40 out of 100 → COVERAGE_DOES_NOT_RECONCILE"),
        _probe("an-unavailable-endpoint-is-not-dropped-from-the-denominator",
               coverage["unavailable"] == 50 and coverage["expected"] ==
               coverage["observed"] + coverage["unavailable"] + coverage["unknown"],
               "420 observed + 50 unavailable + 30 unknown = 500 expected"),
    ]
    return _row("coverage", "does coverage propagate, or does it get rounded to healthy",
                "21", probes)


def row_spine(modules: dict[str, Any]) -> dict[str, Any]:
    t = modules["t"]
    bom, fixture = _build(modules)
    chain = bom["chains"][fixture["names"]["endpoint"]]
    vocabulary = ("CONNECTS_TO", "ROUTES_TO", "TERMINATES_TLS", "RE_ENCRYPTS",
                  "PASSTHROUGH", "PROTECTS", "AUTHENTICATES", "USES_CERTIFICATE",
                  "USES_HSM", "USES_KMS")
    probes = [
        _probe("the-review-s-whole-vocabulary-exists",
               all(relation in t.RELATIONS for relation in vocabulary),
               f"{len(vocabulary)} of {len(vocabulary)} relations exist"),
        _probe("the-chain-reaches-the-business-system-the-database-and-the-keys",
               bool(chain["levels"]["system"]) and bool(chain["levels"]["database"])
               and bool(chain["levels"]["keys"]),
               chain["statement"]),
        _probe("the-chain-also-reaches-the-crypto-behind-the-session",
               bool(chain["levels"]["crypto"]),
               f"{len(chain['levels']['crypto'])} crypto node(s) behind the endpoint"),
        _probe("every-layer-of-the-review-s-stack-is-a-kind-in-one-graph",
               all(kind in t.ASSET_TYPES for kind in
                   ("BUSINESS_SYSTEM", "APPLICATION", "PROCESS", "SERVICE",
                    "NETWORK_ENDPOINT", "WAF", "LOAD_BALANCER", "API_GATEWAY",
                    "SERVICE_MESH", "DATABASE", "HSM", "KMS", "CRYPTO_ASSET", "VENDOR")),
               "14 layers, one ASSET_TYPES tuple"),
        _probe("no-edge-in-the-graph-was-drawn-without-a-basis",
               all(claim["basis"] for claim in bom["claims"]),
               f"{len(bom['claims'])} edge(s), each with a basis"),
    ]
    return _row("spine", "does the biggest missing chain exist end to end", "22", probes)


ROWS = (
    row_endpoint_identity, row_routing_evidence, row_tls_boundaries, row_certificate_chain,
    row_negotiated_crypto, row_runtime, row_keys, row_database, row_mesh, row_gateway_waf,
    row_ssh, row_vpn, row_topology, row_lifecycle, row_twin, row_vendor_hardware,
    row_coverage, row_spine,
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
        "counts_by_kind": bom["counts"],
        "graph": {"nodes": bom["graph"]["node_count"], "edges": bom["graph"]["edge_count"],
                  "edges_missing_a_record": bom["graph"]["edges_missing_a_record"]},
        "tls_modes": bom["tls_modes"],
        "negotiated": n.negotiated_crypto(bom, query=fixture["names"]["endpoint"]),
        "chain": bom["chains"][fixture["names"]["endpoint"]],
        "coverage": bom["coverage"],
        "lifecycle": bom["lifecycle"]["counts"],
        "refusals": bom["refusals"],
        "rows": rows,
        "limits": [
            "the fixture is the review's own example estate, not a bank's collector "
            "output: the shapes are real, the rows are not",
            "a routing edge is only as good as its basis: an SNI value ties a name to a "
            "listener, and this model does not resolve DNS itself",
            "supported, negotiated and used are separated as relations, but a suite's "
            "negotiation is one observation, and a session that was never captured leaves "
            "only the policy behind it",
            "the sidecar is modelled as a process because that is what presents the "
            "certificate; a mesh that terminates outside a sidecar needs its own collector",
            "coverage is only as honest as the denominator, which comes from a CMDB the "
            "platform does not own",
            "a tunnel's parameters are read from configuration unless a status poll "
            "supplied them, and the two are told apart by evidence class",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    negotiated = report["negotiated"]
    chain = report["chain"]
    coverage = report["coverage"]
    lines = [
        "# The network is a graph",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        "The NBOM review's twenty-two points, answered by putting the network into the",
        "graph the rest of the estate lives in. An address is a location, the backend is a",
        "claim with a named basis, and TLS termination is a topology.",
        "",
        "```",
        "endpoint → service      ROUTES_TO          from SNI, DNS, ingress, gateway config",
        "endpoint → suite        NEGOTIATES         a handshake, or a capture of one",
        "endpoint → suite        SUPPORTS           what the listener would accept",
        "suite → crypto          USES_CRYPTO        bulk, mac, kex, auth — four assets",
        "l1 → l2                 TERMINATES_TLS     TLS ends here, plaintext onwards",
        "l1 → l2                 RE_ENCRYPTS        TLS again, possibly weaker",
        "l1 → l2                 PASSTHROUGH        the handshake crosses untouched",
        "proxy → application     PROXY_FOR          the TLS belongs to the proxy",
        "```",
        "",
        report["statement"],
        "",
        "## What the projection holds",
        "",
        "| kind | rows |",
        "|---|---|",
        *[f"| `{kind}` | {count} |" for kind, count in sorted(
            report["counts_by_kind"].items())],
        "",
        f"**Negotiated crypto** — {negotiated['statement']}",
        "",
        "| suite | state |",
        "|---|---|",
        *[f"| `{row['name']}` | negotiated |" for row in negotiated["negotiated"]],
        *[f"| `{row['name']}` | supported only |" for row in negotiated["supported_only"]],
        "",
        f"**The chain from the endpoint** — {chain['statement']}",
        "",
        f"**Coverage** — {coverage['statement'] if coverage else 'not supplied'}",
        "",
        "| lifecycle state | edges |",
        "|---|---|",
        *[f"| `{state}` | {count} |" for state, count in report["lifecycle"].items()],
        "",
        "| Row | Question | Verdict | Probes |",
        "|---|---|---|---|",
    ]
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
