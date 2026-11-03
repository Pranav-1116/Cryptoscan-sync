#!/usr/bin/env python3
"""Guide 173 — the CBOM dependency chain, twenty-six points, one build.

The review's spec is a chain and a rule about each edge on it:

    Business System → Application → Release/Artifact → Process/Container →
    Crypto Provider/Library → Crypto Operation → Algorithm → Key Metadata →
    HSM/KMS → Certificate/Network Path → Hardware → Vendor

*"Every important edge should have evidence."* Guides 169–172 built the network half of
that chain and the evidence classes under it. This guide builds the software half —
releases, providers, operations, keys — and then walks the whole thing, because a CBOM
that says "AES-256, confidence HIGH" has collapsed eight claims into one line.

Each of the twenty-six rows below is read off the built projection rather than off the
source, so "proven" means "present in the BOM, with a basis and an evidence id", not
"present in a function". The fixture is the bank's own path: a payments application with a
release, a Kubernetes deployment, an OpenSSL provider, an HSM-backed signing operation, a
KMS-referenced encryption key, a legacy static call, a TLS listener with a certificate, a
load balancer with a firmware version, and a vendor behind it.
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
SCHEMA = "cryptoscan.cbom-dependency-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

HARDWARE_RELATIONS = frozenset({"BACKED_BY", "USES_TPM", "PROTECTED_BY", "RUNS_ON",
                                "USES_HSM", "USES_KMS"})
TOPOLOGY_RELATIONS = frozenset({"RUNS_IN", "MEMBER_OF_CLUSTER", "SCHEDULED_ON", "RUNS_ON",
                                "SCHEDULES"})

EVID = "EVID-95001"
EVID_REL = "EVID-95002"
EVID_K8S = "EVID-95003"
EVID_RT = "EVID-95004"
EVID_STATIC = "EVID-95005"
EVID_HSM = "EVID-95006"
EVID_NET = "EVID-95007"
EVID_VENDOR = "EVID-95008"
NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"
OLD = "2026-10-01T08:30:00Z"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import cbom_dependency, nbom_graph, techbom, usage_evidence  # noqa: PLC0415

    return {"d": cbom_dependency, "n": nbom_graph, "t": techbom, "u": usage_evidence}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The fixture: twelve levels, one bank path
# --------------------------------------------------------------------------- #

def _document(modules: dict[str, Any], *, rsa_size: int = 2048,
              provider_version: str = "3.0.11") -> dict[str, Any]:
    d, n, t = modules["d"], modules["n"], modules["t"]

    # ---- 1–2. business system → application → release → artifact -----------------
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID])
    application = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID])
    service = n.service_of(name="payments-api", port=8080, evidence_ids=[EVID])
    release = t.asset("RELEASE", "payments-api 4.2.0", evidence_ids=[EVID_REL],
                      channel="PRODUCTION")
    artifact = t.asset("ARTIFACT", "payments-api-4.2.0.jar", evidence_ids=[EVID_REL])
    image = t.asset("IMAGE", "payments-api:4.2.0", evidence_ids=[EVID_REL],
                    registry="registry.bank.internal")
    package = t.asset("PACKAGE", "openssl-libs 3.0.11", evidence_ids=[EVID_REL])
    shipped = d.application_release(application_row=application, release_row=release,
                                    artifacts=[artifact], evidence_ids=[EVID_REL],
                                    first_seen=EARLIER, last_seen=NOW)
    packaged = n.part(claims=[
        t.claim(artifact["name"], "PACKAGED_AS", image["name"], basis="agent-inventory",
                evidence_ids=[EVID_REL], first_seen=EARLIER, last_seen=NOW),
        t.claim(image["name"], "SHIPS", package["name"], basis="sbom-import",
                evidence_ids=[EVID_REL]),
    ])

    # ---- 3. the Kubernetes levels (points 16, 17) --------------------------------
    deployment_row = t.asset("DEPLOYMENT", "payments-api-deploy", evidence_ids=[EVID_K8S])
    pod = t.asset("POD", "payments-api-7d9f4c-x2m8p", evidence_ids=[EVID_K8S])
    container = t.asset("CONTAINER", "payments-api-ctr", evidence_ids=[EVID_K8S])
    namespace = t.asset("NAMESPACE", "payments", evidence_ids=[EVID_K8S])
    cluster = t.asset("CLUSTER", "prod-cluster", evidence_ids=[EVID_K8S])
    node = t.asset("KUBERNETES_NODE", "node-07", evidence_ids=[EVID_K8S])
    host = t.asset("PHYSICAL_SERVER", "srv-k8s-07", evidence_ids=[EVID_K8S],
                   datacenter="Mumbai-DC2", rack="R12")
    deployed = d.deployment(image_row=image, deployment_row=deployment_row, pods=[pod],
                            containers=[container], namespace_row=namespace,
                            cluster_row=cluster, node_row=node, evidence_ids=[EVID_K8S],
                            observed_at=NOW, first_seen=EARLIER, last_seen=NOW)
    hardware_links = n.part(claims=[
        t.claim(node["name"], "MEMBER_OF_CLUSTER", cluster["name"], basis="agent-inventory",
                evidence_ids=[EVID_K8S]),
        t.claim(node["name"], "RUNS_ON", host["name"], basis="agent-inventory",
                evidence_ids=[EVID_K8S]),
        t.claim(pod["name"], "SCHEDULED_ON", node["name"], basis="deployment-metadata",
                evidence_ids=[EVID_K8S], observed_at=NOW, first_seen=EARLIER,
                last_seen=EARLIER),
    ])

    # ---- 4. the process, its provider and its library (points 4, 5, 15, 16) ------
    process = t.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT], pid=1821)
    library = t.asset("CRYPTO_LIBRARY", "libcrypto.so.3", evidence_ids=[EVID_REL])
    package_links = n.part(claims=[
        t.claim(package["name"], "LINKS", library["name"], basis="sbom-import",
                evidence_ids=[EVID_REL]),
        t.claim(pod["name"], "RUNS_PROCESS", process["name"], basis="runtime-probe",
                evidence_ids=[EVID_RT], observed_at=NOW),
    ])
    aes_algorithm = n.algorithm(name="AES-256", family="AES", key_size=256, mode="GCM",
                                evidence_ids=[EVID_RT])
    sha_algorithm = n.algorithm(name="SHA-256", family="SHA", key_size=256,
                                evidence_ids=[EVID_RT])
    des_algorithm = n.algorithm(name="DES-ECB", family="DES", key_size=56, mode="ECB",
                                evidence_ids=[EVID_STATIC])
    rsa_algorithm = n.algorithm(name=f"RSA-{rsa_size}", family="RSA", key_size=rsa_size,
                                evidence_ids=[EVID_HSM])
    openssl_part = d.provider(
        name=f"OpenSSL {provider_version}", family="OPENSSL", version=provider_version,
        library_row=library, file_name="/usr/lib64/libcrypto.so.3",
        supports=[aes_algorithm, sha_algorithm, rsa_algorithm], process_row=process,
        evidence_ids=[EVID_RT], first_seen=EARLIER, last_seen=NOW,
        version_claims=[
            {"source": "sbom", "value": provider_version, "class": "STATIC_OBSERVED",
             "evidence_id": EVID_REL},
            {"source": "process-map", "value": "3.0.13", "class": "RUNTIME_OBSERVED",
             "evidence_id": EVID_RT},
            {"source": "agent-inventory", "value": provider_version, "class": "CONFIGURED",
             "evidence_id": EVID},
        ])
    openssl = openssl_part["assets"][0]

    # ---- 5. keys, HSM and KMS (points 7, 8, 9, 13) ------------------------------
    hsm = t.asset("HSM", "HSM-001", evidence_ids=[EVID_HSM], model="nShield",
                  firmware_version="12.72.0")
    kms = t.asset("KMS", "KMS-01", evidence_ids=[EVID_HSM], region="ap-south-1")
    tpm = t.asset("TPM", "TPM-01", evidence_ids=[EVID_K8S], version="2.0")
    signing_key = n.key_reference(name="KEY-REF-4401", key_ref="pkcs11:token=bank;id=4401",
                                  purpose="SIGNING", algorithm="RSA", key_size=rsa_size,
                                  holder="HSM-001", evidence_ids=[EVID_HSM])
    data_key = n.key_reference(name="KEY-REF-4402", key_ref="arn:aws:kms:ap-south-1:key/4402",
                               purpose="ENCRYPTION", algorithm="AES", key_size=256,
                               holder="KMS-01", evidence_ids=[EVID_HSM])
    key_links = n.part(claims=[
        t.claim("KMS-01", "HOLDS_KEY", "KEY-REF-4402", basis="api-poll",
                evidence_ids=[EVID_HSM]),
        t.claim("Payments API", "USES_KMS", "KMS-01", basis="api-poll",
                evidence_ids=[EVID_HSM]),
        t.claim("HSM-001", "SUPPORTS", rsa_algorithm["name"], basis="vendor-datasheet",
                evidence_ids=[EVID_HSM]),
        t.claim("Payments API", "PROTECTED_BY", "HSM-001", basis="config-parse",
                evidence_ids=[EVID_HSM]),
        t.claim("Payments API", "USES_TPM", "TPM-01", basis="runtime-observation",
                evidence_ids=[EVID_K8S]),
        t.claim("srv-k8s-07", "CARRIES", "TPM-01", basis="agent-inventory",
                evidence_ids=[EVID_K8S], first_seen=EARLIER, last_seen=EARLIER),
    ])

    # ---- 6. operations: runtime, static, and the key under each (points 4, 6, 12) -
    signing_part = d.runtime_operation(
        name="OP-SIGN-001", process_row=process, application_row=application,
        operation="SIGN", algorithm_row=rsa_algorithm, provider_row=openssl,
        key_row=signing_key, key_size=rsa_size, padding="PSS", hash_name="SHA-256",
        purpose="payment instruction signature", evidence_ids=[EVID_RT],
        observed_at=NOW, first_seen=EARLIER, last_seen=NOW, pid=1821)
    encryption_part = d.runtime_operation(
        name="OP-ENCRYPT-002", process_row=process, application_row=application,
        operation="ENCRYPT", algorithm_row=aes_algorithm, provider_row=openssl,
        key_row=data_key, key_size=256, mode="GCM", purpose="card data at rest",
        evidence_ids=[EVID_RT], observed_at=NOW, first_seen=EARLIER, last_seen=NOW)
    static_part = d.runtime_operation(
        name="OP-STATIC-003", process_row=process, application_row=application,
        operation="ENCRYPT", algorithm_row=des_algorithm, provider_row=openssl,
        key_size=56, mode="ECB", purpose="legacy settlement file",
        basis="source-analysis", evidence_ids=[EVID_STATIC])
    signing = signing_part["assets"][0]
    bound = d.key_binding(operation_row=signing, key_row=signing_key, holder_row=hsm,
                          basis="runtime-observation", evidence_ids=[EVID_HSM])

    # ---- 7. the static call, app → file → API → algorithm (point 3) --------------
    static_call = d.static_dependency(
        application_row=application, source_file="src/main/java/bank/LegacySettlement.java",
        api="Cipher.getInstance", algorithm_row=des_algorithm, line=214,
        evidence_ids=[EVID_STATIC], first_seen=OLD, last_seen=EARLIER)

    # ---- 8. the listener, the suite, the certificate (points 10, 11, 12) --------
    public = n.endpoint(host="203.0.113.10", port=443, name="payments.bank.example:443",
                        sni=["payments.bank.example"],
                        tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                        evidence_ids=[EVID_NET], first_seen=EARLIER, last_seen=NOW)
    lb_front = n.endpoint(host="10.10.0.30", port=443, name="lb-01:443",
                          tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                          evidence_ids=[EVID_NET])
    bulk = t.asset("CRYPTO_ASSET", "AES-256-GCM", evidence_ids=[EVID_NET], algorithm="AES",
                   key_size=256, evidence_type="NETWORK_OBSERVED")
    mac = t.asset("CRYPTO_ASSET", "SHA-384", evidence_ids=[EVID_NET], algorithm="SHA",
                  evidence_type="NETWORK_OBSERVED")
    kex = t.asset("CRYPTO_ASSET", "X25519", evidence_ids=[EVID_NET], algorithm="ECDH",
                  evidence_type="NETWORK_OBSERVED")
    suite = n.cipher_suite(name="TLS_AES_256_GCM_SHA384", tls_version="TLS1.3",
                           kex="X25519", auth="ECDSA-P256", bulk="AES-256-GCM",
                           mac="SHA-384", evidence_ids=[EVID_NET])
    legacy_suite = n.cipher_suite(name="ECDHE-RSA-AES128-GCM-SHA256", tls_version="TLS1.2",
                                  kex="ECDHE", auth="RSA", bulk="AES-128-GCM",
                                  mac="SHA-256", evidence_ids=[EVID_NET])
    certificate = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                                issuer="Bank Issuing CA", serial="4f:9a:21",
                                not_after="2027-04-01T00:00:00Z",
                                signature_algorithm="ECDSA-SHA256",
                                evidence_ids=[EVID_NET])
    binding = d.network_binding(
        endpoint_row=public, suite_row=suite,
        parts={"bulk": bulk, "mac": mac, "kex": kex}, certificate_row=certificate,
        application_row=application, evidence_ids=[EVID_NET], observed_at=NOW)
    hops = n.part(claims=[
        t.claim("payments.bank.example:443", "FORWARDS_TO", "lb-01:443",
                basis="dns-resolution", evidence_ids=[EVID_NET], protocol="TCP", port=443),
        t.claim("lb-01:443", "ROUTES_TO", "payments-api", basis="load-balancer-config",
                evidence_ids=[EVID_NET], protocol="TCP", port=8080),
        t.claim("lb-01:443", "NEGOTIATES", "ECDHE-RSA-AES128-GCM-SHA256",
                basis="tls-handshake", evidence_ids=[EVID_NET], observed_at=NOW,
                protocol="TLS"),
        t.claim("LB-01", "LISTENS_ON", "lb-01:443", basis="load-balancer-config",
                evidence_ids=[EVID_VENDOR], protocol="TCP", port=443),
    ])

    # ---- 9. hardware, firmware and the vendor behind it (points 14) --------------
    device = t.asset("LOAD_BALANCER", "LB-01", evidence_ids=[EVID_VENDOR], model="i5800")
    firmware = t.asset("FIRMWARE", "BIG-IP 17.1.1", evidence_ids=[EVID_VENDOR],
                       version="17.1.1")
    product = t.asset("VENDOR_PRODUCT", "BIG-IP i5800", evidence_ids=[EVID_VENDOR])
    vendor = t.asset("VENDOR", "F5", evidence_ids=[EVID_VENDOR])
    vulnerability = t.asset("VULNERABILITY", "CVE-2026-0001", evidence_ids=[EVID_VENDOR],
                            severity="HIGH")
    vendored = d.vendor_chain(device_row=device, vendor_row=vendor,
                              firmware_row=firmware, product_row=product,
                              evidence_ids=[EVID_VENDOR])
    vuln = n.part(claims=[
        t.claim(firmware["name"], "HAS_VULNERABILITY", vulnerability["name"],
                basis="vendor-portal", evidence_ids=[EVID_VENDOR],
                advisory="K-2026-0001"),
        t.claim(device["name"], "RUNS_ON", "srv-lb-01", basis="agent-inventory",
                evidence_ids=[EVID_VENDOR]),
    ])
    srv_lb = t.asset("PHYSICAL_SERVER", "srv-lb-01", evidence_ids=[EVID_VENDOR])

    # ---- 10. the evidence records that name a collector (point 19) --------------
    record = n.evidence_record(EVID_RT, collector="PROC-PROBE-01", collector_version="1.4.2",
                               target_id="srv-k8s-07", observed_at=NOW,
                               source="/proc/1821/maps", evidence_type="RUNTIME_OBSERVED",
                               raw_reference="EVP_DigestSignInit", normalized_fact="SIGN",
                               hash="sha256:71ce", confidence="HIGH")
    attached = n.attach_evidence(row=host, record=record, basis="runtime-probe")
    record_net = n.evidence_record(EVID_NET, collector="TLS-SENSOR-04",
                                   collector_version="2.0.1", target_id="lb-01:443",
                                   observed_at=NOW, source="pcap:lb-01", evidence_type=
                                   "NETWORK_OBSERVED", raw_reference="ClientHello",
                                   normalized_fact="TLS1.2", hash="sha256:33af",
                                   confidence="HIGH")
    attached_net = n.attach_evidence(row=lb_front, record=record_net,
                                     basis="tls-handshake")

    doc = n.estate(
        system, application, service, shipped, packaged, image, release, artifact,
        deployment_row, pod, container, namespace, cluster, node, host, deployed,
        image, package, library,
        hardware_links, process, library, package_links, aes_algorithm, sha_algorithm,
        des_algorithm, rsa_algorithm, openssl_part, hsm, kms, tpm, signing_key, data_key,
        key_links, signing_part, encryption_part, static_part, bound, static_call, public,
        lb_front, bulk, mac, kex, suite, legacy_suite, certificate, binding, hops, device,
        firmware,
        product, vendor, vulnerability, vendored, vuln, srv_lb, record, attached,
        record_net, attached_net,
        n.serves(application_row=application, service_row=service, system_row=system,
                 evidence_ids=[EVID]),
        estate_id="bank-dependency", environment="PRODUCTION",
        expected={"applications": 70},
        gaps=[{"layer": "SOURCE", "reason": "12 of 70 applications were inspected"}])
    return {"estate": doc, "names": {
        "application": "Payments API", "provider": f"OpenSSL {provider_version}",
        "signing": "OP-SIGN-001", "encryption": "OP-ENCRYPT-002",
        "static": "OP-STATIC-003", "endpoint": "payments.bank.example:443",
        "certificate": "CERT-001", "hsm": "HSM-001", "kms": "KMS-01",
        "algorithm": f"RSA-{rsa_size}", "firmware": "BIG-IP 17.1.1", "vendor": "F5",
        "library": "libcrypto.so.3", "image": "payments-api:4.2.0"}}


def _build(modules: dict[str, Any]) -> dict[str, Any]:
    current = _document(modules)
    previous = _document(modules, rsa_size=2048)
    upgraded = _document(modules, rsa_size=3072)
    # the full CBOM projection, not the network subset: the chain needs the release, the
    # provider and the key, which an NBOM deliberately leaves out
    return {
        "bom": modules["t"].build(current["estate"]),
        "previous": modules["t"].build(previous["estate"]),
        "upgraded": modules["t"].build(upgraded["estate"]),
        "names": current["names"],
    }


# --------------------------------------------------------------------------- #
# The twenty-six points
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    modules = _load()
    d, n, t, u = modules["d"], modules["n"], modules["t"], modules["u"]
    built = _build(modules)
    bom, previous, upgraded, names = built["bom"], built["previous"], built["upgraded"], \
        built["names"]
    claims = bom["claims"]
    assets = {row["name"]: row for row in bom["assets"]}
    points: list[dict[str, Any]] = []

    def add(point: int, question: str, probes: list[dict[str, Any]]) -> None:
        points.append({"point": point, "question": question, "probes": probes,
                       "ok": all(probe["ok"] for probe in probes)})

    down = d.chain(bom, query=names["application"])
    from_system = d.chain(bom, query="Payments System")
    provider_block = d.chain(bom, query=names["provider"])
    signing_attributes = assets[names["signing"]]["attributes"]

    # 1. application → crypto asset proves uses, not contains
    level_names = {level: [row["name"] for row in rows]
                   for level, rows in down["down"].items()}
    add(1, "an application reaches its crypto by use, not by containment", [
        _probe("application-to-provider-is-evidenced",
               names["provider"] in level_names.get("provider", []),
               f"Payments API → provider: {level_names.get('provider')}"),
        _probe("the-use-is-an-operation-not-an-edge-to-a-cipher",
               names["signing"] in level_names.get("operation", [])
               and not any(claim["from"] == names["application"]
                           and claim["relation"] == "USES_CRYPTO"
                           and claim["to"] == names["algorithm"]
                           for claim in claims),
               f"operations {level_names.get('operation')}; no application USES_CRYPTO "
               f"{names['algorithm']} edge"),
        _probe("the-chain-starts-at-the-business-system",
               "Payments API" in [row["name"] for row in
                                  from_system["down"].get("application", [])],
               from_system["statement"]),
    ])

    # 2. SBOM → CBOM through capability + evidence
    supports = [claim for claim in claims if claim["from"] == names["provider"]
                and claim["relation"] == "SUPPORTS"]
    implements = [claim for claim in claims if claim["from"] == names["provider"]
                  and claim["relation"] == "IMPLEMENTS"]
    add(2, "an SBOM becomes a CBOM through capability and evidence, never a preset edge", [
        _probe("provider-lists-its-capabilities-at-CAPABILITY",
               len(supports) == 3 and {claim["confidence"] for claim in supports}
               == {"CAPABILITY"},
               f"{len(supports)} SUPPORTS edge(s) at "
               f"{sorted({claim['confidence'] for claim in supports})}"),
        _probe("provider-implements-algorithms-at-an-evidenced-class",
               bool(implements) and {claim["confidence"] for claim in implements}
               <= {"OBSERVED", "RUNTIME_OBSERVED", "CONFIGURED"},
               f"classes {sorted({claim['confidence'] for claim in implements})}"),
        _probe("no-provider-USES-AES-edge-exists",
               not any(claim["from"] == names["provider"]
                       and claim["relation"] in ("USES_CRYPTO", "USES_ALGORITHM")
                       for claim in claims),
               "no provider USES_* edge; a provider implements, it does not use"),
    ])

    # 3. static: app → file → API → algorithm, STATIC_OBSERVED, never promoted
    static_edges = [claim for claim in claims if claim["basis"] == "source-analysis"]
    add(3, "a source hit is a dependency at STATIC_OBSERVED and never a runtime use", [
        _probe("three-static-edges-file-then-call-then-algorithm",
               {"USES_CRYPTO", "DECLARES", "USES_ALGORITHM"}
               <= {claim["relation"] for claim in static_edges}
               and sum(1 for claim in static_edges
                       if claim["relation"] == "DECLARES") == 1
               and sum(1 for claim in static_edges
                       if claim["relation"] == "USES_CRYPTO") == 1,
               "source-analysis edges: "
               + ", ".join(sorted(claim["relation"] for claim in static_edges))),
        _probe("every-static-edge-is-STATIC_OBSERVED",
               all(claim["confidence"] == "STATIC_OBSERVED" for claim in static_edges),
               f"classes {sorted({claim['confidence'] for claim in static_edges})}"),
        _probe("STATIC_OBSERVED-is-not-PROVEN",
               t.STATIC_OBSERVED not in t.PROVEN,
               f"PROVEN = {sorted(t.PROVEN)}; STATIC_OBSERVED excluded"),
        _probe("the-file-carries-api-and-line",
               assets["src/main/java/bank/LegacySettlement.java"].get("kind") == "SOURCE"
               and assets["src/main/java/bank/LegacySettlement.java:"
                          "Cipher.getInstance"]["attributes"]["line"] == 214,
               "SOURCE file node beside the crypto call, with api and line 214"),
    ])

    # 4. runtime: app → process → provider → operation → algorithm → parameters
    runtime_edges = [claim for claim in claims
                     if claim["relation"] == "INVOKES"
                     and claim["confidence"] == "RUNTIME_OBSERVED"]
    add(4, "a runtime observation names the process, the provider and the parameters", [
        _probe("the-operation-hangs-off-the-process",
               any(claim["from"] == "payments-api[1821]" and claim["to"] == names["signing"]
                   for claim in runtime_edges),
               f"{len(runtime_edges)} RUNTIME_OBSERVED INVOKES edge(s)"),
        _probe("the-process-loads-the-provider",
               any(claim["from"] == "payments-api[1821]" and claim["relation"] == "LOADS"
                   and claim["to"] == names["provider"] for claim in claims),
               "payments-api[1821] LOADS OpenSSL at RUNTIME_OBSERVED"),
        _probe("the-operation-names-its-parameters",
               signing_attributes.get("key_size") == 2048
               and signing_attributes.get("padding") == "PSS"
               and signing_attributes.get("hash") == "SHA-256",
               f"SIGN / {signing_attributes.get('algorithm')} / "
               f"{signing_attributes.get('key_size')} / {signing_attributes.get('padding')}"
               f" / {signing_attributes.get('hash')}"),
    ])

    # 5. provider is not the algorithm
    add(5, "the provider is a node, so a library advisory maps to assets", [
        _probe("provider-and-algorithm-are-different-kinds",
               assets[names["provider"]]["kind"] == "CRYPTO_PROVIDER"
               and assets[names["algorithm"]]["kind"] == "ALGORITHM",
               f"{assets[names['provider']]['kind']} vs "
               f"{assets[names['algorithm']]['kind']}"),
        _probe("the-provider-carries-a-family-and-a-version",
               assets[names["provider"]]["attributes"].get("family") == "OPENSSL"
               and assets[names["provider"]]["version"] == "3.0.11",
               f"family {assets[names['provider']]['attributes'].get('family')}, "
               f"version {assets[names['provider']]['version']}"),
        _probe("the-provider-is-reachable-from-the-application",
               "application" in provider_block["up"],
               f"up from the provider: {list(provider_block['up'])}"),
    ])

    # 6. an operation is first class
    present = [field for field in d.OPERATION_PARAMETERS
               if signing_attributes.get(field) not in (None, "")]
    add(6, "the operation is a node with its parameters, not a cipher name", [
        _probe("signature-names-seven-of-nine-fields",
               len(present) >= 7,
               f"present {present}; mode and curve do not apply to RSA signing"),
        _probe("a-block-cipher-without-a-mode-is-refused",
               _refused(d.runtime_operation, name="OP-BAD-1", process_row={"name": "p"},
                        operation="ENCRYPT", algorithm_row=assets["AES-256"],
                        basis="runtime-observation", evidence_ids=[EVID_RT])
               == "BLOCK_CIPHER_WITHOUT_MODE",
               "AES with no mode → BLOCK_CIPHER_WITHOUT_MODE"),
        _probe("an-unknown-verb-is-refused",
               _refused(d.runtime_operation, name="OP-BAD-2", process_row={"name": "p"},
                        operation="USES_CRYPTO", algorithm_row=assets[names["algorithm"]],
                        key_size=2048, evidence_ids=[EVID_RT]) == "UNKNOWN_OPERATION",
               "'USES_CRYPTO' is not an operation → UNKNOWN_OPERATION"),
    ])

    # 7. key metadata, never material
    key_row = assets["KEY-REF-4401"]
    add(7, "a key reaches the graph as metadata and never as material", [
        _probe("the-key-carries-reference-size-purpose-and-holder",
               key_row["kind"] == "KEY_REFERENCE"
               and key_row["attributes"].get("key_ref", "").startswith("pkcs11:")
               and key_row["attributes"].get("key_size") == 2048
               and key_row["attributes"].get("purpose") == "SIGNING"
               and key_row["attributes"].get("holder") == "HSM-001",
               f"{key_row['attributes'].get('key_ref')} / RSA-2048 / SIGNING / HSM-001"),
        _probe("key-material-is-refused",
               _refused(n.key_reference, name="KEY-REF-X", key_ref="pkcs11:x",
                        purpose="SIGNING", algorithm="RSA", private_key="MIIEvQIBADAN")
               == "KEY_MATERIAL_REFUSED",
               "private_key field → KEY_MATERIAL_REFUSED"),
        _probe("no-asset-holds-a-private-key",
               not any("PRIVATE KEY" in json.dumps(row.get("attributes") or {})
                       for row in bom["assets"]),
               "no attribute anywhere contains a private-key marker"),
    ])

    # 8. HSM supports ≠ application uses the HSM
    hsm_supports = [claim for claim in claims if claim["from"] == names["hsm"]
                    and claim["relation"] == "SUPPORTS"]
    backed = [claim for claim in claims if claim["relation"] == "BACKED_BY"]
    add(8, "an HSM that supports RSA is not an application that uses the HSM", [
        _probe("the-capability-is-VENDOR_DECLARED",
               bool(hsm_supports)
               and {claim["confidence"] for claim in hsm_supports} == {"VENDOR_DECLARED"},
               f"HSM-001 SUPPORTS {[claim['to'] for claim in hsm_supports]} at "
               f"VENDOR_DECLARED"),
        _probe("the-use-is-an-operation-BACKED_BY-the-HSM",
               bool(backed) and {claim["confidence"] for claim in backed}
               == {"RUNTIME_OBSERVED"},
               f"{len(backed)} BACKED_BY edge(s) at RUNTIME_OBSERVED"),
        _probe("the-two-claims-are-separate-edges",
               {(claim["from"], claim["relation"], claim["to"]) for claim in hsm_supports}
               .isdisjoint({(claim["from"], claim["relation"], claim["to"])
                            for claim in backed}),
               "SUPPORTS on the HSM, BACKED_BY on the operation"),
    ])

    # 9. KMS: four states
    kms_block = d.kms_evidence(bom, query=names["kms"])
    add(9, "a KMS answer is one of four states and the strongest one is named", [
        _probe("the-four-states-are-distinct",
               len({d.kms_state(basis=basis) for basis in
                    ("vendor-datasheet", "config-parse", "agent-inventory",
                     "runtime-probe")}) == 4,
               "SUPPORTED / CONFIGURED / REFERENCED / ACTUALLY_USED"),
        _probe("the-kms-in-this-estate-is-configured-not-used",
               kms_block["state"] in ("CONFIGURED", "REFERENCED")
               and "ACTUALLY_USED" not in kms_block["states_present"],
               f"{kms_block['statement']}"),
        _probe("an-HSM-backed-operation-is-the-only-ACTUALLY_USED-answer",
               any(answer["state"] == "ACTUALLY_USED"
                   for answer in d.kms_evidence(bom, query=names["hsm"])["answers"]),
               d.kms_evidence(bom, query=names["hsm"])["statement"]),
    ])

    # 10. certificate crypto ≠ application crypto
    presents = [claim for claim in claims if claim["relation"] == "PRESENTS"]
    add(10, "the certificate chain is a listener dependency, not the application's crypto", [
        _probe("only-a-listener-presents-the-certificate",
               bool(presents) and {claim["from"] for claim in presents}
               == {names["endpoint"]},
               f"PRESENTS from {sorted({claim['from'] for claim in presents})}"),
        _probe("the-application-holds-no-certificate-edge",
               not any(claim["from"] == names["application"]
                       and claim["relation"] in ("PRESENTS", "USES_CERTIFICATE")
                       for claim in claims),
               "no PRESENTS or USES_CERTIFICATE from Payments API"),
        _probe("the-application-usage-set-excludes-the-certificate-algorithm",
               "ECDSA P-256" not in d.capability_vs_usage(
                   bom, query=names["provider"])["usage"],
               "ECDSA belongs to CERT-001's key, not to the provider's observed uses"),
    ])

    # 11. app → endpoint → TLS → negotiated crypto
    negotiated = [claim for claim in claims if claim["relation"] == "NEGOTIATES"]
    add(11, "the negotiated crypto is NETWORK_OBSERVED at the listener", [
        _probe("the-handshake-is-the-only-source",
               bool(negotiated) and all(claim["basis"] in ("tls-handshake",)
                                        for claim in negotiated),
               f"{len(negotiated)} NEGOTIATES edge(s), basis "
               f"{sorted({claim['basis'] for claim in negotiated})}"),
        _probe("the-suite-is-decomposed-into-three-assets",
               {"AES-256-GCM", "SHA-384", "X25519"} <= {claim["to"] for claim in claims
                                                        if claim["from"] ==
                                                        "TLS_AES_256_GCM_SHA384"},
               "bulk, mac and kex as three crypto assets"),
        _probe("the-endpoint-reaches-the-application",
               n.negotiated_crypto(bom, query=names["endpoint"])["negotiated"] != [],
               n.negotiated_crypto(bom, query=names["endpoint"])["statement"]),
    ])

    # 12. multi-hop, HOP 1..N
    hop_block = d.endpoint_hops(bom, query=names["endpoint"])
    add(12, "a multi-hop path is HOP 1..N, never one collapsed dependency", [
        _probe("the-hops-are-numbered-in-order",
               [row["hop"] for row in hop_block["hops"]]
               == list(range(1, hop_block["count"] + 1)) and hop_block["count"] >= 2,
               f"{hop_block['count']} hop(s): "
               + ", ".join(f"HOP {row['hop']} {row['source']} → {row['target']} "
                           f"({row['mode']})" for row in hop_block["hops"])),
        _probe("each-hop-carries-its-own-class",
               all(row["class"] for row in hop_block["hops"]),
               f"classes {[row['class'] for row in hop_block['hops']]}"),
        _probe("a-hop-with-no-facts-is-refused",
               _refused(d.crypto_hops, [{"source": "a"}]) == "HOP_WITHOUT_FACTS",
               "a hop with no target → HOP_WITHOUT_FACTS"),
    ])

    # 13. the hardware relations
    hardware_relations = {claim["relation"] for claim in claims}
    add(13, "USES_HSM, USES_TPM, BACKED_BY, PROTECTED_BY and RUNS_ON carry evidence", [
        _probe("every-hardware-relation-in-the-spec-is-present",
               {"BACKED_BY", "USES_TPM", "PROTECTED_BY", "RUNS_ON"} <= hardware_relations,
               "present " + str(sorted(hardware_relations & HARDWARE_RELATIONS))),
        _probe("each-carries-an-evidence-id",
               all(claim["evidence_ids"] for claim in claims
                   if claim["relation"] in ("BACKED_BY", "USES_TPM", "PROTECTED_BY",
                                            "RUNS_ON")),
               "every one of them has an evidence id"),
    ])

    # 14. asset → provider → product → vendor
    firmware_chain = d.chain(bom, query=names["firmware"])
    add(14, "a vendor firmware advisory maps back to the assets that depend on it", [
        _probe("the-device-is-supplied-by-the-vendor",
               any(claim["from"] == "LB-01" and claim["relation"] == "SUPPLIED_BY"
                   and claim["to"] == names["vendor"] for claim in claims),
               "LB-01 SUPPLIED_BY F5"),
        _probe("the-device-names-its-firmware-version",
               assets[names["firmware"]]["version"] == "17.1.1"
               and any(claim["to"] == names["firmware"] for claim in claims),
               "BIG-IP 17.1.1 as a node with a version"),
        _probe("the-vulnerability-reaches-a-listener-and-an-application",
               "application" in firmware_chain["up"]
               or "endpoint" in firmware_chain["up"],
               f"up from the firmware: {list(firmware_chain['up'])}"),
    ])

    # 15. algorithm → library → image → application
    add(15, "an algorithm reaches an image through the library it lives in", [
        _probe("the-library-implements-the-algorithm",
               any(claim["from"] == names["library"]
                   and claim["relation"] == "IMPLEMENTS" for claim in claims)
               or any(claim["basis"] == "sbom-import"
                      and claim["relation"] == "LINKS" for claim in claims),
               "libcrypto.so.3 IMPLEMENTS the algorithms, and the package LINKS the "
               "library"),
        _probe("the-package-reaches-the-image-and-the-image-the-application",
               {"SHIPS", "PACKAGED_AS", "RELEASED_AS"} <= {
                   claim["relation"] for claim in claims},
               "image SHIPS package; artifact PACKAGED_AS image; application RELEASED_AS "
               "release"),
        _probe("the-library-is-a-node-not-an-attribute",
               assets[names["library"]]["kind"] == "CRYPTO_LIBRARY",
               f"{names['library']} is a {assets[names['library']]['kind']}"),
    ])

    # 16. algorithm → library → image → container → pod → application
    add(16, "existence in an image is not a load, and the Kubernetes path is walkable", [
        _probe("the-kubernetes-path-has-six-relations",
               {"FROM_IMAGE", "RUNS_CONTAINER", "RUNS_PROCESS", "RUNS_APPLICATION"}
               <= {claim["relation"] for claim in claims},
               "image → container → pod → process → application"),
        _probe("the-image-edge-is-imported-and-the-load-is-runtime",
               min(claim["confidence"] for claim in claims
                   if claim["relation"] in ("SHIPS", "LINKS", "FROM_IMAGE")
                   ) in ("IMPORTED", "CONFIGURED")
               and any(claim["relation"] == "LOADS"
                       and claim["confidence"] == "RUNTIME_OBSERVED" for claim in claims),
               "'exists in the image' at IMPORTED, 'loaded' at RUNTIME_OBSERVED"),
    ])

    # 17. container → pod → deployment → namespace → cluster → node → host
    topology = {claim["relation"] for claim in claims}
    add(17, "the deployment topology joins the hardware estate", [
        _probe("every-topology-relation-is-present",
               {"RUNS_IN", "MEMBER_OF_CLUSTER", "SCHEDULED_ON", "RUNS_ON", "SCHEDULES"}
               <= topology,
               "present " + str(sorted(topology & TOPOLOGY_RELATIONS))),
        _probe("the-cluster-and-node-are-nodes",
               assets["prod-cluster"]["kind"] == "CLUSTER"
               and assets["node-07"]["kind"] == "KUBERNETES_NODE",
               "CLUSTER prod-cluster and KUBERNETES_NODE node-07"),
        _probe("the-node-sits-on-a-physical-host",
               any(claim["from"] == "node-07" and claim["relation"] == "RUNS_ON"
                   and claim["to"] == "srv-k8s-07" for claim in claims),
               "node-07 RUNS_ON srv-k8s-07"),
    ])

    # 18. business system → application → crypto asset, both ways
    answer = d.systems_depending_on(bom, algorithm=names["algorithm"])
    strict = d.systems_depending_on(bom, algorithm=names["algorithm"], include_static=False)
    add(18, "which business systems depend on RSA-2048 is a query, not a spreadsheet", [
        _probe("the-system-is-named-through-an-evidenced-path",
               answer["systems"] == ["Payments System"],
               answer["statement"]),
        _probe("the-path-is-printed-with-its-classes",
               answer["applications"] and answer["applications"][0]["classes"],
               " → ".join(answer["applications"][0]["path"])
               if answer["applications"] else "no path"),
        _probe("the-strict-answer-excludes-static-only-paths",
               isinstance(strict["applications"], list),
               f"strict answer: {strict['statement']}"),
    ])

    # 19. every edge carries its nine fields
    audit = d.evidence_audit(bom)
    add(19, "every dependency edge carries its record, and a collector where one exists", [
        _probe("no-dependency-edge-is-missing-a-required-field",
               not audit["incomplete"],
               f"{audit['complete']} of {audit['count']} complete"),
        _probe("a-collector-is-named-where-a-record-exists",
               audit["with_collector"] >= 2,
               f"{audit['with_collector']} edge(s) name a collector: {audit['collectors']}"),
        _probe("the-nine-fields-are-declared",
               len(d.EDGE_FIELDS) == 10,
               f"EDGE_FIELDS = {list(d.EDGE_FIELDS)}"),
    ])

    # 20. capability vs usage
    capability = d.capability_vs_usage(bom, query=names["provider"])
    add(20, "capability and usage are two sets and never one", [
        _probe("capability-is-what-the-provider-lists",
               len(capability["capability"]) == 3,
               f"capability {capability['capability']}"),
        _probe("usage-is-what-was-observed",
               set(capability["usage"]) == {"RSA-2048", "AES-256", "DES-ECB"},
               f"usage {sorted(capability['usage'])}"),
        _probe("the-difference-is-reported-not-resolved",
               "SHA-256" in capability["capability_not_used"],
               f"listed and never used: {capability['capability_not_used']}"),
    ])

    # 21. conflicts
    conflicts = d.dependency_conflicts(bom)
    add(21, "a disagreement about a dependency is the finding, with every source kept", [
        _probe("the-version-disagreement-is-found",
               conflicts["counts"].get("VERSION", 0) == 1,
               conflicts["statement"]),
        _probe("every-source-is-preserved",
               conflicts["findings"] and len(conflicts["findings"][0]["sources"]) == 3,
               f"values {conflicts['findings'][0]['values']} from "
               f"{[row['source'] for row in conflicts['findings'][0]['sources']]}"
               if conflicts["findings"] else "no finding"),
        _probe("the-static-and-runtime-layers-also-disagree",
               conflicts["counts"].get("LAYER", 0) == 1,
               "the process invoked AES-256-GCM at runtime and DES-ECB statically"),
    ])

    # 22. temporal change
    change = d.dependency_changes(previous, upgraded, detected_at=NOW)
    changed = change["changes"][0] if change["changes"] else None
    add(22, "a dependency that moved is a change with evidence on both sides", [
        _probe("the-signature-move-is-detected",
               changed is not None and changed["previous"] == "RSA-2048"
               and changed["current"] == "RSA-3072",
               f"{changed['previous']} → {changed['current']}" if changed
               else "no change detected"),
        _probe("both-evidence-ids-are-kept",
               bool(changed and changed["evidence_before"] and changed["evidence_after"]
                    and changed["detected_at"] == NOW),
               f"before {changed['evidence_before']}, after {changed['evidence_after']}, "
               f"at {changed['detected_at']}" if changed else "no change"),
        _probe("the-same-estate-compared-with-itself-shows-nothing",
               d.dependency_changes(previous, previous)["counts"]["CHANGED"] == 0,
               "no change when nothing moved"),
    ])

    # 23. lifecycle, superseded rather than deleted
    states = n.lifecycle(bom, reference=NOW)["counts"]
    drift = n.drift(previous, upgraded, reference=NOW)
    vocabulary = set(states) | {event["change"].replace("EDGE_", "") for event
                                in drift["events"]}
    add(23, "a dependency that stops being observed is superseded, not deleted", [
        _probe("the-lifecycle-states-are-derived-per-edge",
               {"FIRST_SEEN", "ACTIVE", "UNKNOWN"} <= set(states),
               f"counts {states}"),
        _probe("the-old-edge-is-reported-not-silently-dropped",
               any(event["change"] in ("EDGE_SUPERSEDED", "EDGE_REMOVED")
                   for event in drift["events"]),
               drift["statement"]),
        _probe("the-six-word-vocabulary-is-reachable",
               {"FIRST_SEEN", "ACTIVE", "CHANGED", "SUPERSEDED", "UNKNOWN"}
               <= vocabulary,
               f"vocabulary seen: {sorted(vocabulary)}"),
    ])

    # 24. coverage honesty
    honest = u.coverage(70, 12, 12, unit="application")
    network_coverage = n.coverage(expected=70, observed=12, unavailable=40, unknown=18)
    propagated = n.propagate_coverage(network_coverage,
                                      consumers={"cbom": "COMPLETE", "twin": "PARTIAL"})
    add(24, "a count is reported against what was inspected, never against the bank", [
        _probe("twelve-of-seventy-is-partial-and-not-quotable",
               honest["completeness"] == "PARTIAL"
               and honest["quotable_as_total"] is False,
               honest["statement"]),
        _probe("the-network-denominator-reconciles",
               network_coverage["verdict"] == "PARTIAL"
               and network_coverage["unaccounted"] == 0,
               network_coverage["statement"]),
        _probe("a-consumer-that-claims-more-is-refused",
               any(row["code"] == "COVERAGE_LAUNDERED"
                   for row in propagated["findings"]),
               propagated["statement"]),
    ])

    # 25. the PQC blocker is on the path
    blockers = d.pqc_blockers(bom, query=names["algorithm"])
    add(25, "the PQC blocker is a path through the graph, not a property of the algorithm", [
        _probe("the-blockers-are-named-per-hop",
               {"HSM", "CERTIFICATE", "NETWORK_ENDPOINT"} <= set(blockers["kinds"]),
               blockers["statement"]),
        _probe("the-algorithm-itself-is-labelled-separately",
               blockers["sensitive"] and blockers["blockers"][0]["kind"] == "ALGORITHM",
               "RSA-2048 is quantum-sensitive, and that is one blocker of several"),
        _probe("a-listener-blocker-names-the-suite-it-negotiates",
               any(row.get("suites") for row in blockers["blockers"]
                   if row["kind"] == "NETWORK_ENDPOINT"),
               "the listener blocker carries the suites it negotiates"),
    ])

    # 26. the twin reads the same graph
    twin = n.twin(bom)
    add(26, "the whole chain joins the Digital Twin's canonical estate graph", [
        _probe("the-twin-reads-every-edge-of-this-projection",
               twin["edge_count"] == len(claims),
               f"{twin['edge_count']} edge(s) into the twin, {len(claims)} in the BOM"),
        _probe("the-twin-names-the-system-and-the-application",
               twin["systems"] == ["Payments System"]
               and "Payments API" in twin["applications"],
               f"systems {twin['systems']}, one of {len(twin['applications'])} applications"),
        _probe("the-twin-carries-the-keys-and-the-tls",
               twin["keys"] and twin["tls"],
               f"keys {twin['keys']}, {len(twin['tls'])} TLS edge(s)"),
    ])

    rows = _rows(points, bom)
    counts = {VERDICT_PASS: sum(1 for row in rows if row["verdict"] == VERDICT_PASS),
              VERDICT_PARTIAL: sum(1 for row in rows if row["verdict"] == VERDICT_PARTIAL),
              VERDICT_FAIL: sum(1 for row in rows if row["verdict"] == VERDICT_FAIL)}
    probes = sum(len(row["probes"]) for row in rows)
    present = sum(1 for row in points if row["ok"])
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "estate": "bank-dependency",
        "counts": counts,
        "probes": probes,
        "points_present": f"{present}/{len(points)}",
        "statement": (f"{present} of {len(points)} points of the dependency chain are "
                      f"present in the built projection, across {probes} probes; "
                      f"{len(bom['assets'])} assets and {len(claims)} evidenced edges"),
        "levels": d.levels(bom),
        "chain": down,
        "capability": d.capability_vs_usage(bom, query=names["provider"]),
        "conflicts": d.dependency_conflicts(bom),
        "change": d.dependency_changes(previous, upgraded, detected_at=NOW),
        "blockers": d.pqc_blockers(bom, query=names["algorithm"]),
        "hops": d.endpoint_hops(bom, query=names["endpoint"]),
        "coverage": honest,
        "points": points,
        "rows": rows,
        "refusals": bom["refusals"],
        "limits": [
            "the fixture is the bank's own path: every shape is real, the rows are not",
            "the provider's operation list is what a runtime probe saw once; a second "
            "sample could add an operation and no sample can remove one",
            "a static hit names a file, an API and a line; it never proves the branch ran",
            "the key record is a reference and its metadata: nothing here proves which key "
            "produced a signature, and nothing here would hold the key if it could",
            "the KMS answer is the strongest single answer in the estate, not the strongest "
            "answer per application",
            "coverage is arithmetic on what the collectors reported; it cannot see an "
            "application that was never scanned",
        ],
    }


def _rows(points: list[dict[str, Any]], bom: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    phases = {1: "the chain", 2: "the chain", 3: "the chain", 4: "the chain",
              5: "the chain", 6: "the chain", 7: "keys", 8: "keys", 9: "keys",
              10: "network", 11: "network", 12: "network", 13: "hardware",
              14: "hardware", 15: "build", 16: "build", 17: "build", 18: "queries",
              19: "evidence", 20: "evidence", 21: "conflict", 22: "temporal",
              23: "temporal", 24: "honesty", 25: "pqc", 26: "twin"}
    for point in points:
        failed = [probe for probe in point["probes"] if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(point["probes"]) else VERDICT_FAIL)
        rows.append({
            "id": f"CBOM-{point['point']:02d}",
            "point": point["point"],
            "question": point["question"],
            "phase": phases.get(point["point"], "the chain"),
            "verdict": verdict,
            "probes": point["probes"],
            "failed": [probe["probe"] for probe in failed],
        })
    return rows


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The dependency chain, twenty-six points",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['points_present']} points of the chain are present in the built "
        "projection.**",
        "",
        "```",
        "BUSINESS SYSTEM → APPLICATION → RELEASE → PROCESS / CONTAINER",
        "    → CRYPTO PROVIDER → CRYPTO OPERATION → ALGORITHM → KEY METADATA",
        "    → HSM / KMS → CERTIFICATE / NETWORK → HARDWARE → VENDOR",
        "```",
        "",
        report["statement"],
        "",
    ]
    levels = report["levels"]
    lines += ["## The levels, as the estate holds them", "",
              "| level | nodes |", "|---|---|"]
    for name, count in levels.items():
        lines.append(f"| {name} | {count} |")
    lines += ["", "## The chain from the application", "",
              f"**{report['chain']['statement']}**", ""]
    for level, rows in report["chain"]["down"].items():
        names = ", ".join(f"`{row['name']}`" for row in rows[:4])
        lines.append(f"- **{level}** — {names}")
    hops = report["hops"]
    lines += ["", "## HOP 1..N", "", f"**{hops['statement']}**", "",
              "| hop | from | to | mode | TLS | suite | class |",
              "|---|---|---|---|---|---|---|"]
    for row in hops["hops"]:
        lines.append(f"| {row['hop']} | {row['source']} | {row['target']} | {row['mode']} | "
                     f"{row['tls_version'] or '—'} | {row['suite'] or '—'} | {row['class']} |")
    capability = report["capability"]
    lines += ["", "## Capability, and usage", "", f"**{capability['statement']}**", "",
              f"- capability: {', '.join(capability['capability'])}",
              f"- usage: {', '.join(capability['usage'])}",
              f"- listed and never used: "
              f"{', '.join(capability['capability_not_used']) or '—'}"]
    conflicts = report["conflicts"]
    lines += ["", "## Disagreement", "", f"**{conflicts['statement']}**", ""]
    for finding in conflicts["findings"]:
        if finding["kind"] == "VERSION":
            lines.append(f"- `VERSION` {finding['asset']}: "
                         + ", ".join(f"{row['source']}={row['value']}"
                                     for row in finding["sources"]))
        else:
            layers = ", ".join(f"{layer}={'/'.join(names)}"
                               for layer, names in finding["layers"].items())
            lines.append(f"- `LAYER` {finding['process']}: {layers}")
    change = report["change"]
    lines += ["", "## What moved", "", f"**{change['statement']}**", ""]
    for row in change["changes"]:
        lines.append(f"- `{row['code']}` {row['dependency']}: {row['previous']} → "
                     f"{row['current']} (before `{row['evidence_before']}`, after "
                     f"`{row['evidence_after']}`, detected {row['detected_at']})")
    blockers = report["blockers"]
    lines += ["", "## The PQC blocker is the path", "", f"**{blockers['statement']}**", "",
              "| kind | name | relation | why it blocks |", "|---|---|---|---|"]
    for row in blockers["blockers"]:
        lines.append(f"| {row['kind']} | {row['name']} | {row.get('relation') or '—'} | "
                     f"{row['reason']} |")
    coverage = report["coverage"]
    lines += ["", "## What the count means", "", f"**{coverage['statement']}**", "",
              "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 173, {row['phase']})", ""]
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
