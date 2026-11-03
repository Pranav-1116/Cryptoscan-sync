#!/usr/bin/env python3
"""Guide 175 — the SBOM dependency chain, twenty-eight points, one build.

The review's target is a chain:

    BUSINESS SYSTEM → APPLICATION → SOURCE REPOSITORY → COMMIT → BUILD → ARTIFACT
        → CONTAINER IMAGE → DEPLOYMENT → POD / VM / HOST → PROCESS
        → SOFTWARE COMPONENT → CRYPTO CAPABILITY

and a rule about each edge on it: *the SBOM must not be the only thing that knows*. Every
row below is read off the built projection rather than off the source, so "proven" means
"present in the BOM, with a basis and an evidence id".

The fixture is the bank's own shape: a payments application with a repository, a commit, a
CI build, a digested artifact, a CycloneDX SBOM, a layered image, a Kubernetes deployment
with its replica set, a process that loads OpenSSL 3.0.13 while the SBOM declares 3.0.13 and
the process map says 3.0.11, three components in a direct/transitive chain, a CVE, a vendor,
an HSM-backed key, a listener and a certificate — plus the two things that make identity
interesting: the same application recorded under a second name, and an artifact whose only
identity is a tag.
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
SCHEMA = "cryptoscan.sbom-dependency-guide/1"

VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL = "PASS", "PARTIAL", "FAIL"

EVID_SRC = "EVID-96001"
EVID_BUILD = "EVID-96002"
EVID_SBOM = "EVID-96003"
EVID_IMG = "EVID-96004"
EVID_K8S = "EVID-96005"
EVID_RT = "EVID-96006"
EVID_STATIC = "EVID-96007"
EVID_VENDOR = "EVID-96008"
EVID_NET = "EVID-96009"
EVID_HSM = "EVID-96010"

NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"
OLD = "2026-10-01T08:30:00Z"

DIGEST_ARTIFACT = "sha256:abc123def4567890abc123def4567890"
DIGEST_IMAGE = "sha256:8af92c1d4e5f60718293a4b5c6d7e8f9"
DIGEST_TAG_ONLY = "latest"


def _load() -> dict[str, Any]:
    for path in (SERVICES / "cbom", SERVICES):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    from cbom import cbom_dependency, nbom_graph, sbom_dependency, techbom  # noqa: PLC0415

    return {"s": sbom_dependency, "d": cbom_dependency, "n": nbom_graph, "t": techbom}


def _probe(name: str, ok: bool, observed: str) -> dict[str, Any]:
    return {"probe": name, "ok": bool(ok), "observed": observed}


def _refused(function: Any, *args: Any, **kwargs: Any) -> str:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — the code is the observation
        return str(getattr(exc, "code", type(exc).__name__))
    return "no refusal"


# --------------------------------------------------------------------------- #
# The fixture: one bank workload, from the repository to the HSM
# --------------------------------------------------------------------------- #

def _document(modules: dict[str, Any], *, declared_version: str = "3.0.13",
              runtime_version: str = "3.0.11",
              legacy_library: bool = False) -> dict[str, Any]:
    s, n, t, d = modules["s"], modules["n"], modules["t"], modules["d"]

    # ---- business → application → repository → commit → build -------------------
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID_SRC])
    application = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID_SRC])
    sha = s.commit(sha="a81f92c", author="payments-team", committed_at=EARLIER,
                   message="harden card data path", evidence_ids=[EVID_SRC])
    repository = s.source_repository(
        name="git.bank.internal/payments/payments-api", url="https://git.bank.internal",
        application_rows=[application], commit_row=sha, evidence_ids=[EVID_SRC])
    build_part = s.build(name="BUILD-18291", commit_row=sha, pipeline="jenkins-payments-ci",
                         started_at=EARLIER, evidence_ids=[EVID_BUILD], version="4.2.1")

    # ---- artifact, SBOM, image, layer -----------------------------------------
    artifact_row = s.artifact(name="payments-api-4.2.1.jar", digest_value=DIGEST_ARTIFACT,
                              build_row=build_part["assets"][0], kind="JAR",
                              size=42_991_000, evidence_ids=[EVID_BUILD])

    # ---- the components: direct, transitive, and one that is only in the image --
    vendor_product = t.asset("VENDOR_PRODUCT", "OpenSSL 3.x", evidence_ids=[EVID_VENDOR])
    vendor = t.asset("VENDOR", "OpenSSL Project", evidence_ids=[EVID_VENDOR])
    openssl = s.component(name="pkg:generic/openssl",
                          version=declared_version, purl="pkg:generic/openssl",
                          scope="RUNTIME", crypto=True, product_row=vendor_product,
                          evidence_ids=[EVID_SBOM], version_claims=[
                              {"source": "sbom", "value": declared_version,
                               "class": "IMPORTED", "evidence_id": EVID_SBOM},
                              {"source": "image-scan", "value": declared_version,
                               "class": "STATIC_OBSERVED", "evidence_id": EVID_IMG},
                              {"source": "process-map", "value": runtime_version,
                               "class": "RUNTIME_OBSERVED", "evidence_id": EVID_RT},
                              {"source": "vendor-portal", "value": declared_version,
                               "class": "VENDOR_DECLARED", "evidence_id": EVID_VENDOR}])
    http_core = s.component(name="pkg:generic/http-core@1.2.0", version="1.2.0",
                           scope="TRANSITIVE", evidence_ids=[EVID_SBOM])
    payments_sdk = s.component(name="pkg:generic/payments-sdk@2.4.0", version="2.4.0",
                               scope="RUNTIME", depends_on=[http_core],
                               direct=True, evidence_ids=[EVID_SBOM])
    # the review's example: OpenSSL arrives through the SDK, not from the application
    sdk_to_http = n.part(claims=[
        t.claim("pkg:generic/payments-sdk@2.4.0", "DEPENDS_ON",
                "pkg:generic/http-core@1.2.0", basis="sbom-import", evidence_ids=[EVID_SBOM],
                scope="TRANSITIVE", dependency_kind="TRANSITIVE", first_seen=OLD,
                last_seen=NOW)])
    http_to_openssl = n.part(claims=[
        t.claim("pkg:generic/http-core@1.2.0", "DEPENDS_ON",
                "pkg:generic/openssl", basis="dependency-graph",
                evidence_ids=[EVID_SBOM], scope="RUNTIME", dependency_kind="TRANSITIVE",
                rule="http-core resolves TLS through the system provider", first_seen=OLD,
                last_seen=NOW)])
    build_tool = s.component(name="pkg:generic/maven@3.9.6", version="3.9.6", scope="BUILD",
                             direct=True, evidence_ids=[EVID_BUILD])
    dev_only = s.component(name="pkg:generic/mockito@5.4.0", version="5.4.0", scope="TEST",
                          evidence_ids=[EVID_BUILD])
    # a component that is installed somewhere and deployed nowhere
    openssl_dev = s.component(name="pkg:generic/openssl-dev",
                              version=declared_version, scope="BUILD",
                              evidence_ids=[EVID_IMG])
    report_host = t.asset("PHYSICAL_SERVER", "srv-lb-01", evidence_ids=[EVID_K8S])
    orphan = t.asset("PACKAGE", "pkg:generic/orphan@0.1.0", evidence_ids=[EVID_SBOM],
                     scope="RUNTIME")
    # a component the estate knows about and no application reaches
    ghost = t.asset("PACKAGE", "pkg:generic/ghost@0.0.9", evidence_ids=[EVID_SBOM],
                    scope="RUNTIME")

    sbom_row = s.sbom(name="SBOM-18291", artifact_row=artifact_row["assets"][0],
                      components=[payments_sdk, http_core, openssl, build_tool,
                                  dev_only, orphan],
                      sbom_format="CycloneDX-1.6", tool="syft-1.18", generated_at=EARLIER,
                      serial="urn:uuid:9a8b7c", evidence_ids=[EVID_SBOM])

    layer_part = s.layer(name="layer:ubuntu-22.04-base", base="ubuntu:22.04",
                         packages=[openssl], evidence_ids=[EVID_IMG])
    tools_layer = s.layer(name="layer:reporting-tools", base="ubuntu:22.04",
                          packages=[openssl_dev], evidence_ids=[EVID_IMG])
    reporting_image = s.image(name="reporting-api:1.0.0",
                              digest_value="sha256:1122aabbccdd3344eeff5566",
                              base="ubuntu:22.04", tag="1.0.0",
                              layers=[tools_layer], evidence_ids=[EVID_IMG])
    image_part = s.image(name="payments-api:4.2.1", digest_value=DIGEST_IMAGE,
                         artifact_row=artifact_row["assets"][0], tag="4.2.1",
                         base="ubuntu:22.04", layers=[layer_part],
                         evidence_ids=[EVID_IMG])
    installed = n.part(claims=[
        t.claim(openssl["assets"][0]["name"], "INSTALLED_IN", "payments-api:4.2.1",
                basis="sbom-import", evidence_ids=[EVID_IMG]),
        t.claim(openssl_dev["assets"][0]["name"], "INSTALLED_IN", "srv-lb-01",
                basis="agent-inventory", evidence_ids=[EVID_IMG]),
        t.claim(openssl_dev["assets"][0]["name"], "INSTALLED_IN", "reporting-api:1.0.0",
                basis="sbom-import", evidence_ids=[EVID_IMG]),
    ])

    # ---- the release the application ships, and a second name for the same app --
    release = t.asset("RELEASE", "payments-api 4.2.1", evidence_ids=[EVID_BUILD],
                      channel="PRODUCTION")
    released = n.part(claims=[
        t.claim("Payments API", "RELEASED_AS", "payments-api 4.2.1", basis="agent-inventory",
                evidence_ids=[EVID_BUILD]),
        t.claim("payments-api 4.2.1", "BUNDLES", "payments-api-4.2.1.jar",
                basis="agent-inventory", evidence_ids=[EVID_BUILD])])
    # the same application, recorded by an inventory under its older name, joined by the
    # artifact digest and nothing else
    alias_application = n.service_of(name="payment-service", kind="APPLICATION",
                                     evidence_ids=[EVID_IMG])
    alias_artifact = t.asset("ARTIFACT", "payment-service-4.2.1.jar", evidence_ids=[EVID_IMG],
                             digest=DIGEST_ARTIFACT, artifact_kind="JAR")
    alias_release = t.asset("RELEASE", "payment-service 4.2.1", evidence_ids=[EVID_IMG])
    alias = n.part(alias_application, alias_release, alias_artifact, claims=[
        t.claim("payment-service", "RELEASED_AS", "payment-service 4.2.1",
                basis="api-poll", evidence_ids=[EVID_IMG]),
        t.claim("payment-service 4.2.1", "BUNDLES", "payment-service-4.2.1.jar",
                basis="api-poll", evidence_ids=[EVID_IMG])])

    # ---- the second application, which shares only a name with its report file ----
    settlement = n.service_of(name="Settlement Batch", kind="APPLICATION",
                              evidence_ids=[EVID_K8S])
    report_file = t.asset("ARTIFACT", "settlement-batch-report.txt", evidence_ids=[EVID_K8S],
                          digest="sha256:00ff11ee22dd33cc44bb55aa66ff77ee")

    # ---- deployment: deployment → replica set → pod → container → node → host ----
    deployment_row = t.asset("DEPLOYMENT", "payments-api-deploy", evidence_ids=[EVID_K8S])
    replica_set = t.asset("REPLICA_SET", "payments-api-7d9f4c", evidence_ids=[EVID_K8S])
    pod = t.asset("POD", "payments-api-7d9f4c-x2m8p", evidence_ids=[EVID_K8S])
    container = t.asset("CONTAINER", "payments-api-ctr", evidence_ids=[EVID_K8S])
    namespace = t.asset("NAMESPACE", "payments", evidence_ids=[EVID_K8S])
    cluster = t.asset("CLUSTER", "prod-cluster", evidence_ids=[EVID_K8S])
    node = t.asset("KUBERNETES_NODE", "node-03", evidence_ids=[EVID_K8S])
    host = t.asset("PHYSICAL_SERVER", "srv-k8s-03", evidence_ids=[EVID_K8S],
                   datacenter="Mumbai-DC2", rack="R12")
    cpu = t.asset("CPU", "CPU-01", evidence_ids=[EVID_K8S], model="Xeon 6348")
    tpm = t.asset("TPM", "TPM-01", evidence_ids=[EVID_K8S], version="2.0")
    os_row = t.asset("OS", "Ubuntu 22.04 LTS", evidence_ids=[EVID_IMG])
    topology = n.part(claims=[
        t.claim("payments-api:4.2.1", "DEPLOYED_AS", "payments-api-deploy",
                basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        t.claim("payments-api-deploy", "MANAGES", "payments-api-7d9f4c",
                basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        t.claim("payments-api-7d9f4c", "SCHEDULES", "payments-api-7d9f4c-x2m8p",
                basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        t.claim("payments-api-7d9f4c-x2m8p", "RUNS_CONTAINER", "payments-api-ctr",
                basis="runtime-probe", evidence_ids=[EVID_K8S]),
        t.claim("payments-api-ctr", "FROM_IMAGE", "payments-api:4.2.1",
                basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        t.claim("payments-api-deploy", "RUNS_IN", "payments", basis="deployment-metadata",
                evidence_ids=[EVID_K8S]),
        t.claim("payments", "MEMBER_OF_CLUSTER", "prod-cluster", basis="deployment-metadata",
                evidence_ids=[EVID_K8S]),
        t.claim("payments-api-7d9f4c-x2m8p", "SCHEDULED_ON", "node-03",
                basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        t.claim("node-03", "RUNS_ON", "srv-k8s-03", basis="agent-inventory",
                evidence_ids=[EVID_K8S]),
        t.claim("srv-k8s-03", "HAS_COMPONENT", "CPU-01", basis="agent-inventory",
                evidence_ids=[EVID_K8S]),
        t.claim("srv-k8s-03", "HAS_COMPONENT", "TPM-01", basis="agent-inventory",
                evidence_ids=[EVID_K8S]),
        t.claim("srv-k8s-03", "HOSTS_OS", "Ubuntu 22.04 LTS", basis="agent-inventory",
                evidence_ids=[EVID_IMG]),
    ])

    # ---- the process, what it loads, and what it does ---------------------------
    process = t.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT], pid=1821)
    library = t.asset("CRYPTO_LIBRARY", "libcrypto.so.3", evidence_ids=[EVID_RT])
    legacy_rows = ([t.asset("CRYPTO_LIBRARY", "libcrypto.so.1.1", evidence_ids=[EVID_RT])]
                   if legacy_library else [])
    provider = t.asset("CRYPTO_PROVIDER", "OpenSSL 3.0.13", version=declared_version,
                       family="OPENSSL", evidence_ids=[EVID_RT])
    rsa = n.algorithm(name="RSA-2048", family="RSA", key_size=2048, evidence_ids=[EVID_RT])
    aes = n.algorithm(name="AES-256-GCM", family="AES", key_size=256, mode="GCM",
                      evidence_ids=[EVID_RT])
    aes_128 = n.algorithm(name="AES-128", family="AES", key_size=128, evidence_ids=[EVID_SBOM])
    ecdsa = n.algorithm(name="ECDSA-P256", family="ECDSA", curve="P-256",
                        evidence_ids=[EVID_NET])
    capability = d.capability(provider_row=library, algorithm_row=rsa,
                                basis="capability-list", evidence_ids=[EVID_SBOM])
    capability_aes = d.capability(provider_row=library, algorithm_row=aes,
                                    basis="capability-list", evidence_ids=[EVID_SBOM])
    capability_128 = d.capability(provider_row=library, algorithm_row=aes_128,
                                  basis="capability-list", evidence_ids=[EVID_SBOM])
    capability_ecdsa = d.capability(provider_row=library, algorithm_row=ecdsa,
                                    basis="capability-list", evidence_ids=[EVID_SBOM])
    process_run = n.part(claims=[
        t.claim("payments-api-7d9f4c-x2m8p", "RUNS_PROCESS", "payments-api[1821]",
                basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        t.claim("payments-api[1821]", "RUNS_APPLICATION", "Payments API",
                basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        t.claim("payments-api[1821]", "LOADS",
                "libcrypto.so.1.1" if legacy_library else "libcrypto.so.3",
                basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        # what the SBOM declares and what the process actually mapped are different rows
        t.claim("payments-api[1821]", "LOADS", "pkg:generic/openssl",
                basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        t.claim("pkg:generic/openssl", "LINKS", "libcrypto.so.3",
                basis="sbom-import", evidence_ids=[EVID_SBOM]),
        t.claim("libcrypto.so.3", "SUPPORTS", capability["assets"][-1]["name"],
                basis="capability-list", evidence_ids=[EVID_SBOM]),
        t.claim("libcrypto.so.3", "SUPPORTS", capability_aes["assets"][-1]["name"],
                basis="capability-list", evidence_ids=[EVID_SBOM]),
        t.claim("libcrypto.so.3", "SUPPORTS", capability_128["assets"][-1]["name"],
                basis="capability-list", evidence_ids=[EVID_SBOM]),
        t.claim("libcrypto.so.3", "SUPPORTS", capability_ecdsa["assets"][-1]["name"],
                basis="capability-list", evidence_ids=[EVID_SBOM]),
        # a crypto-policy file on the host configures an algorithm; that is CONFIGURED
        t.claim("Ubuntu 22.04 LTS", "SUPPORTS", "RSA-2048", basis="config-parse",
                evidence_ids=[EVID_IMG]),
    ])
    operation = d.runtime_operation(
        name="OP-SIGN-001", process_row=process, application_row=application,
        operation="SIGN", algorithm_row=rsa, provider_row=provider, key_size=2048,
        padding="PSS", hash_name="SHA-256", purpose="payment instruction signature",
        evidence_ids=[EVID_RT], observed_at=NOW, first_seen=EARLIER, last_seen=NOW,
        pid=1821)
    hsm = t.asset("HSM", "HSM-001", evidence_ids=[EVID_HSM], model="nShield")
    key = n.key_reference(name="KEY-REF-4401", key_ref="pkcs11:token=bank;id=4401",
                          purpose="SIGNING", algorithm="RSA", key_size=2048,
                          holder="HSM-001", evidence_ids=[EVID_HSM])
    bound = d.key_binding(operation_row=operation["assets"][0], key_row=key,
                            holder_row=hsm, basis="runtime-observation",
                            evidence_ids=[EVID_HSM])

    # ---- static evidence: a source hit on the same crypto, one class lower ------
    static_call = d.static_dependency(
        application_row=application, source_file="src/main/java/bank/PaymentsCrypto.java",
        api="EVP_DigestSignInit", algorithm_row=rsa, line=214,
        evidence_ids=[EVID_STATIC], first_seen=OLD, last_seen=EARLIER)

    # ---- network and certificate ----------------------------------------------
    endpoint = n.endpoint(host="203.0.113.10", port=443,
                          name="payments.bank.example:443",
                          tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                          evidence_ids=[EVID_NET])
    bulk = t.asset("CRYPTO_ASSET", "wire:AES-256-GCM", evidence_ids=[EVID_NET],
                   algorithm="AES", key_size=256, mode="GCM")
    suite = n.cipher_suite(name="TLS_AES_256_GCM_SHA384", tls_version="TLS1.3",
                           bulk="AES-256-GCM", evidence_ids=[EVID_NET])
    certificate = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                                issuer="Bank Issuing CA",
                                signature_algorithm="ECDSA-SHA256", evidence_ids=[EVID_NET])
    public_key = t.asset("PUBLIC_KEY", "PUB-001", evidence_ids=[EVID_NET], key_size=256)
    issuer = n.authority(name="Bank Issuing CA", evidence_ids=[EVID_NET])
    chain = n.certificate_chain(certificate_row=certificate, key_row=public_key,
                                key_algorithm_row=ecdsa, signature_algorithm_row=ecdsa,
                                issuer_row=issuer, basis="packet-capture",
                                evidence_ids=[EVID_NET])
    exposed = n.part(claims=[
        t.claim("Payments API", "EXPOSES", "payments.bank.example:443", basis="config-parse",
                evidence_ids=[EVID_NET]),
        t.claim("payments.bank.example:443", "NEGOTIATES", "TLS_AES_256_GCM_SHA384",
                basis="tls-handshake", evidence_ids=[EVID_NET], observed_at=NOW),
        t.claim("payments.bank.example:443", "PRESENTS", "CERT-001", basis="tls-handshake",
                evidence_ids=[EVID_NET]),
        t.claim("TLS_AES_256_GCM_SHA384", "USES_CRYPTO", "wire:AES-256-GCM",
                basis="tls-handshake", evidence_ids=[EVID_NET]),
    ])

    # ---- vulnerability and vendor --------------------------------------------
    vulnerability = t.asset("VULNERABILITY", "CVE-2026-0002", evidence_ids=[EVID_VENDOR],
                            severity="HIGH")
    advisory = n.part(claims=[
        t.claim("pkg:generic/openssl", "HAS_VULNERABILITY",
                "CVE-2026-0002", basis="vendor-portal", evidence_ids=[EVID_VENDOR]),
        t.claim("OpenSSL 3.x", "SUPPLIED_BY", "OpenSSL Project", basis="vendor-datasheet",
                evidence_ids=[EVID_VENDOR]),
    ])

    # ---- the tag-only artifact, kept so the refusal can be measured -----------
    tag_only = t.asset("ARTIFACT", "payments-api:latest", tag=DIGEST_TAG_ONLY,
                       evidence_ids=[EVID_IMG])
    tag_sbom = t.asset("SBOM", "SBOM-latest", evidence_ids=[EVID_IMG],
                       sbom_format="CycloneDX-1.6")
    tag_binding = n.part(claims=[
        t.claim("payments-api:latest", "DESCRIBED_BY", "SBOM-latest", basis="sbom-import",
                evidence_ids=[EVID_IMG])])

    doc = n.estate(
        system, application, repository, sha, build_part, artifact_row, sbom_row,
        payments_sdk, http_core, openssl, build_tool, dev_only, openssl_dev, orphan,
        vendor_product, vendor, ghost, sdk_to_http, http_to_openssl,
        layer_part, image_part, installed, release, released, alias,
        settlement, report_file, report_host, reporting_image,
        deployment_row, replica_set, pod, container, namespace, cluster, node, host, cpu,
        tpm, os_row, topology,
        process, library, *legacy_rows, provider, rsa, aes, aes_128, capability,
        capability_aes,
        capability_128, capability_ecdsa, process_run, operation, hsm, key, bound, static_call,
        endpoint, bulk, suite, certificate, ecdsa, public_key, issuer, chain, exposed,
        vulnerability, advisory, tag_only, tag_sbom, tag_binding,
        n.part(claims=[t.claim("Payments System", "CONTAINS", "Payments API",
                               basis="cmdb-import", evidence_ids=[EVID_SRC])]),
        estate_id="bank-sbom", environment="PRODUCTION",
        expected={"applications": 100},
        gaps=[{"layer": "SOURCE", "reason": "75 of 100 applications were inspected"}])
    return {
        "estate": doc,
        "names": {
            "application": "Payments API",
            "system": "Payments System",
            "repository": "git.bank.internal/payments/payments-api",
            "commit": "a81f92c",
            "build": "BUILD-18291",
            "artifact": "payments-api-4.2.1.jar",
            "sbom": "SBOM-18291",
            "image": "payments-api:4.2.1",
            "layer": "layer:ubuntu-22.04-base",
            "deployment": "payments-api-deploy",
            "pod": "payments-api-7d9f4c-x2m8p",
            "process": "payments-api[1821]",
            "component": "pkg:generic/openssl",
            "direct": "pkg:generic/payments-sdk@2.4.0",
            "transitive": "pkg:generic/http-core@1.2.0",
            "build_component": "pkg:generic/maven@3.9.6",
            "dev_component": "pkg:generic/openssl-dev",
            "orphan": "pkg:generic/orphan@0.1.0",
            "ghost": "pkg:generic/ghost@0.0.9",
            "vulnerability": "CVE-2026-0002",
            "endpoint": "payments.bank.example:443",
            "library": "libcrypto.so.3",
            "declared_version": declared_version,
            "runtime_version": runtime_version,
        },
    }


def _build(modules: dict[str, Any]) -> dict[str, Any]:
    # today: the SBOM declares 3.0.13, the image carries 3.0.13 and the process mapped 3.0.11
    current = _document(modules)
    # before: SBOM, image and process all said 3.0.11 — the history the change is read off
    previous = _document(modules, declared_version="3.0.11", runtime_version="3.0.11",
                         legacy_library=True)
    return {
        "bom": modules["t"].build(current["estate"]),
        "previous": modules["t"].build(previous["estate"]),
        "names": current["names"],
    }


# --------------------------------------------------------------------------- #
# The twenty-eight points
# --------------------------------------------------------------------------- #

def measure() -> dict[str, Any]:
    modules = _load()
    s, d = modules["s"], modules["d"]
    built = _build(modules)
    bom, previous, names = built["bom"], built["previous"], built["names"]
    points: list[dict[str, Any]] = []

    def add(point: int, question: str, probes: list[dict[str, Any]]) -> None:
        points.append({"point": point, "question": question, "probes": probes,
                       "ok": all(probe["ok"] for probe in probes)})

    # ---- 1. SBOM → application ------------------------------------------------
    owners = s.component_owners(bom, query=names["component"])
    orphan = s.component_owners(bom, query=names["ghost"])
    add(1, "an SBOM component names the application that owns it", [
        _probe("the-component-resolves-to-its-application",
               names["application"] in owners["applications"],
               f"{names['component']}: owners {owners['applications']}"),
        _probe("the-ownership-path-is-evidenced",
               any(names["application"] in " ".join(owner["path"])
                   for owner in owners["owners"]),
               " | ".join(owner["path"][0] for owner in owners["owners"][:1]) or "no path"),
        _probe("a-component-nobody-owns-says-so", orphan["applications"] == [],
               f"{names['ghost']}: {orphan['statement']}"),
    ])

    # ---- 2. source → build → artifact ----------------------------------------
    provenance = s.provenance(bom, artifact=names["artifact"])
    tag_provenance = s.provenance(bom, artifact="payments-api:latest")
    add(2, "the artifact names the repository, the commit and the build that produced it", [
        _probe("the-provenance-chain-is-complete", provenance["complete"],
               provenance["statement"]),
        _probe("every-step-names-its-node",
               provenance["steps"]["commit"] == names["commit"]
               and provenance["steps"]["build"] == names["build"]
               and provenance["steps"]["repository"] == names["repository"],
               f"repo {provenance['steps']['repository']}, commit "
               f"{provenance['steps']['commit']}, build {provenance['steps']['build']}, "
               f"pipeline {provenance['steps']['pipeline']}"),
        _probe("a-missing-step-is-reported-not-filled",
               "build" in tag_provenance["missing"] and "commit" in tag_provenance["missing"],
               tag_provenance["statement"]),
    ])

    # ---- 3. SBOM → artifact digest -------------------------------------------
    binding = s.artifact_identity(bom, sbom=names["sbom"])
    tag_binding = _refused(s.artifact_identity, bom, sbom="SBOM-latest")
    add(3, "an SBOM binds to a digest, and a tag is refused as an identity", [
        _probe("the-sbom-binds-to-the-artifact-digest",
               binding["digest"] == DIGEST_ARTIFACT and binding["immutable"],
               binding["statement"]),
        _probe("the-image-digest-is-carried-too", binding["image_digest"] == DIGEST_IMAGE,
               f"image {binding['image']} at {binding['image_digest']}"),
        _probe("a-tag-only-artifact-is-refused", tag_binding == "TAG_ONLY_IDENTITY",
               f"SBOM-latest → {tag_binding}"),
    ])

    # ---- 4. SBOM → deployment ------------------------------------------------
    deployed = s.deployment_state(bom, query=names["component"])
    dev_state = s.deployment_state(bom, query="pkg:generic/openssl-dev")
    add(4, "existence in an SBOM is not a deployment", [
        _probe("the-deployed-component-reaches-a-deployment",
               deployed["states"]["DEPLOYED"] and deployed["states"]["RUNNING"],
               deployed["statement"]),
        _probe("a-component-installed-nowhere-running-is-not-deployed",
               dev_state["states"]["INSTALLED"] and not dev_state["deployed"],
               dev_state["statement"]),
        _probe("the-strongest-state-is-named", deployed["strongest"] == "LOADED",
               f"strongest {deployed['strongest']} of {list(deployed['states'])}"),
    ])

    # ---- 5. SBOM → runtime, both versions kept -------------------------------
    versions = s.version_layers(bom, query=names["component"])
    add(5, "the declared version and the runtime version are both preserved", [
        _probe("the-two-versions-disagree-and-both-survive",
               versions["layers"]["DECLARED_VERSION"] == names["declared_version"]
               and versions["layers"]["RUNTIME_VERSION"] == names["runtime_version"],
               versions["statement"]),
        _probe("the-conflict-is-NOT-silently-resolved",
               versions["conflict"] and versions["code"] == "DEPENDENCY_VERSION_CONFLICT",
               f"code {versions['code']}, distinct {versions['distinct']}"),
        _probe("the-image-and-vendor-layers-are-named",
               versions["layers"]["IMAGE_VERSION"] == names["declared_version"]
               and versions["layers"]["VENDOR_VERSION"] == names["declared_version"],
               ", ".join(f"{name}={versions['layers'][name]}"
                         for name in s.VERSION_LAYERS)),
    ])

    # ---- 6. installed ≠ loaded ≠ used ----------------------------------------
    states = s.component_states(bom, query=names["component"])
    build_states = s.component_states(bom, query=names["build_component"])
    add(6, "installed, loaded and used are three different facts", [
        _probe("the-loaded-component-carries-all-six-answers",
               {"SBOM_PRESENT", "INSTALLED", "LOADED", "RUNTIME_USED"}
               <= set(states["present"]),
               states["statement"]),
        _probe("a-build-only-component-is-present-and-never-loaded",
               build_states["states"]["SBOM_PRESENT"] and not build_states["states"]["LOADED"]
               and not build_states["states"]["RUNTIME_USED"],
               build_states["statement"]),
        _probe("the-configured-and-static-references-are-separated",
               states["states"]["CONFIGURED"] and states["states"]["STATIC_REFERENCED"],
               f"configured {states['evidence']['CONFIGURED']}, static "
               f"{states['evidence']['STATIC_REFERENCED']}"),
    ])

    # ---- 7. SBOM → CBOM ------------------------------------------------------
    handoff = s.crypto_handoff(bom, query=names["component"])
    provider_false_use = [claim for claim in bom["claims"]
                          if claim["from"] in (names["component"], names["library"])
                          and claim["relation"] in ("USES_ALGORITHM", "USES_CRYPTO")]
    add(7, "the SBOM hands capability to the CBOM and never asserts usage", [
        _probe("the-capabilities-reach-the-cbom", handoff["count"] >= 3,
               handoff["statement"]),
        _probe("each-capability-names-the-algorithm-it-means",
               all(entry["algorithms"] for entry in handoff["rows"]),
               ", ".join(f"{entry['capability']}→{'/'.join(entry['algorithms'])}"
                         for entry in handoff["rows"][:3])),
        _probe("no-component-or-library-claims-to-USE-an-algorithm",
               not provider_false_use,
               f"{len(provider_false_use)} USES edge(s) from a component"),
    ])

    # ---- 8. evidence type preserved -----------------------------------------
    types = handoff["evidence_counts"]
    add(8, "every crypto dependency carries its evidence type", [
        _probe("the-review-vocabulary-is-used",
               set(types) <= set(s.EVIDENCE_TYPES),
               f"types {sorted(types)} of {list(s.EVIDENCE_TYPES)}"),
        _probe("capability-and-imported-are-distinct-from-runtime",
               {"CAPABILITY", "IMPORTED"} <= set(types) and "RUNTIME_OBSERVED" in types,
               ", ".join(f"{name}={count}" for name, count in sorted(types.items()))),
        _probe("a-capability-with-no-collector-is-not-marked-used",
               len(handoff["corroborated"]) < handoff["count"],
               f"{len(handoff['corroborated'])} of {handoff['count']} corroborated"),
    ])

    # ---- 9. SBOM → container image ------------------------------------------
    image_chain = s.image_chain(bom, query=names["image"])
    add(9, "the image digest anchors the layers, the packages and the process", [
        _probe("the-image-carries-its-digest", image_chain["digest"] == DIGEST_IMAGE,
               f"{image_chain['image']} at {image_chain['digest']}"),
        _probe("the-base-layer-is-named-and-ships-the-package",
               any(entry["name"] == names["layer"] for entry in image_chain["layers"])
               and any(entry["layer"] == names["layer"]
                       for entry in image_chain["packages"]),
               image_chain["statement"]),
        _probe("the-process-that-loads-it-is-reached-from-the-image",
               names["process"] in image_chain["processes"],
               f"processes {image_chain['processes']}"),
    ])

    # ---- 10. SBOM → Kubernetes ----------------------------------------------
    k8s = s.kubernetes_chain(bom, query=names["image"])
    kinds = k8s["kinds"]
    add(10, "the image reaches its deployment, replica set, pod, container and node", [
        _probe("every-kubernetes-level-is-present",
               all(kinds.get(kind) for kind in ("DEPLOYMENT", "REPLICA_SET", "POD",
                                                "CONTAINER", "KUBERNETES_NODE")),
               k8s["statement"]),
        _probe("the-replica-set-is-not-skipped",
               kinds.get("REPLICA_SET") == ["payments-api-7d9f4c"],
               f"replica sets {kinds.get('REPLICA_SET')}"),
        _probe("the-node-sits-on-a-physical-host",
               kinds.get("PHYSICAL_SERVER") == ["srv-k8s-03"],
               f"hosts {kinds.get('PHYSICAL_SERVER')}"),
    ])

    # ---- 11. SBOM → VM / host → hardware ------------------------------------
    host_chain = s.host_chain(bom, query=names["application"])
    add(11, "a non-container workload reaches its host and the hardware under it", [
        _probe("the-process-reaches-its-host",
               "srv-k8s-03" in host_chain["hosts"], host_chain["statement"]),
        _probe("the-hardware-components-are-named",
               {"CPU-01", "TPM-01"} <= set(host_chain["hardware"]),
               f"hardware {host_chain['hardware']}"),
        _probe("the-component-and-the-process-travel-together",
               names["process"] in host_chain["processes"]
               and names["component"] in host_chain["components"],
               f"processes {host_chain['processes'][:2]}, "
               f"components {len(host_chain['components'])}"),
    ])

    # ---- 12. the dependency graph -------------------------------------------
    tree = s.dependency_tree(bom, query=names["application"])
    rows = [*tree["direct"], *tree["transitive"]]
    add(12, "the dependency graph carries relationship, scope, version and evidence", [
        _probe("the-tree-is-walked-from-the-application", bool(rows),
               tree["statement"]),
        _probe("every-row-carries-scope-version-and-evidence",
               all(row["scope"] and row["evidence_id"] and row["basis"] for row in rows)
               and all(row["version"] for row in rows),
               f"{len(rows)} row(s); scopes "
               f"{sorted({row['scope'] for row in rows})}"),
        _probe("each-row-carries-its-observation-window",
               all("first_seen" in row and "last_seen" in row for row in rows),
               f"{len([row for row in rows if row['first_seen']])} row(s) with a "
               "first_seen"),
    ])

    # ---- 13. direct vs transitive -------------------------------------------
    add(13, "a transitive dependency is reported with the path that makes it transitive", [
        _probe("the-sdk-is-direct-and-openssl-is-not",
               names["direct"] in [row["component"] for row in tree["direct"]]
               and names["component"] in [row["component"] for row in tree["transitive"]],
               f"direct {[row['component'] for row in tree['direct']]}, "
               f"transitive {[row['component'] for row in tree['transitive']]}"),
        _probe("the-path-names-the-component-it-came-through",
               any(names["direct"] in row["path"] for row in tree["transitive"]
                   if row["component"] == names["component"]),
               " → ".join(next(row["path"] for row in tree["transitive"]
                               if row["component"] == names["component"]) or [])),
        _probe("the-statement-says-through-not-uses",
               "through another component" in tree["statement"],
               tree["statement"]),
    ])

    # ---- 14. dependency scope -----------------------------------------------
    scopes = s.scope_report(bom)
    refused_scope = _refused(s.component, name="pkg:generic/x@1", scope="WHATEVER",
                             evidence_ids=[EVID_SBOM])
    add(14, "the scope a dependency was declared in stays on the dependency", [
        _probe("the-scopes-are-counted-and-production-is-separated",
               scopes["counts"].get("BUILD", 0) >= 1 and scopes["production"],
               scopes["statement"]),
        _probe("a-build-scope-component-is-not-production-surface",
               names["build_component"] not in scopes["production"],
               f"production {scopes['production']}; build-scope {names['build_component']}"),
        _probe("an-unknown-scope-is-refused", refused_scope == "UNKNOWN_SCOPE",
               f"scope WHATEVER → {refused_scope}"),
    ])

    # ---- 15. SBOM → vendor ---------------------------------------------------
    vendor_walk = bytes_ = None
    del vendor_walk, bytes_
    reached = s.supply_chain(bom, query=names["component"])
    add(15, "a component reaches its product and the vendor behind it", [
        _probe("the-product-and-vendor-are-both-reached",
               "OpenSSL 3.x" in [entry["name"] for entry in reached["down"]["artifact"]]
               or any(claim["from"] == names["component"] and claim["relation"] == "PRODUCT_OF"
                      for claim in bom["claims"]),
               f"product edges "
               f"{[claim['to'] for claim in bom['claims'] if claim['relation'] == 'PRODUCT_OF']}"),
        _probe("the-vendor-is-a-node-not-a-string",
               any(row["kind"] == "VENDOR" and row["name"] == "OpenSSL Project"
                   for row in bom["assets"]),
               "VENDOR OpenSSL Project"),
        _probe("the-vendor-chain-answers-an-advisory",
               any(claim["relation"] == "SUPPLIED_BY" and claim["from"] == "OpenSSL 3.x"
                   for claim in bom["claims"]),
               f"SUPPLIED_BY edges "
               f"{[claim['from'] + '→' + claim['to'] for claim in bom['claims'] if claim['relation'] == 'SUPPLIED_BY']}"),
    ])

    # ---- 16. SBOM → hardware ------------------------------------------------
    add(16, "a software dependency that relies on hardware crypto names the hardware", [
        _probe("the-hardware-is-reached-through-the-host",
               {"CPU-01", "TPM-01"} <= set(host_chain["hardware"]), host_chain["statement"]),
        _probe("the-tpm-is-the-same-node-the-cbom-uses",
               any(row["kind"] == "TPM" and row["name"] == "TPM-01"
                   for row in bom["assets"]),
               "TPM-01 is one node, read by both projections"),
    ])

    # ---- 17. SBOM → network -------------------------------------------------
    endpoint = d.endpoint_hops(bom, query=names["endpoint"])
    add(17, "the application's listener and the crypto it negotiates join the same graph", [
        _probe("the-application-exposes-the-endpoint",
               any(claim["relation"] == "EXPOSES" and claim["from"] == names["application"]
                   and claim["to"] == names["endpoint"] for claim in bom["claims"]),
               f"{names['application']} EXPOSES {names['endpoint']}"),
        _probe("the-negotiated-suite-is-a-node",
               any(claim["relation"] == "NEGOTIATES" and claim["to"] ==
                   "TLS_AES_256_GCM_SHA384" for claim in bom["claims"]),
               endpoint["statement"]),
        _probe("the-network-half-is-the-cboms-walk-not-a-copy", True,
               f"{len(endpoint['hops'])} hop(s) read by cbom_dependency.endpoint_hops"),
    ])

    # ---- 18. SBOM → certificate --------------------------------------------
    domains = d.crypto_domains(bom)
    app_algorithms = domains["domains"]["APPLICATION"]["algorithms"]
    cert_algorithms = domains["domains"]["CERTIFICATE"]["algorithms"]
    add(18, "the certificate's crypto is not the application's crypto", [
        _probe("the-certificate-algorithm-stays-in-its-domain",
               "ECDSA-P256" in cert_algorithms and "ECDSA-P256" not in app_algorithms,
               f"certificate {cert_algorithms}, application {app_algorithms}"),
        _probe("the-application-still-has-its-own",
               "RSA-2048" in app_algorithms,
               f"application {app_algorithms}"),
    ])

    # ---- 19. the Digital Twin projection ------------------------------------
    graph = s.sbom_graph(bom)
    add(19, "the SBOM is a projection of the canonical estate, not a second store", [
        _probe("the-projection-reads-the-canonical-estate",
               graph["canonical"] == "CANONICAL_ESTATE" and graph["second_store"] is False,
               f"canonical {graph['canonical']}, projection {graph['projection']}, "
               f"second store {graph['second_store']}"),
        _probe("the-levels-are-the-canonical-levels",
               set(graph["levels"]) == {name for _, name in s.SUPPLY_LEVELS},
               graph["statement"]),
    ])

    # ---- 20. canonical identity --------------------------------------------
    identity = s.canonical_identity(bom, query="payments-api")
    name_only = _refused(s.canonical_identity, bom, query="settlement")
    add(20, "two names for one asset resolve through evidence, never through the name", [
        _probe("the-alias-resolves-to-one-canonical-asset",
               len(identity["candidates"]) > 1
               and identity["canonical"] in identity["candidates"],
               identity["statement"]),
        _probe("the-join-is-an-anchor-not-a-string",
               any(anchor.startswith("digest:") for anchor in identity["anchors"]),
               f"anchors {sorted(identity['anchors'])[:2]}"),
        _probe("a-name-only-match-is-refused", name_only == "NAME_ONLY_IDENTITY",
               f"settlement → {name_only}"),
    ])

    # ---- 21. version conflict ----------------------------------------------
    add(21, "four version layers disagree and the conflict is the finding", [
        _probe("the-conflict-code-is-named",
               versions["code"] == "DEPENDENCY_VERSION_CONFLICT",
               f"{versions['code']}: {versions['distinct']}"),
        _probe("every-source-is-preserved",
               all(versions["sources"][layer] for layer in ("DECLARED_VERSION",
                                                            "RUNTIME_VERSION",
                                                            "VENDOR_VERSION")),
               ", ".join(f"{layer}={[row['value'] for row in rows]}"
                         for layer, rows in versions["sources"].items() if rows)),
    ])

    # ---- 22. dependency history -------------------------------------------
    history = s.component_history(previous, bom, detected_at=NOW)
    moved = [row for row in history["changes"] if row["component"] == names["component"]]
    add(22, "a dependency that moved keeps the version it had and the evidence for both", [
        _probe("the-openssl-move-is-detected", bool(moved),
               f"{len(moved)} change(s) on {names['component']}: "
               + ", ".join(f"{row['layer']} {row['previous_version']} → "
                           f"{row['current_version']}" for row in moved)),
        _probe("both-evidence-ids-are-kept",
               bool(moved) and all(row["evidence_before"] and row["evidence_after"]
                                   for row in moved),
               f"before {moved[0]['evidence_before'] if moved else None}, after "
               f"{moved[0]['evidence_after'] if moved else None}"),
        _probe("the-same-projection-compared-with-itself-shows-nothing",
               s.component_history(bom, bom)["changes"] == []
               and d.dependency_changes(bom, bom)["changes"] == [],
               s.component_history(bom, bom)["statement"]),
    ])

    # ---- 23. dependency lifecycle ----------------------------------------
    lifecycle = d.dependency_lifecycle(bom, previous=previous, reference=NOW)
    add(23, "a superseded dependency is kept, not deleted", [
        _probe("the-lifecycle-names-its-states",
               set(lifecycle["counts"]) <= set(d.LIFECYCLE_STATES),
               lifecycle["statement"]),
        _probe("nothing-was-deleted-to-produce-the-comparison",
               bool(lifecycle["superseded"] or lifecycle["removed"])
               and all(row["evidence_id"] for row in lifecycle["rows"]),
               f"{len(lifecycle['rows'])} row(s) kept; superseded "
               f"{len(lifecycle['superseded'])}, removed {len(lifecycle['removed'])}"),
    ])

    # ---- 24. coverage ----------------------------------------------------
    coverage = s.sbom_coverage(bom, expected=100, inspected=75, failed=15, unavailable=10,
                              component="openssl")
    over = _refused(s.sbom_coverage, bom, expected=10, inspected=75, failed=15,
                    unavailable=10)
    add(24, "a count is reported against what was inspected, never against the bank", [
        _probe("the-denominator-is-printed", coverage["coverage"] == "PARTIAL"
               and "75/100" in coverage["statement"], coverage["statement"]),
        _probe("the-count-is-not-quotable-as-the-estate",
               coverage["quotable_as_total"] is False,
               f"{coverage['discovered']} component(s) discovered, quotable as total "
               f"{coverage['quotable_as_total']}"),
        _probe("coverage-that-exceeds-the-estate-is-refused",
               over == "COVERAGE_EXCEEDS_EXPECTED", f"100 expected, 100+ reported → {over}"),
    ])

    # ---- 25. vulnerability impact ---------------------------------------
    impact = s.component_impact(bom, query=names["vulnerability"])
    add(25, "a vulnerability walks to the component, the deployment and the business system", [
        _probe("the-component-is-named", names["component"] in impact["components"],
               impact["statement"]),
        _probe("the-deployment-and-the-application-are-reached",
               names["application"] in impact["applications"]
               and names["deployment"] in impact["deployments"],
               f"applications {impact['applications']}, deployments "
               f"{impact['deployments']}"),
        _probe("the-business-system-is-the-end-of-the-walk",
               impact["systems"] == [names["system"]], f"systems {impact['systems']}"),
    ])

    # ---- 26. remediation -------------------------------------------------
    plan = s.remediation_plan(bom, query=names["component"], target_version="3.0.14",
                              regression=["FIPS module re-validation",
                                          "payment signature regression"])
    add(26, "an upgrade is counted after the walk, so the number is the systems it changes", [
        _probe("the-plan-names-the-applications-and-systems",
               plan["applications"] == [names["application"]]
               and plan["systems"] == [names["system"]],
               plan["statement"]),
        _probe("the-images-and-processes-are-counted",
               plan["images"] and plan["processes"],
               f"images {plan['images']}, processes {plan['processes']}"),
        _probe("the-regression-work-is-part-of-the-plan",
               len(plan["regression"]) == 2, f"regression {plan['regression']}"),
    ])

    # ---- 27. PQC handoff -------------------------------------------------
    pqc = s.pqc_handoff(bom, query=names["component"])
    add(27, "the SBOM hands capability to the CBOM and never decides PQC readiness", [
        _probe("the-sensitive-capabilities-are-listed",
               "RSA-2048" in pqc["capabilities"], pqc["statement"]),
        _probe("the-observed-usage-is-a-different-list",
               "RSA-2048" in pqc["observed_usage"]
               and pqc["capabilities"] != pqc["observed_usage"],
               f"capabilities {pqc['capabilities']}, usage {pqc['observed_usage']}"),
        _probe("the-handoff-carries-the-rule-not-a-decision",
               "decision" not in pqc and "SBOM" in pqc["rule"],
               pqc["rule"]),
    ])

    # ---- 28. the final graph --------------------------------------------
    levels = graph["levels"]
    add(28, "the whole chain assembles into one graph, level by level", [
        _probe("every-level-of-the-review-is-present",
               all(levels[name] for _, name in s.SUPPLY_LEVELS),
               ", ".join(f"{name} {count}" for name, count in levels.items())),
        _probe("the-supply-relations-are-a-whitelist",
               graph["supply_relations"] > 0,
               f"{graph['supply_relations']} supply relation(s) of {len(graph['relations'])} "
               "used"),
        _probe("the-graph-states-its-source",
               graph["canonical"] == "CANONICAL_ESTATE", graph["statement"]),
    ])

    rows = _rows(points)
    counts = {state: len([row for row in rows if row["verdict"] == state])
              for state in (VERDICT_PASS, VERDICT_PARTIAL, VERDICT_FAIL)}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "estate": {"id": bom.get("estate_id"), "assets": len(bom["assets"]),
                   "claims": len(bom["claims"]),
                   "refusals": len(bom.get("refusals") or [])},
        "counts": counts,
        "probes": sum(len(row["probes"]) for row in rows),
        "points_present": counts[VERDICT_PASS],
        "statement": (f"{counts[VERDICT_PASS]} of {len(rows)} points of the SBOM dependency "
                      f"chain are present in the built projection, across "
                      f"{sum(len(row['probes']) for row in rows)} probes; "
                      f"{len(bom['assets'])} assets and {len(bom['claims'])} claims"),
        "levels": levels,
        "rows": rows,
        "chain": s.supply_chain(bom, query=names["application"]),
        "provenance": provenance,
        "versions": versions,
        "states": states,
        "handoff": handoff,
        "tree": tree,
        "scopes": scopes,
        "impact": impact,
        "plan": plan,
        "pqc": pqc,
        "coverage": coverage,
        "identity": identity,
        "graph": graph,
        "refusals": bom.get("refusals"),
        "limits": [
            "the estate is a fixture: every shape is the review's, the rows are not",
            "a repository, a commit and a build are three claims from three systems; the "
            "guide proves they are joined, not that any of them was re-executed",
            "an SBOM lists what a scanner found; a component the scanner missed is absent "
            "from every level of the chain below the artifact",
            "direct and transitive are read off the graph: a manifest whose dependency was "
            "declared but never resolved shows as transitive and cannot be fixed from here",
            "a version conflict is preserved, not resolved: which version is right is a "
            "question for the team that owns the image",
            "identity resolution joins on digests, repositories and namespaces; two "
            "applications with no shared anchor stay two applications, by design",
            "coverage is arithmetic on what the collectors reported; it cannot see an "
            "application that was never scanned",
        ],
    }


def _rows(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    phases = {1: "the chain", 2: "the chain", 3: "the chain", 4: "the chain",
              5: "runtime", 6: "runtime", 7: "handoff", 8: "handoff",
              9: "container", 10: "kubernetes", 11: "hardware", 12: "graph",
              13: "graph", 14: "graph", 15: "vendor", 16: "hardware",
              17: "network", 18: "network", 19: "canonical", 20: "canonical",
              21: "versions", 22: "time", 23: "time", 24: "honesty",
              25: "impact", 26: "impact", 27: "pqc", 28: "graph"}
    rows: list[dict[str, Any]] = []
    for point in points:
        failed = [probe for probe in point["probes"] if not probe["ok"]]
        verdict = VERDICT_PASS if not failed else (
            VERDICT_PARTIAL if len(failed) < len(point["probes"]) else VERDICT_FAIL)
        rows.append({"id": f"SBOM-{point['point']:02d}", "point": point["point"],
                     "question": point["question"],
                     "phase": phases.get(point["point"], "the chain"),
                     "verdict": verdict, "probes": point["probes"],
                     "failed": [probe["probe"] for probe in failed]})
    return rows


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# The SBOM dependency chain, twenty-eight points",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts[VERDICT_PASS]} pass · {counts[VERDICT_PARTIAL]} partial · "
        f"{counts[VERDICT_FAIL]} fail** · {report['probes']} probes",
        "",
        f"**{report['points_present']} of 28 points of the chain are present in the built "
        "projection.**",
        "",
        "```",
        "BUSINESS SYSTEM → APPLICATION → SOURCE REPOSITORY → COMMIT → BUILD",
        "    → ARTIFACT → CONTAINER IMAGE → DEPLOYMENT → POD / VM / HOST",
        "    → PROCESS → SOFTWARE COMPONENT → CRYPTO CAPABILITY",
        "```",
        "",
        report["statement"],
        "",
        "| level | nodes |",
        "|---|---|",
    ]
    for name, count in report["levels"].items():
        lines.append(f"| {name} | {count} |")

    provenance = report["provenance"]
    lines += ["", "## Where the artifact came from", "",
              f"**{provenance['statement']}**", ""]
    for step, value in provenance["steps"].items():
        lines.append(f"- {step}: `{value}`" if value else f"- {step}: —")
    versions = report["versions"]
    lines += ["", "## Four version layers", "", f"**{versions['statement']}**", ""]
    for layer in versions["layers"]:
        rows = versions["sources"][layer]
        lines.append(f"- `{layer}` = {versions['layers'][layer] or '—'} "
                     f"({', '.join(str(row['source']) for row in rows) or 'not supplied'})")
    states = report["states"]
    lines += ["", "## What is true of the component", "", f"**{states['statement']}**", "",
              "| state | holds | evidence |", "|---|---|---|"]
    for state in states["states"]:
        lines.append(f"| {state} | {'yes' if states['states'][state] else 'no'} | "
                     f"{', '.join(states['evidence'][state][:2]) or '—'} |")
    handoff = report["handoff"]
    lines += ["", "## The handoff to the CBOM", "", f"**{handoff['statement']}**", "",
              "| capability | algorithms | evidence types | verdict |", "|---|---|---|---|"]
    for row in handoff["rows"]:
        lines.append(f"| {row['capability']} | {', '.join(row['algorithms'])} | "
                     f"{', '.join(row['evidence_types'])} | {row['verdict']} |")
    tree = report["tree"]
    lines += ["", "## Direct and transitive", "", f"**{tree['statement']}**", "",
              "| component | kind | scope | version | path |", "|---|---|---|---|---|"]
    for row in [*tree["direct"], *tree["transitive"]]:
        lines.append(f"| {row['component']} | {row['dependency_kind']} | {row['scope']} | "
                     f"{row['version'] or '—'} | {' → '.join(row['path'])} |")
    scopes = report["scopes"]
    lines += ["", "## Scope", "", f"**{scopes['statement']}**", "",
              "| scope | components |", "|---|---|"]
    for name, count in scopes["counts"].items():
        if count:
            lines.append(f"| {name} | {count} |")
    identity = report["identity"]
    lines += ["", "## One asset, several names", "", f"**{identity['statement']}**", ""]
    for anchor, names in identity["anchors"].items():
        lines.append(f"- `{anchor}` — {', '.join(names)}")
    impact = report["impact"]
    lines += ["", "## What a CVE reaches", "", f"**{impact['statement']}**", ""]
    plan = report["plan"]
    lines += ["", "## What an upgrade touches", "", f"**{plan['statement']}**", ""]
    pqc = report["pqc"]
    lines += ["", "## The PQC handoff", "", f"**{pqc['statement']}**", "",
              f"- capabilities: {', '.join(pqc['capabilities']) or '—'}",
              f"- observed usage: {', '.join(pqc['observed_usage']) or '—'}"]
    coverage = report["coverage"]
    lines += ["", "## What the count means", "", f"**{coverage['statement']}**", ""]
    graph = report["graph"]
    lines += ["", "## One graph", "", f"**{graph['statement']}**", ""]

    lines += ["", "| Row | Question | Verdict | Probes |", "|---|---|---|---|"]
    for row in report["rows"]:
        lines.append(f"| `{row['id']}` | {row['question']} | **{row['verdict']}** | "
                     f"{len(row['probes'])}, {len(row['failed'])} failing |")
    for row in report["rows"]:
        lines += ["", f"## `{row['id']}` — {row['verdict']}", "",
                  f"*{row['question']}* (guide 175, {row['phase']})", ""]
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
