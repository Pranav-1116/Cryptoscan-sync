"""The SBOM dependency chain — the supply levels, the states and the handoff, as tests."""

from __future__ import annotations

import pytest
from cbom import cbom_dependency as dep
from cbom import nbom_graph as n
from cbom import sbom_dependency as sbom
from cbom import techbom as tb

EVID_SRC = "EVID-94101"
EVID_BUILD = "EVID-94102"
EVID_SBOM = "EVID-94103"
EVID_IMG = "EVID-94104"
EVID_K8S = "EVID-94105"
EVID_RT = "EVID-94106"
EVID_STATIC = "EVID-94107"
EVID_VENDOR = "EVID-94108"
EVID_NET = "EVID-94109"
EVID_HSM = "EVID-94110"

NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"
OLD = "2026-10-01T08:30:00Z"

DIGEST_ARTIFACT = "sha256:abc123def4567890abc123def4567890"
DIGEST_IMAGE = "sha256:8af92c1d4e5f60718293a4b5c6d7e8f9"


# --------------------------------------------------------------------------- #
# The fixture: one workload, repository → commit → build → artifact → image
# --------------------------------------------------------------------------- #

def document(*, declared_version: str = "3.0.13", runtime_version: str = "3.0.11",
             legacy_library: bool = False) -> dict:
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM",
                          evidence_ids=[EVID_SRC])
    application = n.service_of(name="Payments API", kind="APPLICATION",
                               evidence_ids=[EVID_SRC])
    sha = sbom.commit(sha="a81f92c", author="payments-team", committed_at=EARLIER,
                      evidence_ids=[EVID_SRC])
    repository = sbom.source_repository(name="git.bank.internal/payments/payments-api",
                                        url="https://git.bank.internal",
                                        application_rows=[application], commit_row=sha,
                                        evidence_ids=[EVID_SRC])
    build_part = sbom.build(name="BUILD-18291", commit_row=sha,
                            pipeline="jenkins-payments-ci", evidence_ids=[EVID_BUILD])
    artifact_row = sbom.artifact(name="payments-api-4.2.1.jar", digest_value=DIGEST_ARTIFACT,
                                 build_row=build_part["assets"][0], kind="JAR",
                                 evidence_ids=[EVID_BUILD])

    vendor_product = tb.asset("VENDOR_PRODUCT", "OpenSSL 3.x", evidence_ids=[EVID_VENDOR])
    vendor = tb.asset("VENDOR", "OpenSSL Project", evidence_ids=[EVID_VENDOR])
    openssl = sbom.component(
        name="pkg:generic/openssl", version=declared_version, scope="RUNTIME", crypto=True,
        product_row=vendor_product, evidence_ids=[EVID_SBOM],
        version_claims=[
            {"source": "sbom", "value": declared_version, "class": "IMPORTED",
             "evidence_id": EVID_SBOM},
            {"source": "image-scan", "value": declared_version, "class": "STATIC_OBSERVED",
             "evidence_id": EVID_IMG},
            {"source": "process-map", "value": runtime_version,
             "class": "RUNTIME_OBSERVED", "evidence_id": EVID_RT},
            {"source": "vendor-portal", "value": declared_version,
             "class": "VENDOR_DECLARED", "evidence_id": EVID_VENDOR}])
    http_core = sbom.component(name="pkg:generic/http-core@1.2.0", version="1.2.0",
                               scope="TRANSITIVE", evidence_ids=[EVID_SBOM])
    payments_sdk = sbom.component(name="pkg:generic/payments-sdk@2.4.0", version="2.4.0",
                                  scope="RUNTIME", depends_on=[http_core], direct=True,
                                  evidence_ids=[EVID_SBOM])
    sdk_to_http = n.part(claims=[
        tb.claim("pkg:generic/payments-sdk@2.4.0", "DEPENDS_ON",
                 "pkg:generic/http-core@1.2.0", basis="sbom-import",
                 evidence_ids=[EVID_SBOM], scope="TRANSITIVE",
                 dependency_kind="TRANSITIVE", first_seen=OLD, last_seen=NOW)])
    http_to_openssl = n.part(claims=[
        tb.claim("pkg:generic/http-core@1.2.0", "DEPENDS_ON", "pkg:generic/openssl",
                 basis="dependency-graph", evidence_ids=[EVID_SBOM], scope="RUNTIME",
                 dependency_kind="TRANSITIVE", first_seen=OLD, last_seen=NOW,
                 rule="http-core resolves TLS through the system provider")])
    build_tool = sbom.component(name="pkg:generic/maven@3.9.6", version="3.9.6", scope="BUILD",
                                direct=True, evidence_ids=[EVID_BUILD])
    dev_only = sbom.component(name="pkg:generic/mockito@5.4.0", version="5.4.0",
                              scope="TEST", evidence_ids=[EVID_BUILD])
    # installed in an image that is deployed nowhere it matters
    openssl_dev = sbom.component(name="pkg:generic/openssl-dev", version=declared_version,
                                 scope="BUILD", evidence_ids=[EVID_IMG])
    orphan = tb.asset("PACKAGE", "pkg:generic/orphan@0.1.0", evidence_ids=[EVID_SBOM],
                      scope="RUNTIME")
    ghost = tb.asset("PACKAGE", "pkg:generic/ghost@0.0.9", evidence_ids=[EVID_SBOM],
                     scope="RUNTIME")

    sbom_row = sbom.sbom(name="SBOM-18291", artifact_row=artifact_row["assets"][0],
                         components=[payments_sdk, http_core, openssl, build_tool, dev_only,
                                     orphan],
                         tool="syft-1.18", generated_at=EARLIER, evidence_ids=[EVID_SBOM])
    layer_part = sbom.layer(name="layer:ubuntu-22.04-base", base="ubuntu:22.04",
                            packages=[openssl], evidence_ids=[EVID_IMG])
    tools_layer = sbom.layer(name="layer:reporting-tools", base="ubuntu:22.04",
                             packages=[openssl_dev], evidence_ids=[EVID_IMG])
    report_host = tb.asset("PHYSICAL_SERVER", "srv-lb-01", evidence_ids=[EVID_K8S])
    reporting_image = sbom.image(name="reporting-api:1.0.0",
                                 digest_value="sha256:1122aabbccdd3344eeff5566",
                                 base="ubuntu:22.04", layers=[tools_layer],
                                 evidence_ids=[EVID_IMG])
    image_part = sbom.image(name="payments-api:4.2.1", digest_value=DIGEST_IMAGE,
                            artifact_row=artifact_row["assets"][0], base="ubuntu:22.04",
                            layers=[layer_part], evidence_ids=[EVID_IMG])
    installed = n.part(claims=[
        tb.claim("pkg:generic/openssl", "INSTALLED_IN", "payments-api:4.2.1",
                 basis="sbom-import", evidence_ids=[EVID_IMG]),
        tb.claim("pkg:generic/openssl-dev", "INSTALLED_IN", "srv-lb-01",
                 basis="agent-inventory", evidence_ids=[EVID_IMG]),
        tb.claim("pkg:generic/openssl-dev", "INSTALLED_IN", "reporting-api:1.0.0",
                 basis="sbom-import", evidence_ids=[EVID_IMG])])

    # the release is the node the application ships and the artifact is what it bundles:
    # without it the application and its SBOM are two facts in one database
    release = tb.asset("RELEASE", "payments-api 4.2.1", evidence_ids=[EVID_BUILD],
                       channel="PRODUCTION")
    released = n.part(claims=[
        tb.claim("Payments API", "RELEASED_AS", "payments-api 4.2.1",
                 basis="agent-inventory", evidence_ids=[EVID_BUILD]),
        tb.claim("payments-api 4.2.1", "BUNDLES", "payments-api-4.2.1.jar",
                 basis="agent-inventory", evidence_ids=[EVID_BUILD])])
    # the same application recorded under its older name, joined by the artifact digest
    alias_application = n.service_of(name="payment-service", kind="APPLICATION",
                                     evidence_ids=[EVID_IMG])
    alias_artifact = tb.asset("ARTIFACT", "payment-service-4.2.1.jar", evidence_ids=[EVID_IMG],
                              digest=DIGEST_ARTIFACT, artifact_kind="JAR")
    alias_release = tb.asset("RELEASE", "payment-service 4.2.1", evidence_ids=[EVID_IMG])
    alias = n.part(alias_application, alias_release, alias_artifact, claims=[
        tb.claim("payment-service", "RELEASED_AS", "payment-service 4.2.1",
                 basis="api-poll", evidence_ids=[EVID_IMG]),
        tb.claim("payment-service 4.2.1", "BUNDLES", "payment-service-4.2.1.jar",
                 basis="api-poll", evidence_ids=[EVID_IMG])])

    deployment_row = tb.asset("DEPLOYMENT", "payments-api-deploy", evidence_ids=[EVID_K8S])
    pod = tb.asset("POD", "payments-api-7d9f4c-x2m8p", evidence_ids=[EVID_K8S])
    container = tb.asset("CONTAINER", "payments-api-ctr", evidence_ids=[EVID_K8S])
    node = tb.asset("KUBERNETES_NODE", "node-03", evidence_ids=[EVID_K8S])
    host = tb.asset("PHYSICAL_SERVER", "srv-k8s-03", evidence_ids=[EVID_K8S])
    cpu = tb.asset("CPU", "CPU-01", evidence_ids=[EVID_K8S], model="Xeon 6348")
    tpm = tb.asset("TPM", "TPM-01", evidence_ids=[EVID_K8S], version="2.0")
    os_row = tb.asset("OS", "Ubuntu 22.04 LTS", evidence_ids=[EVID_IMG])
    topology = n.part(claims=[
        tb.claim("payments-api:4.2.1", "DEPLOYED_AS", "payments-api-deploy",
                 basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        tb.claim("payments-api-deploy", "SCHEDULES", "payments-api-7d9f4c-x2m8p",
                 basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        tb.claim("payments-api-7d9f4c-x2m8p", "RUNS_CONTAINER", "payments-api-ctr",
                 basis="runtime-probe", evidence_ids=[EVID_K8S]),
        tb.claim("payments-api-ctr", "FROM_IMAGE", "payments-api:4.2.1",
                 basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        tb.claim("payments-api-7d9f4c-x2m8p", "SCHEDULED_ON", "node-03",
                 basis="deployment-metadata", evidence_ids=[EVID_K8S]),
        tb.claim("node-03", "RUNS_ON", "srv-k8s-03", basis="agent-inventory",
                 evidence_ids=[EVID_K8S]),
        tb.claim("srv-k8s-03", "HAS_COMPONENT", "CPU-01", basis="agent-inventory",
                 evidence_ids=[EVID_K8S]),
        tb.claim("srv-k8s-03", "HAS_COMPONENT", "TPM-01", basis="agent-inventory",
                 evidence_ids=[EVID_K8S]),
        tb.claim("srv-k8s-03", "HOSTS_OS", "Ubuntu 22.04 LTS", basis="agent-inventory",
                 evidence_ids=[EVID_IMG])])

    process = tb.asset("PROCESS", "payments-api[1821]", evidence_ids=[EVID_RT], pid=1821)
    library = tb.asset("CRYPTO_LIBRARY", "libcrypto.so.3", evidence_ids=[EVID_RT])
    legacy = ([tb.asset("CRYPTO_LIBRARY", "libcrypto.so.1.1", evidence_ids=[EVID_RT])]
              if legacy_library else [])
    provider = tb.asset("CRYPTO_PROVIDER", f"OpenSSL {declared_version}",
                        version=declared_version, family="OPENSSL", evidence_ids=[EVID_RT])
    rsa = n.algorithm(name="RSA-2048", family="RSA", key_size=2048, evidence_ids=[EVID_RT])
    aes = n.algorithm(name="AES-256-GCM", family="AES", key_size=256, mode="GCM",
                      evidence_ids=[EVID_RT])
    ecdsa = n.algorithm(name="ECDSA-P256", family="ECDSA", curve="P-256",
                        evidence_ids=[EVID_NET])
    capability = dep.capability(provider_row=library, algorithm_row=rsa,
                                basis="capability-list", evidence_ids=[EVID_SBOM])
    capability_aes = dep.capability(provider_row=library, algorithm_row=aes,
                                    basis="capability-list", evidence_ids=[EVID_SBOM])
    capability_ecdsa = dep.capability(provider_row=library, algorithm_row=ecdsa,
                                      basis="capability-list", evidence_ids=[EVID_SBOM])
    process_run = n.part(claims=[
        tb.claim("payments-api-7d9f4c-x2m8p", "RUNS_PROCESS", "payments-api[1821]",
                 basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        tb.claim("payments-api[1821]", "RUNS_APPLICATION", "Payments API",
                 basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        tb.claim("payments-api[1821]", "LOADS",
                 "libcrypto.so.1.1" if legacy_library else "libcrypto.so.3",
                 basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        tb.claim("payments-api[1821]", "LOADS", "pkg:generic/openssl",
                 basis="runtime-probe", evidence_ids=[EVID_RT], observed_at=NOW),
        tb.claim("pkg:generic/openssl", "LINKS", "libcrypto.so.3", basis="sbom-import",
                 evidence_ids=[EVID_SBOM]),
        tb.claim("libcrypto.so.3", "SUPPORTS", capability["assets"][-1]["name"],
                 basis="capability-list", evidence_ids=[EVID_SBOM]),
        tb.claim("libcrypto.so.3", "SUPPORTS", capability_aes["assets"][-1]["name"],
                 basis="capability-list", evidence_ids=[EVID_SBOM]),
        tb.claim("libcrypto.so.3", "SUPPORTS", capability_ecdsa["assets"][-1]["name"],
                 basis="capability-list", evidence_ids=[EVID_SBOM]),
        tb.claim("Ubuntu 22.04 LTS", "SUPPORTS", "AES-256-GCM", basis="config-parse",
                 evidence_ids=[EVID_IMG])])
    operation = dep.runtime_operation(
        name="OP-SIGN-001", process_row=process, application_row=application,
        operation="SIGN", algorithm_row=rsa, provider_row=provider, key_size=2048,
        padding="PSS", hash_name="SHA-256", purpose="payment signature",
        evidence_ids=[EVID_RT], observed_at=NOW, first_seen=EARLIER, last_seen=NOW)
    hsm = tb.asset("HSM", "HSM-001", evidence_ids=[EVID_HSM], model="nShield")
    key = n.key_reference(name="KEY-REF-4401", key_ref="pkcs11:token=bank;id=4401",
                          purpose="SIGNING", algorithm="RSA", key_size=2048,
                          holder="HSM-001", evidence_ids=[EVID_HSM])
    bound = dep.key_binding(operation_row=operation["assets"][0], key_row=key,
                            holder_row=hsm, basis="runtime-observation",
                            evidence_ids=[EVID_HSM])
    static_call = dep.static_dependency(
        application_row=application, source_file="src/main/java/bank/PaymentsCrypto.java",
        api="EVP_DigestSignInit", algorithm_row=rsa, line=214,
        evidence_ids=[EVID_STATIC], first_seen=OLD, last_seen=EARLIER)

    endpoint = n.endpoint(host="203.0.113.10", port=443,
                          name="payments.bank.example:443",
                          tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                          evidence_ids=[EVID_NET])
    suite = n.cipher_suite(name="TLS_AES_256_GCM_SHA384", tls_version="TLS1.3",
                           bulk="AES-256-GCM", evidence_ids=[EVID_NET])
    certificate = n.certificate(name="CERT-001", subject="CN=payments.bank.example",
                                issuer="Bank Issuing CA",
                                signature_algorithm="ECDSA-SHA256",
                                evidence_ids=[EVID_NET])
    public_key = tb.asset("PUBLIC_KEY", "PUB-001", evidence_ids=[EVID_NET], key_size=256)
    issuer = n.authority(name="Bank Issuing CA", evidence_ids=[EVID_NET])
    chain = n.certificate_chain(certificate_row=certificate, key_row=public_key,
                                key_algorithm_row=ecdsa, signature_algorithm_row=ecdsa,
                                issuer_row=issuer, basis="packet-capture",
                                evidence_ids=[EVID_NET])
    exposed = n.part(claims=[
        tb.claim("Payments API", "EXPOSES", "payments.bank.example:443",
                 basis="config-parse", evidence_ids=[EVID_NET]),
        tb.claim("payments.bank.example:443", "NEGOTIATES", "TLS_AES_256_GCM_SHA384",
                 basis="tls-handshake", evidence_ids=[EVID_NET], observed_at=NOW),
        tb.claim("payments.bank.example:443", "PRESENTS", "CERT-001",
                 basis="tls-handshake", evidence_ids=[EVID_NET])])

    vulnerability = tb.asset("VULNERABILITY", "CVE-2026-0002", evidence_ids=[EVID_VENDOR],
                             severity="HIGH")
    advisory = n.part(claims=[
        tb.claim("pkg:generic/openssl", "HAS_VULNERABILITY", "CVE-2026-0002",
                 basis="vendor-portal", evidence_ids=[EVID_VENDOR]),
        tb.claim("OpenSSL 3.x", "SUPPLIED_BY", "OpenSSL Project", basis="vendor-datasheet",
                 evidence_ids=[EVID_VENDOR])])

    tag_only = tb.asset("ARTIFACT", "payments-api:latest", tag="latest",
                        evidence_ids=[EVID_IMG])
    tag_sbom = tb.asset("SBOM", "SBOM-latest", evidence_ids=[EVID_IMG],
                        sbom_format="CycloneDX-1.6")
    tag_binding = n.part(claims=[
        tb.claim("payments-api:latest", "DESCRIBED_BY", "SBOM-latest", basis="sbom-import",
                 evidence_ids=[EVID_IMG])])

    doc = n.estate(
        system, application, repository, sha, build_part, artifact_row, sbom_row,
        payments_sdk, http_core, openssl, build_tool, dev_only, openssl_dev, orphan,
        vendor_product,
        vendor, ghost, sdk_to_http, http_to_openssl, layer_part, image_part, installed,
        report_host, reporting_image, release, released, alias, deployment_row, pod,
        container, node, host, cpu, tpm,
        os_row, topology, process, library, *legacy, provider, rsa, aes, capability,
        capability_aes, capability_ecdsa, process_run, operation, hsm, key, bound,
        static_call, endpoint, suite, certificate, ecdsa, public_key, issuer, chain, exposed,
        vulnerability, advisory, tag_only, tag_sbom, tag_binding,
        n.part(claims=[tb.claim("Payments System", "CONTAINS", "Payments API",
                               basis="cmdb-import", evidence_ids=[EVID_SRC])]),
        estate_id="bank-sbom", environment="PRODUCTION")
    return {"estate": doc, "names": {
        "application": "Payments API", "system": "Payments System",
        "repository": "git.bank.internal/payments/payments-api", "commit": "a81f92c",
        "build": "BUILD-18291", "artifact": "payments-api-4.2.1.jar",
        "sbom": "SBOM-18291", "image": "payments-api:4.2.1", "deployment":
        "payments-api-deploy", "pod": "payments-api-7d9f4c-x2m8p",
        "process": "payments-api[1821]", "component": "pkg:generic/openssl",
        "direct": "pkg:generic/payments-sdk@2.4.0",
        "transitive": "pkg:generic/http-core@1.2.0",
        "build_component": "pkg:generic/maven@3.9.6",
        "dev_component": "pkg:generic/openssl-dev",
        "orphan": "pkg:generic/orphan@0.1.0", "ghost": "pkg:generic/ghost@0.0.9",
        "vulnerability": "CVE-2026-0002", "library": "libcrypto.so.3"}}


@pytest.fixture(scope="module")
def built() -> dict:
    current = document()
    previous = document(declared_version="3.0.11", runtime_version="3.0.11",
                        legacy_library=True)
    return {"bom": tb.build(current["estate"]), "previous": tb.build(previous["estate"]),
            "names": current["names"]}


@pytest.fixture(scope="module")
def bom(built: dict) -> dict:
    return built["bom"]


@pytest.fixture(scope="module")
def names(built: dict) -> dict:
    return built["names"]


# --------------------------------------------------------------------------- #
# The vocabulary
# --------------------------------------------------------------------------- #

def test_twelve_supply_levels_from_the_system_to_the_capability():
    assert [name for _, name in sbom.SUPPLY_LEVELS] == [
        "system", "application", "repository", "commit", "build", "artifact", "image",
        "deployment", "pod", "process", "component", "capability"]
    assert len(sbom.SUPPLY_LEVELS) == 12


def test_six_component_states_and_five_deployment_states():
    assert sbom.COMPONENT_STATES == ("SBOM_PRESENT", "INSTALLED", "LOADED", "CONFIGURED",
                                     "STATIC_REFERENCED", "RUNTIME_USED")
    assert sbom.DEPLOYMENT_STATES == ("EXISTS", "INSTALLED", "DEPLOYED", "RUNNING",
                                      "LOADED")


def test_four_version_layers_and_eight_evidence_types():
    assert sbom.VERSION_LAYERS == ("DECLARED_VERSION", "IMAGE_VERSION", "RUNTIME_VERSION",
                                   "VENDOR_VERSION")
    assert len(sbom.EVIDENCE_TYPES) == 8


def test_only_runtime_and_network_observations_are_proven():
    assert sbom.PROVEN_EVIDENCE == frozenset({"RUNTIME_OBSERVED", "NETWORK_OBSERVED"})
    assert "CAPABILITY" not in sbom.PROVEN_EVIDENCE
    assert "STATIC_OBSERVED" not in sbom.PROVEN_EVIDENCE


def test_an_undifferentiated_observation_is_a_runtime_observation_not_a_capability():
    assert sbom.CLASS_TO_EVIDENCE[tb.OBSERVED] == "RUNTIME_OBSERVED"
    assert sbom.CLASS_TO_EVIDENCE[tb.CAPABILITY] == "CAPABILITY"
    assert sbom.CLASS_TO_EVIDENCE[tb.INFERRED] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def test_a_repository_hangs_off_the_application_and_holds_the_commit():
    application = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID_SRC])
    sha = sbom.commit(sha="a81f92c", evidence_ids=[EVID_SRC])
    part = sbom.source_repository(name="git.bank.internal/payments/payments-api",
                                  application_rows=[application], commit_row=sha,
                                  evidence_ids=[EVID_SRC])
    relations = [claim["relation"] for claim in part["claims"]]
    assert relations == ["TRACKED_IN", "AT_COMMIT"]
    assert part["assets"][0]["kind"] == "REPOSITORY"


def test_a_commit_without_a_sha_is_a_branch_not_a_revision():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.commit(sha="main")
    assert excinfo.value.code == "COMMIT_WITHOUT_SHA"


def test_an_artifact_without_a_digest_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.artifact(name="payments-api:latest", digest_value="latest")
    assert excinfo.value.code == "ARTIFACT_WITHOUT_DIGEST"


def test_an_image_tag_is_not_an_identity():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.image(name="payments-api:4.2.1", digest_value="4.2.1")
    assert excinfo.value.code == "IMAGE_WITHOUT_DIGEST"


def test_the_build_names_the_commit_it_built_from_and_the_artifact_it_produced():
    sha = sbom.commit(sha="a81f92c", evidence_ids=[EVID_SRC])
    artifact_row = sbom.artifact(name="payments-api-4.2.1.jar", digest_value=DIGEST_ARTIFACT,
                                 evidence_ids=[EVID_BUILD])
    part = sbom.build(name="BUILD-18291", commit_row=sha, artifact_rows=[artifact_row],
                      evidence_ids=[EVID_BUILD])
    relations = [claim["relation"] for claim in part["claims"]]
    assert relations == ["BUILT_FROM", "PRODUCES"]


def test_a_layer_keeps_the_claims_of_the_packages_it_ships():
    package = sbom.component(name="pkg:generic/openssl", version="3.0.13",
                             depends_on=[sbom.component(name="pkg:generic/zlib@1.3",
                                                        version="1.3",
                                                        evidence_ids=[EVID_SBOM])],
                             evidence_ids=[EVID_SBOM])
    part = sbom.layer(name="layer:base", packages=[package], evidence_ids=[EVID_IMG])
    relations = {claim["relation"] for claim in part["claims"]}
    assert relations == {"SHIPS", "DEPENDS_ON"}
    assert part["assets"][0]["kind"] == "IMAGE_LAYER"


def test_an_image_keeps_the_claims_of_its_layers_and_their_packages(built: dict):
    relations = {claim["relation"] for claim in built["bom"]["claims"]}
    assert {"HAS_LAYER", "SHIPS", "LISTS", "PACKAGED_AS"} <= relations


def test_an_sbom_lists_its_components_and_keeps_what_they_depend_on(built: dict):
    bom = built["bom"]
    listed = [claim for claim in bom["claims"]
              if claim["relation"] == "LISTS"
              and claim["from"] == "SBOM-18291"]
    assert len(listed) == 6
    depended = [claim for claim in bom["claims"] if claim["relation"] == "DEPENDS_ON"]
    assert {claim["facts"]["scope"] for claim in depended} == {"TRANSITIVE", "RUNTIME"}


def test_an_unknown_scope_is_refused_rather_than_defaulted():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.component(name="pkg:generic/x", scope="SHIPPED-ISH")
    assert excinfo.value.code == "UNKNOWN_SCOPE"


def test_directness_is_what_the_manifest_declared():
    part = sbom.component(name="pkg:generic/payments-sdk@2.4.0", scope="RUNTIME",
                          direct=True, evidence_ids=[EVID_SBOM])
    assert part["assets"][0]["attributes"]["direct"] is True
    plain = sbom.component(name="pkg:generic/other@1.0", evidence_ids=[EVID_SBOM])
    assert plain["assets"][0]["attributes"]["direct"] is False


# --------------------------------------------------------------------------- #
# The chain, read off the projection
# --------------------------------------------------------------------------- #

def test_the_levels_are_counted_from_the_built_projection(bom: dict):
    counted = sbom.levels(bom)
    assert counted["system"] == 1
    assert counted["repository"] == 1
    assert counted["commit"] == 1
    assert counted["component"] >= 5


def test_the_chain_walks_down_from_the_application_to_a_capability(bom: dict, names: dict):
    chain = sbom.supply_chain(bom, query=names["application"])
    assert {"repository", "commit", "artifact", "image", "deployment", "component",
            "capability"} <= set(chain["down"])


def test_the_chain_walks_up_to_the_business_system(bom: dict, names: dict):
    chain = sbom.supply_chain(bom, query=names["application"])
    assert [row["name"] for row in chain["up"]["system"]] == ["Payments System"]


def test_a_component_names_the_application_that_owns_it(bom: dict, names: dict):
    owners = sbom.component_owners(bom, query=names["component"])
    assert "Payments API" in owners["applications"]


def test_a_component_no_application_reaches_says_so(bom: dict, names: dict):
    owners = sbom.component_owners(bom, query=names["ghost"])
    assert owners["applications"] == []


def test_existence_installation_deployment_and_load_are_four_facts(bom: dict,
                                                                  names: dict):
    state = sbom.deployment_state(bom, query=names["component"])
    assert state["states"]["EXISTS"] is True
    assert state["states"]["INSTALLED"] is True
    assert state["states"]["DEPLOYED"] is True

    dev = sbom.deployment_state(bom, query=names["dev_component"])
    assert dev["states"]["INSTALLED"] is True
    assert dev["states"]["DEPLOYED"] is False
    assert dev["deployed"] is False


def test_the_six_component_states_are_read_through_the_algorithm(bom: dict, names: dict):
    states = sbom.component_states(bom, query=names["component"])
    assert {"SBOM_PRESENT", "INSTALLED", "LOADED", "CONFIGURED", "STATIC_REFERENCED",
            "RUNTIME_USED"} <= set(states["present"])


def test_a_static_hit_is_not_a_runtime_use(bom: dict, names: dict):
    states = sbom.component_states(bom, query=names["component"])
    assert "STATIC_OBSERVED" not in sbom.PROVEN_EVIDENCE
    assert states["states"]["STATIC_REFERENCED"] is True


def test_four_version_layers_are_kept_apart_and_the_conflict_is_the_finding(bom: dict,
                                                                           names: dict):
    versions = sbom.version_layers(bom, query=names["component"])
    assert versions["layers"]["DECLARED_VERSION"] == "3.0.13"
    assert versions["layers"]["RUNTIME_VERSION"] == "3.0.11"
    assert versions["conflict"] is True
    assert versions["code"] == "DEPENDENCY_VERSION_CONFLICT"
    assert versions["distinct"] == ["3.0.11", "3.0.13"]


def test_an_unknown_version_source_is_refused():
    package = tb.asset("PACKAGE", "pkg:generic/x", version="1.0", evidence_ids=[EVID_SBOM],
                       version_claims=[{"source": "vibes", "value": "1.0"}])
    doc = tb.build(n.estate(package, estate_id="version-test"))
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.version_layers(doc, query="pkg:generic/x")
    assert excinfo.value.code == "UNKNOWN_VERSION_SOURCE"


def test_provenance_names_the_repository_the_commit_the_build_and_the_sbom(bom: dict,
                                                                          names: dict):
    found = sbom.provenance(bom, artifact=names["artifact"])
    assert found["complete"] is True
    assert found["steps"]["repository"] == names["repository"]
    assert found["steps"]["commit"] == names["commit"]
    assert found["steps"]["build"] == names["build"]
    assert found["steps"]["sbom"] == names["sbom"]


def test_an_sbom_binds_to_the_artifact_digest(bom: dict, names: dict):
    identity = sbom.artifact_identity(bom, sbom=names["sbom"])
    assert identity["immutable"] is True
    assert identity["digest"] == DIGEST_ARTIFACT
    assert identity["image_digest"] == DIGEST_IMAGE


def test_an_sbom_bound_to_a_tag_is_refused(bom: dict):
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.artifact_identity(bom, sbom="SBOM-latest")
    assert excinfo.value.code == "TAG_ONLY_IDENTITY"


def test_direct_transitive_and_listed_only_are_three_answers(bom: dict, names: dict):
    tree = sbom.dependency_tree(bom, query=names["application"])
    direct = {row["component"] for row in tree["direct"]}
    transitive = {row["component"] for row in tree["transitive"]}
    listed_only = {row["component"] for row in tree["listed_only"]}
    assert direct == {names["direct"], names["build_component"]}
    assert names["transitive"] in transitive
    assert names["component"] in transitive
    assert names["orphan"] in listed_only
    assert not (direct & transitive)


def test_a_transitive_dependency_carries_the_path_that_makes_it_transitive(bom: dict,
                                                                           names: dict):
    tree = sbom.dependency_tree(bom, query=names["application"])
    openssl = next(row for row in tree["transitive"]
                   if row["component"] == names["component"])
    assert openssl["path"] == [names["direct"], names["transitive"], names["component"]]
    assert openssl["dependency_kind"] == "TRANSITIVE"


def test_every_row_of_the_tree_carries_its_evidence(bom: dict, names: dict):
    tree = sbom.dependency_tree(bom, query=names["application"])
    for kind in ("direct", "transitive", "listed_only"):
        for row in tree[kind]:
            assert row["evidence_id"], (kind, row["component"])
            assert row["basis"]


def test_the_scope_a_dependency_was_declared_in_stays_on_it(bom: dict, names: dict):
    tree = sbom.dependency_tree(bom, query=names["application"])
    build_tool = next(row for row in tree["direct"]
                      if row["component"] == names["build_component"])
    assert build_tool["scope"] == "BUILD"


def test_a_build_scope_component_that_reaches_runtime_is_flagged(bom: dict, names: dict):
    report = sbom.scope_report(bom)
    flagged = {row["component"] for row in report["build_scope_in_runtime"]}
    assert names["build_component"] in flagged
    assert names["component"] not in flagged


def test_two_names_for_one_asset_resolve_through_a_digest(bom: dict, names: dict):
    identity = sbom.canonical_identity(bom, query="payment")
    assert "payment-service-4.2.1.jar" in identity["candidates"]
    joined = identity["anchors"][f"digest:{DIGEST_ARTIFACT}"]
    assert {"payment-service-4.2.1.jar", "payments-api-4.2.1.jar", "Payments API"} \
        <= set(joined)


def test_a_name_alone_never_merges_two_assets():
    """Two applications with one name and no shared anchor stay two assets."""
    first = n.service_of(name="Payments API", kind="APPLICATION", evidence_ids=[EVID_SRC])
    second = n.service_of(name="payments-api", kind="APPLICATION", evidence_ids=[EVID_SRC])
    doc = tb.build(n.estate(first, second, estate_id="name-only"))
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.canonical_identity(doc, query="payments api")
    assert excinfo.value.code == "NAME_ONLY_IDENTITY"


def test_a_vulnerability_walks_to_the_business_system(bom: dict, names: dict):
    impact = sbom.component_impact(bom, query=names["vulnerability"])
    assert names["component"] in impact["components"]
    assert "Payments API" in impact["applications"]
    assert impact["systems"] == ["Payments System"]


def test_impact_is_asked_of_a_component_and_refused_of_anything_else(bom: dict,
                                                                    names: dict):
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.component_impact(bom, query=names["application"])
    assert excinfo.value.code == "NOT_A_COMPONENT"


def test_an_upgrade_is_counted_after_the_walk(bom: dict, names: dict):
    plan = sbom.remediation_plan(bom, query=names["component"], target_version="3.0.14",
                                 regression=["FIPS module re-validation"])
    assert plan["from_version"] == "3.0.13"
    assert plan["to_version"] == "3.0.14"
    assert plan["applications"] == ["Payments API"]
    assert plan["systems"] == ["Payments System"]
    assert names["image"] in plan["images"]
    assert plan["regression"] == ["FIPS module re-validation"]


def test_a_count_is_reported_against_what_was_inspected(bom: dict):
    coverage = sbom.sbom_coverage(bom, expected=100, inspected=75, component="http-core")
    assert coverage["coverage"] == "PARTIAL"
    assert coverage["quotable_as_total"] is False
    assert coverage["statement"].startswith("1 component(s) discovered; 75/100")
    complete = sbom.sbom_coverage(bom, expected=100, inspected=100, component="http-core")
    assert complete["quotable_as_total"] is True


def test_a_denominator_smaller_than_its_parts_is_refused(bom: dict):
    with pytest.raises(tb.ClaimRefused) as excinfo:
        sbom.sbom_coverage(bom, expected=10, inspected=9, failed=5)
    assert excinfo.value.code == "COVERAGE_EXCEEDS_EXPECTED"


# --------------------------------------------------------------------------- #
# The handoff to the CBOM
# --------------------------------------------------------------------------- #

def test_the_sbom_hands_capability_to_the_cbom(bom: dict, names: dict):
    handoff = sbom.crypto_handoff(bom, query=names["component"])
    assert handoff["count"] == 3
    assert all(row["algorithms"] for row in handoff["rows"])


def test_a_capability_alone_is_not_evidence_of_use(bom: dict, names: dict):
    handoff = sbom.crypto_handoff(bom, query=names["component"])
    verdicts = {row["capability"]: row["verdict"] for row in handoff["rows"]}
    assert verdicts["libcrypto.so.3:RSA-2048"] == "CORROBORATED"
    assert verdicts["libcrypto.so.3:AES-256-GCM"] == "CAPABILITY_ONLY"


def test_a_certificate_is_not_a_caller(bom: dict, names: dict):
    """ECDSA is on the library's list, carried by a certificate and used by nobody."""
    handoff = sbom.crypto_handoff(bom, query=names["component"])
    verdicts = {row["capability"]: row["verdict"] for row in handoff["rows"]}
    assert verdicts["libcrypto.so.3:ECDSA-P256"] == "CAPABILITY_ONLY"


def test_the_handoff_carries_the_rule_and_never_asserts_usage(bom: dict, names: dict):
    handoff = sbom.crypto_handoff(bom, query=names["component"])
    assert "capability" in handoff["rule"]
    assert set(handoff["evidence_counts"]) <= set(sbom.EVIDENCE_TYPES)
    assert set(handoff["corroborated"]) <= {"libcrypto.so.3:RSA-2048"}


def test_the_pqc_handoff_separates_capability_from_observed_use(bom: dict, names: dict):
    handoff = sbom.pqc_handoff(bom, query=names["component"])
    assert "RSA-2048" in handoff["capabilities"]
    assert handoff["observed_usage"] == ["RSA-2048"]
    assert handoff["not_proven"]


def test_component_history_keeps_both_versions_and_both_evidence_ids(built: dict,
                                                                     names: dict):
    history = sbom.component_history(built["previous"], built["bom"], detected_at=NOW)
    moved = [row for row in history["changes"] if row["component"] == names["component"]]
    assert {row["layer"] for row in moved} == {"declared"}
    assert all(row["code"] == "DEPENDENCY_CHANGED" for row in moved)
    assert all(row["evidence_before"] and row["evidence_after"] for row in moved)
    assert all(row["detected_at"] == NOW for row in moved)


def test_component_history_names_what_came_and_went(built: dict):
    history = sbom.component_history(built["previous"], built["bom"], detected_at=NOW)
    assert "libcrypto.so.1.1" in history["removed"]
    assert history["counts"]["REMOVED"] == len(history["removed"])


def test_the_same_projection_compared_with_itself_shows_nothing(built: dict):
    history = sbom.component_history(built["bom"], built["bom"], detected_at=NOW)
    assert history["changes"] == [] and history["added"] == [] and history["removed"] == []


# --------------------------------------------------------------------------- #
# The graph
# --------------------------------------------------------------------------- #

def test_the_image_anchors_its_layers_packages_and_process(bom: dict, names: dict):
    chain = sbom.image_chain(bom, query=names["image"])
    assert chain["digest"] == DIGEST_IMAGE
    assert "layer:ubuntu-22.04-base" in {row["name"] for row in chain["layers"]}
    assert names["component"] in {row["name"] for row in chain["packages"]}
    assert names["process"] in chain["processes"]


def test_kubernetes_is_reached_from_the_image(bom: dict, names: dict):
    chain = sbom.kubernetes_chain(bom, query=names["image"])
    assert "POD" in chain["kinds"] and "DEPLOYMENT" in chain["kinds"]


def test_a_host_chain_reaches_the_hardware_under_it(bom: dict, names: dict):
    chain = sbom.host_chain(bom, query=names["pod"])
    assert "srv-k8s-03" in chain["hosts"]
    assert {"CPU-01", "TPM-01"} <= set(chain["hardware"])


def test_the_chain_assembles_into_one_projection(bom: dict):
    graph = sbom.sbom_graph(bom)
    assert graph["second_store"] is False
    assert graph["supply_relations"] > 10
    assert graph["levels"]["component"] >= 5
    assert graph["statement"].endswith("one store")


def test_a_brief_row_names_its_key(bom: dict):
    """The chain readers index ``bom['by_key'][entry['key']]`` — a brief without one is a
    KeyError waiting for the first walk that uses it."""
    tree = sbom.dependency_tree(bom, query="Payments API")
    assert tree["node"]["key"] == bom["by_key"][tree["node"]["key"]]["key"]


def test_nesting_parts_does_not_ask_a_container_to_hold_the_wrong_kind(built: dict):
    """A component's part also carries its vendor product; an SBOM lists components."""
    assert built["bom"]["refusals"] == []
