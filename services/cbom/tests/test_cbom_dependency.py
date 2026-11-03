"""The CBOM dependency chain — releases, providers, operations and keys, as tests."""

from __future__ import annotations

import pytest
from cbom import cbom_dependency as dep
from cbom import nbom_graph as n
from cbom import techbom as tb

EVID = "EVID-93101"
EVID_RT = "EVID-93102"
EVID_STATIC = "EVID-93103"
NOW = "2026-11-03T08:30:00Z"
EARLIER = "2026-11-02T08:30:00Z"
OLD = "2026-10-01T08:30:00Z"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

def application_row(name: str = "Payments API") -> dict:
    return n.service_of(name=name, kind="APPLICATION", evidence_ids=[EVID])


def process_row(name: str = "payments-api[1821]") -> dict:
    return tb.asset("PROCESS", name, evidence_ids=[EVID_RT], pid=1821)


def rsa(size: int = 2048) -> dict:
    return n.algorithm(name=f"RSA-{size}", family="RSA", key_size=size,
                       evidence_ids=[EVID])


def aes_algorithm() -> dict:
    return n.algorithm(name="AES-256", family="AES", key_size=256, mode="GCM",
                       evidence_ids=[EVID_RT])


def provider_part(family: str = "OPENSSL", version: str = "3.0.11",
                  process: dict | None = None, supports: list | None = None) -> dict:
    return dep.provider(name=f"OpenSSL {version}", family=family, version=version,
                        process_row=process, supports=supports or [],
                        evidence_ids=[EVID_RT])


def chain_estate() -> dict:
    """system → application → release → process → provider → operation → algorithm."""
    system = n.service_of(name="Payments System", kind="BUSINESS_SYSTEM", evidence_ids=[EVID])
    application = application_row()
    process = process_row()
    release = tb.asset("RELEASE", "payments-api 4.2.0", evidence_ids=[EVID])
    artifact = tb.asset("ARTIFACT", "payments-api-4.2.0.jar", evidence_ids=[EVID])
    library = tb.asset("CRYPTO_LIBRARY", "libcrypto.so.3", evidence_ids=[EVID])
    algorithm = rsa()
    hsm = tb.asset("HSM", "HSM-001", evidence_ids=[EVID])
    key = n.key_reference(name="KEY-REF-4401", key_ref="pkcs11:token=bank;id=4401",
                          purpose="SIGNING", algorithm="RSA", key_size=2048,
                          holder="HSM-001", evidence_ids=[EVID])
    openssl = provider_part(process=process, supports=[algorithm])
    signing = dep.runtime_operation(
        name="OP-SIGN-001", process_row=process, application_row=application,
        operation="SIGN", algorithm_row=algorithm,
        provider_row=openssl["assets"][0], key_row=key, key_size=2048, padding="PSS",
        hash_name="SHA-256", purpose="payment signature", evidence_ids=[EVID_RT],
        observed_at=NOW)
    bound = dep.key_binding(operation_row=signing["assets"][0], key_row=key,
                            holder_row=hsm, basis="runtime-observation",
                            evidence_ids=[EVID])
    return n.estate(
        system, application, process, hsm, key, library,
        dep.application_release(application_row=application, release_row=release,
                                artifacts=[artifact], evidence_ids=[EVID]),
        openssl, signing, bound,
        n.serves(application_row=application, service_row=process, system_row=system,
                 evidence_ids=[EVID]),
        estate_id="chain-test")


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #

def test_a_release_is_a_level_between_the_application_and_its_artifact():
    application = application_row()
    release = tb.asset("RELEASE", "payments-api 4.2.0", evidence_ids=[EVID])
    artifact = tb.asset("ARTIFACT", "payments-api-4.2.0.jar", evidence_ids=[EVID])
    part = dep.application_release(application_row=application, release_row=release,
                                   artifacts=[artifact], evidence_ids=[EVID])
    relations = [claim["relation"] for claim in part["claims"]]
    assert relations == ["RELEASED_AS", "BUNDLES"]
    assert part["claims"][0]["from"] == "Payments API"


def test_a_pod_runs_containers_and_a_deployment_schedules_the_pod():
    image = tb.asset("IMAGE", "payments-api:4.2.0", evidence_ids=[EVID])
    deployment_row = tb.asset("DEPLOYMENT", "payments-api-deploy", evidence_ids=[EVID])
    pod = tb.asset("POD", "payments-api-7d9f4c", evidence_ids=[EVID])
    container = tb.asset("CONTAINER", "payments-api-ctr", evidence_ids=[EVID])
    namespace = tb.asset("NAMESPACE", "payments", evidence_ids=[EVID])
    part = dep.deployment(image_row=image, deployment_row=deployment_row, pods=[pod],
                          containers=[container], namespace_row=namespace,
                          evidence_ids=[EVID])
    relations = {claim["relation"] for claim in part["claims"]}
    assert {"DEPLOYED_AS", "SCHEDULES", "RUNS_CONTAINER", "FROM_IMAGE", "RUNS_IN"} \
        <= relations


def test_an_unknown_provider_family_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        provider_part(family="SOMETHING-ELSE")
    assert excinfo.value.code == "UNKNOWN_PROVIDER_FAMILY"


def test_a_providers_capability_is_CAPABILITY_and_its_load_is_observed():
    process = process_row()
    part = provider_part(process=process, supports=[rsa()])
    supports = [claim for claim in part["claims"] if claim["relation"] == "SUPPORTS"]
    loads = [claim for claim in part["claims"] if claim["relation"] == "LOADS"]
    assert {claim["confidence"] for claim in supports} == {"CAPABILITY"}
    assert {claim["confidence"] for claim in loads} == {"OBSERVED"}


def test_an_operation_carries_its_parameters():
    application = application_row()
    process = process_row()
    part = dep.runtime_operation(
        name="OP-SIGN-001", process_row=process, application_row=application,
        operation="SIGN", algorithm_row=rsa(), key_size=2048, padding="PSS",
        hash_name="SHA-256", purpose="signature", evidence_ids=[EVID_RT])
    attributes = part["assets"][0]["attributes"]
    assert attributes["operation"] == "SIGN"
    assert attributes["key_size"] == 2048
    assert attributes["padding"] == "PSS"
    assert attributes["hash"] == "SHA-256"


def test_a_block_cipher_without_a_mode_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.runtime_operation(name="OP-BAD", process_row=process_row(),
                              operation="ENCRYPT", algorithm_row=aes_algorithm(),
                              evidence_ids=[EVID_RT])
    assert excinfo.value.code == "BLOCK_CIPHER_WITHOUT_MODE"


def test_a_signature_without_a_size_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.runtime_operation(name="OP-BAD", process_row=process_row(), operation="SIGN",
                              algorithm_row=rsa(), evidence_ids=[EVID_RT])
    assert excinfo.value.code == "SIGNATURE_WITHOUT_SIZE"


def test_an_unknown_operation_verb_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.runtime_operation(name="OP-BAD", process_row=process_row(),
                              operation="USES_CRYPTO", algorithm_row=rsa(),
                              key_size=2048, evidence_ids=[EVID_RT])
    assert excinfo.value.code == "UNKNOWN_OPERATION"


def test_a_key_binding_needs_a_key_provider_holder():
    operation = {"name": "OP-SIGN-001", "kind": "CRYPTO_OPERATION"}
    key = n.key_reference(name="KEY-REF-4401", key_ref="pkcs11:x", purpose="SIGNING",
                          algorithm="RSA", evidence_ids=[EVID])
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.key_binding(operation_row=operation, key_row=key,
                        holder_row={"name": "KMS-01", "kind": "APPLICATION"},
                        evidence_ids=[EVID])
    assert excinfo.value.code == "NOT_A_KEY_PROVIDER"


def test_a_static_hit_is_STATIC_OBSERVED_and_names_a_file_and_a_line():
    part = dep.static_dependency(application_row=application_row(),
                                 source_file="src/main/java/bank/Legacy.java",
                                 api="Cipher.getInstance", algorithm_row=rsa(),
                                 line=214, evidence_ids=[EVID_STATIC])
    assert {claim["confidence"] for claim in part["claims"]} == {"STATIC_OBSERVED"}
    call = part["assets"][2]
    assert call["kind"] == "CRYPTO_ASSET"
    assert call["attributes"]["line"] == 214


def test_a_static_hit_claimed_as_runtime_evidence_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.static_dependency(application_row=application_row(),
                              source_file="src/main/java/bank/Legacy.java",
                              api="Cipher.getInstance", algorithm_row=rsa(),
                              basis="runtime-probe", evidence_ids=[EVID_STATIC])
    assert excinfo.value.code == "NOT_STATIC_EVIDENCE"


def test_static_evidence_does_not_enter_PROVEN():
    assert tb.STATIC_OBSERVED not in tb.PROVEN


# --------------------------------------------------------------------------- #
# The walk
# --------------------------------------------------------------------------- #

def built() -> dict:
    return tb.build(chain_estate())


def test_the_chain_reaches_every_level_from_the_application():
    bom = built()
    block = dep.chain(bom, query="Payments API")
    levels = block["down"]
    assert "release" in levels
    assert "provider" in levels
    assert "operation" in levels
    assert "algorithm" in levels
    assert "key" in levels
    assert "key_provider" in levels


def test_the_chain_walks_up_to_the_business_system():
    bom = built()
    block = dep.chain(bom, query="Payments API")
    assert [row["name"] for row in block["up"]["system"]] == ["Payments System"]


def test_the_chain_from_the_system_reaches_the_application():
    bom = built()
    block = dep.chain(bom, query="Payments System")
    assert [row["name"] for row in block["down"]["application"]] == ["Payments API"]


def test_an_unknown_query_is_refused_rather_than_guessed():
    bom = built()
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.chain(bom, query="Payments Platform")
    assert excinfo.value.code == "UNKNOWN_NODE"


def test_levels_count_every_kind_that_fills_a_level():
    bom = built()
    levels = dep.levels(bom)
    assert levels["operation"] == 1
    # the provider and the library it ships are two nodes at one level
    assert levels["provider"] == 2
    assert levels["key_provider"] == 1


# --------------------------------------------------------------------------- #
# Capability, conflict, change
# --------------------------------------------------------------------------- #

def test_capability_and_usage_are_two_sets():
    bom = built()
    block = dep.capability_vs_usage(bom, query="OpenSSL 3.0.11")
    assert block["capability"] == ["RSA-2048"]
    assert "RSA-2048" in block["usage"]
    assert block["capability_not_used"] == []


def test_a_provider_that_never_uses_a_listed_algorithm_says_so():
    process = process_row()
    unsupported = n.algorithm(name="SHA-256", family="SHA", evidence_ids=[EVID])
    openssl = provider_part(process=process, supports=[rsa(), unsupported])
    bom = tb.build(n.estate(application_row(), process, openssl, rsa(),
                            estate_id="capability-test"))
    block = dep.capability_vs_usage(bom, query="OpenSSL 3.0.11")
    assert "SHA-256" in block["capability_not_used"]


def test_a_version_disagreement_is_a_conflict_with_every_source():
    row = tb.asset("CRYPTO_PROVIDER", "OpenSSL 3.0.11", evidence_ids=[EVID],
                   version_claims=[{"source": "sbom", "value": "3.0.11"},
                                   {"source": "process-map", "value": "3.0.13"}])
    bom = tb.build(n.estate(row, estate_id="conflict-test"))
    block = dep.dependency_conflicts(bom)
    assert block["counts"]["VERSION"] == 1
    assert len(block["findings"][0]["sources"]) == 2
    assert block["findings"][0]["values"] == ["3.0.11", "3.0.13"]


def test_a_change_keeps_the_evidence_on_both_sides():
    old = tb.build(chain_estate())
    new_estate = chain_estate()
    new_estate["assets"] = [row for row in new_estate["assets"]
                            if row["name"] != "RSA-2048"]
    new_estate["assets"].append(rsa(3072))
    for claim in new_estate["claims"]:
        if claim.get("to") == "RSA-2048":
            claim["to"] = "RSA-3072"
    changed = tb.build(new_estate)
    block = dep.dependency_changes(old, changed, detected_at=NOW)
    change = block["changes"][0]
    assert change["code"] == "CRYPTO_DEPENDENCY_CHANGED"
    assert change["previous"] == "RSA-2048"
    assert change["current"] == "RSA-3072"
    assert change["evidence_before"] and change["evidence_after"]
    assert change["detected_at"] == NOW


def test_comparing_an_estate_with_itself_finds_nothing():
    bom = built()
    assert dep.dependency_changes(bom, bom)["counts"]["CHANGED"] == 0


# --------------------------------------------------------------------------- #
# KMS, hops, PQC, evidence
# --------------------------------------------------------------------------- #

def test_the_four_kms_states_are_distinct():
    states = {dep.kms_state(basis=basis) for basis in
              ("vendor-datasheet", "config-parse", "agent-inventory", "runtime-probe")}
    assert states == {"SUPPORTED", "CONFIGURED", "REFERENCED", "ACTUALLY_USED"}


def test_a_kms_answer_is_the_strongest_thing_the_estate_says():
    application = application_row()
    kms = tb.asset("KMS", "KMS-01", evidence_ids=[EVID])
    bom = tb.build(n.estate(application, kms,
                            n.part(claims=[tb.claim("Payments API", "USES_KMS", "KMS-01",
                                                    basis="api-poll",
                                                    evidence_ids=[EVID])]),
                            estate_id="kms-test"))
    block = dep.kms_evidence(bom, query="KMS-01")
    assert block["state"] == "CONFIGURED"
    assert "ACTUALLY_USED" not in block["states_present"]


def test_a_kms_answer_about_something_that_is_not_a_key_provider_is_refused():
    bom = built()
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.kms_evidence(bom, query="Payments API")
    assert excinfo.value.code == "NOT_A_KEY_PROVIDER"


def test_hops_are_numbered_in_order_and_carry_their_own_class():
    front = n.endpoint(host="10.10.0.10", port=443, name="edge:443",
                       tls={"version": "TLS1.3", "suite": "TLS_AES_256_GCM_SHA384"},
                       evidence_ids=[EVID])
    back = n.endpoint(host="10.10.0.30", port=443, name="lb:443",
                      tls={"version": "TLS1.2", "suite": "ECDHE-RSA-AES128-GCM-SHA256"},
                      evidence_ids=[EVID])
    bom = tb.build(n.estate(front, back, n.part(claims=[
        tb.claim("edge:443", "FORWARDS_TO", "lb:443", basis="dns-resolution",
                 evidence_ids=[EVID])]),
        estate_id="hop-test"))
    block = dep.endpoint_hops(bom, query="edge:443")
    assert [row["hop"] for row in block["hops"]] == [1]
    assert block["hops"][0]["class"] == "CONFIGURED"


def test_a_hop_without_its_facts_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.crypto_hops([{"source": "client"}])
    assert excinfo.value.code == "HOP_WITHOUT_FACTS"


def test_the_pqc_blocker_is_the_path_and_names_each_hop():
    bom = built()
    block = dep.pqc_blockers(bom, query="RSA-2048")
    assert block["sensitive"] is True
    assert "HSM" in block["kinds"]
    assert "KEY_REFERENCE" in block["kinds"]
    assert block["blockers"][0]["kind"] == "ALGORITHM"


def test_every_dependency_edge_carries_its_record():
    bom = built()
    block = dep.evidence_audit(bom)
    assert block["incomplete"] == []
    assert block["count"] >= 10


def test_which_systems_depend_on_an_algorithm_is_a_walk():
    bom = built()
    block = dep.systems_depending_on(bom, algorithm="RSA-2048")
    assert block["systems"] == ["Payments System"]
    assert block["applications"][0]["path"][0] == "Payments API"
