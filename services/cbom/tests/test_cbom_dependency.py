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


# --------------------------------------------------------------------------- #
# Capability nodes, impact walks, lifecycle
# --------------------------------------------------------------------------- #

def capability_document() -> dict:
    application = application_row()
    process = process_row()
    library = tb.asset("CRYPTO_LIBRARY", "libcrypto.so.3", evidence_ids=[EVID])
    algorithm = rsa()
    aes = aes_algorithm()
    provider_row = tb.asset("CRYPTO_PROVIDER", "OpenSSL 3.0.11", version="3.0.11",
                            evidence_ids=[EVID_RT], family="OPENSSL")
    capabilities = [dep.capability(provider_row=provider_row, algorithm_row=row,
                                   key_size=row["attributes"].get("key_size"),
                                   evidence_ids=[EVID_RT])
                    for row in (algorithm, aes)]
    openssl = dep.provider(name="OpenSSL 3.0.11", family="OPENSSL", version="3.0.11",
                           process_row=process, provider_row=provider_row,
                           library_row=library,
                           capabilities=[row["assets"][-1] for row in capabilities],
                           evidence_ids=[EVID_RT])
    signing = dep.runtime_operation(
        name="OP-SIGN-001", process_row=process, application_row=application,
        operation="SIGN", algorithm_row=algorithm, provider_row=provider_row,
        key_size=2048, padding="PSS", hash_name="SHA-256", evidence_ids=[EVID_RT],
        observed_at=NOW, first_seen=EARLIER, last_seen=NOW)
    return n.estate(application, process, library, algorithm, aes, provider_row,
                    *capabilities, openssl, signing, estate_id="capability-estate")


def capability_estate() -> dict:
    return tb.build(capability_document())


def test_a_capability_is_a_node_between_the_provider_and_the_algorithm():
    bom = capability_estate()
    assert bom["counts"].get("CRYPTO_CAPABILITY") == 2
    implements = [claim for claim in bom["claims"] if claim["relation"] == "IMPLEMENTS"]
    assert implements
    assert {bom["by_key"][claim["from_key"]]["kind"] for claim in implements} \
        == {"CRYPTO_CAPABILITY"}


def test_capability_and_usage_compare_on_algorithms_not_on_labels():
    bom = capability_estate()
    block = dep.capability_vs_usage(bom, query="OpenSSL 3.0.11")
    assert block["capability"] == ["AES-256", "RSA-2048"]
    assert set(block["usage"]) == {"RSA-2048"}
    assert block["capability_not_used"] == ["AES-256"]
    assert len(block["capability_nodes"]) == 2


def test_a_provider_row_of_another_name_is_refused():
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.provider(name="OpenSSL 3.0.11", family="OPENSSL",
                     provider_row=tb.asset("CRYPTO_PROVIDER", "BoringSSL",
                                           evidence_ids=[EVID]),
                     evidence_ids=[EVID])
    assert excinfo.value.code == "PROVIDER_ROW_MISMATCH"


def test_a_provider_advisory_maps_to_the_operations_that_name_it():
    bom = capability_estate()
    block = dep.provider_impact(bom, query="OpenSSL 3.0.11", version="3.0.11")
    assert block["version_matches"] is True
    assert block["counts"]["operations"] == 1
    assert block["counts"]["applications"] == 1


def test_an_advisory_for_another_version_is_a_mismatch_not_an_all_clear():
    bom = capability_estate()
    block = dep.provider_impact(bom, query="OpenSSL 3.0.11", version="3.0.9")
    assert block["version_matches"] is False
    assert "MISMATCH" in block["statement"]


def test_an_advisory_against_an_algorithm_is_refused():
    bom = capability_estate()
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.provider_impact(bom, query="RSA-2048")
    assert excinfo.value.code == "NOT_A_PROVIDER"


def firmware_estate() -> dict:
    vendor = tb.asset("VENDOR", "F5", evidence_ids=[EVID])
    product = tb.asset("VENDOR_PRODUCT", "BIG-IP i5800", evidence_ids=[EVID])
    firmware = tb.asset("FIRMWARE", "BIG-IP 17.1.1", evidence_ids=[EVID], version="17.1.1")
    device = tb.asset("LOAD_BALANCER", "LB-01", evidence_ids=[EVID])
    endpoint = n.endpoint(host="10.10.0.30", port=443, name="lb-01:443", evidence_ids=[EVID])
    application = application_row()
    vulnerability = tb.asset("VULNERABILITY", "CVE-2026-0001", evidence_ids=[EVID])
    return tb.build(n.estate(
        vendor, product, firmware, device, endpoint, application, vulnerability,
        dep.vendor_chain(device_row=device, vendor_row=vendor, firmware_row=firmware,
                         product_row=product, evidence_ids=[EVID]),
        n.part(claims=[
            tb.claim("LB-01", "LISTENS_ON", "lb-01:443", basis="load-balancer-config",
                     evidence_ids=[EVID]),
            tb.claim("lb-01:443", "ROUTES_TO", "Payments API", basis="load-balancer-config",
                     evidence_ids=[EVID]),
            tb.claim("BIG-IP 17.1.1", "HAS_VULNERABILITY", "CVE-2026-0001",
                     basis="vendor-portal", evidence_ids=[EVID]),
        ]),
        estate_id="firmware-estate"))


def test_a_firmware_advisory_walks_to_the_application_behind_the_device():
    bom = firmware_estate()
    block = dep.advisory_impact(bom, query="CVE-2026-0001")
    finding = block["findings"][0]
    assert finding["firmware"] == "BIG-IP 17.1.1"
    assert "LB-01" in finding["devices"]
    assert finding["vendors"] == ["F5"]
    assert finding["applications"] == ["Payments API"]


def test_an_advisory_against_a_service_is_refused():
    bom = firmware_estate()
    with pytest.raises(tb.ClaimRefused) as excinfo:
        dep.advisory_impact(bom, query="Payments API")
    assert excinfo.value.code == "NOT_AN_ADVISORY"


def test_the_lifecycle_has_six_states_and_deletes_nothing():
    assert dep.LIFECYCLE_STATES == ("FIRST_SEEN", "ACTIVE", "CHANGED", "SUPERSEDED",
                                    "REMOVED", "UNKNOWN")
    bom = capability_estate()
    block = dep.dependency_lifecycle(bom, reference=NOW)
    assert set(block["counts"]) <= set(dep.LIFECYCLE_STATES)
    assert block["superseded"] == [] and block["removed"] == []


def test_a_replaced_dependency_is_superseded_and_the_old_row_is_kept():
    old = capability_estate()
    assert old["by_key"]["ALGORITHM:rsa-2048:production"]
    block_new = dep.dependency_lifecycle(old, previous=old, reference=NOW)
    assert block_new["counts"].get("SUPERSEDED", 0) == 0
    upgraded = _upgraded(old)
    block = dep.dependency_lifecycle(upgraded, previous=old, reference=NOW)
    assert block["counts"].get("SUPERSEDED", 0) == 1
    assert block["superseded"][0]["previous"] == "RSA-2048"
    assert block["superseded"][0]["current"] == "RSA-3072"
    assert block["superseded"][0]["evidence_before"]


def _upgraded(bom: dict) -> dict:
    estate = capability_document()
    estate["assets"] = [row for row in estate["assets"] if row["name"] != "RSA-2048"]
    estate["assets"].append(rsa(3072))
    for claim in estate["claims"]:
        if claim.get("to") == "RSA-2048":
            claim["to"] = "RSA-3072"
    return tb.build(estate)


def test_a_class_that_moved_without_the_target_moving_is_CHANGED():
    old = capability_estate()
    estate = capability_document()
    for claim in estate["claims"]:
        if claim["relation"] == "USES_ALGORITHM" and claim["confidence"] == "RUNTIME_OBSERVED":
            claim["confidence"] = "CONFIGURED"
    moved = tb.build(estate)
    block = dep.dependency_lifecycle(moved, previous=old, reference=NOW)
    assert "CHANGED" in block["counts"]


def test_the_evidence_audit_publishes_the_fields_the_estate_did_not_supply():
    bom = capability_estate()
    audit = dep.evidence_audit(bom)
    assert audit["incomplete"] == []
    assert audit["fully_recorded"] < audit["count"] or not audit["missing_fields"]
    assert set(audit["field_coverage"]) == set(dep.EDGE_FIELDS)
    assert sum(1 for value in audit["field_coverage"].values()
               if value < audit["count"]) == len(audit["missing_fields"])


def test_the_answer_to_which_systems_depend_carries_its_denominator():
    bom = capability_estate()
    block = dep.systems_depending_on(bom, algorithm="RSA-2048",
                                     coverage={"systems_total": 70,
                                               "systems_inspected": 12,
                                               "quotable_as_total": False})
    assert "12 of 70" in block["statement"]
    assert block["quotable_as_total"] is False
