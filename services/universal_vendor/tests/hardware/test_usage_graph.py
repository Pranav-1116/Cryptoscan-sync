"""The usage graph: who uses which HSM, and what it can do — with evidence.

The two failure modes this file is written against are opposite and equally
common in CMDB-shaped tools: an edge nobody can evidence, and a *missing* edge
that gets papered over. The first is refused by construction; the second is
reported as UNRESOLVED or AMBIGUOUS rather than silently dropped, because "this
application depends on something the estate has not discovered" is a finding.
"""

from __future__ import annotations

import pytest

from universal_vendor.hardware.relationships import (
    Evidence,
    HardwareEdge,
    UnevidencedRelationship,
    derive_edges,
)
from universal_vendor.hardware.usage_graph import (
    AMBIGUOUS,
    UNRESOLVED,
    CapabilitySupport,
    UsageEdge,
    UsageGraph,
    UsageRejected,
    algorithm_family,
    build_graph,
    capabilities_from_observation,
    is_pqc,
    resolve_usage,
)

PKCS11_CONFIG = """
crypto:
  provider: pkcs11
  pkcs11:
    module: /usr/lib/libCryptoki2_64.so
    token:
      label: PAYMENTS01
      slot: 1
"""

KMIP_CONFIG = """
hsm:
  kmip:
    host: hsm-cluster-01
    port: 5696
"""

HSM_OBSERVATION = {
    "manufacturer": "Thales", "model": "Luna K7", "firmware": "7.8.2",
    "supported_algorithms": ["RSA-3072", "ECDSA-P256", "AES-256"],
    "pqc_algorithms": ["ML-DSA-65", "ML-KEM-768"],
}


def graph(applications=(("Payment API", "apps/payment/config.yml", PKCS11_CONFIG),),
          hardware=("PAYMENTS01", "hsm-cluster-01"),
          observations=None):
    return build_graph(
        applications=list(applications),
        hardware={name: HSM_OBSERVATION for name in hardware},
        observations=observations if observations is not None else
        {"PAYMENTS01": HSM_OBSERVATION},
        observation_reference=lambda name: f"observed:hsm/{name}/firmware",
    )


# -- evidence or nothing ---------------------------------------------------- #


def test_a_pkcs11_config_names_both_ends_and_that_is_the_edge():
    built = graph()
    used = built.used_by("PAYMENTS01")
    assert [item["application"] for item in used] == ["Payment API"]
    assert used[0]["confidence"] == "HIGH"
    assert used[0]["evidence_ids"]

    evidence = built.to_dict()["usage"][0]["evidence"][0]
    assert evidence["kind"] == "CONFIG"
    assert evidence["reference"].startswith("apps/payment/config.yml#PKCS#11:PAYMENTS01")
    assert evidence["evidence_id"].startswith("EV-")


def test_an_application_that_merely_exists_produces_no_edge():
    assert derive_edges("Payment API") == []
    built = build_graph(applications=[("Payment API", "apps/payment/config.yml",
                                       "server:\n  port: 8443\n")],
                        hardware={"PAYMENTS01": HSM_OBSERVATION})
    assert built.used_by("PAYMENTS01") == []
    assert built.to_dict()["resolved"] == 0


def test_a_slot_number_is_not_an_appliance():
    text = "pkcs11:\n  module: /usr/lib/libCryptoki2.so\n  slot: 1\n"
    assert derive_edges("Payment API", config_text=text,
                        config_reference="apps/payment/config.yml") == []


def test_a_config_that_names_an_undiscovered_label_is_unresolved_not_dropped():
    built = graph(hardware=("SOME-OTHER-HSM",))
    unresolved = built.unresolved()
    assert [item["resolution"] for item in unresolved] == [UNRESOLVED]
    assert unresolved[0]["subject"] == "Payment API"
    assert unresolved[0]["hardware"] == "PAYMENTS01"
    # and it is not counted as usage of an appliance that was not named
    assert built.used_by("SOME-OTHER-HSM") == []


def test_a_label_two_appliances_claim_is_ambiguous_and_refused():
    """Two appliances can carry one token label. That is not evidence for either."""
    edges = derive_edges("Payment API", config_text=PKCS11_CONFIG,
                         config_reference="apps/payment/config.yml")
    resolved = resolve_usage(edges, ["HSM-01", "HSM-02"],
                             labels={"PAYMENTS01": ["HSM-01", "HSM-02"]})
    assert resolved[0].resolution == AMBIGUOUS
    assert resolved[0].candidates == ("HSM-01", "HSM-02")
    built = UsageGraph()
    built.add_edges(resolved)
    assert built.used_by("HSM-01") == [], "an ambiguous claim is not evidence"
    assert built.used_by("HSM-02") == []
    assert built.to_dict()["ambiguous"] == 1


def test_a_label_that_names_one_appliance_resolves_to_the_asset_id():
    edges = derive_edges("Payment API", config_text=PKCS11_CONFIG,
                         config_reference="apps/payment/config.yml")
    resolved = resolve_usage(edges, ["HSM-01"], labels={"PAYMENTS01": ["HSM-01"]})
    assert resolved[0].resolution == "RESOLVED"
    assert resolved[0].hardware_id == "HSM-01"
    built = UsageGraph()
    built.add_edges(resolved)
    assert [item["application"] for item in built.used_by("HSM-01")] == ["Payment API"]
    assert built.used_by("HSM-01")[0]["named_in_config_as"] == "PAYMENTS01"


def test_an_ambiguous_usage_cannot_be_declared_with_one_candidate():
    edge = derive_edges("Payment API", config_text=PKCS11_CONFIG,
                        config_reference="apps/payment/config.yml")[0]
    with pytest.raises(UsageRejected):
        UsageEdge(edge, AMBIGUOUS, ("PAYMENTS01",))


def test_the_same_pair_from_two_sources_is_one_edge_with_two_citations():
    edges = derive_edges("Payment API", config_text=PKCS11_CONFIG,
                         config_reference="apps/payment/config.yml",
                         declared=["PAYMENTS01"])
    assert len(edges) == 1
    assert len(edges[0].evidence) == 2
    # The weaker citation governs: a CMDB row cannot make a config-proven edge
    # stronger than it is, and it must not make it weaker than the config is.
    assert edges[0].confidence == "MEDIUM"


# -- what the appliance can do --------------------------------------------- #


def test_supported_algorithms_become_supports_links_with_the_observation_as_evidence():
    built = graph()
    capabilities = built.supports("PAYMENTS01")
    names = [item["algorithm"] for item in capabilities]
    assert names == ["RSA-3072", "ECDSA-P256", "AES-256", "ML-DSA-65", "ML-KEM-768"]
    assert all(item["kind"] == "SUPPORTS" for item in capabilities)
    assert next(item for item in capabilities if item["algorithm"] == "ML-DSA-65")["pqc"] is True
    assert all(item["evidence"][0]["reference"].startswith("observed:") for item in capabilities)


def test_an_algorithm_listed_twice_is_one_capability():
    observation = {**HSM_OBSERVATION,
                   "pqc_algorithms": ["ML-DSA-65"], "supported_algorithms": ["ML-DSA-65"]}
    capabilities = capabilities_from_observation(
        "PAYMENTS01", observation, reference="observed:hsm/PAYMENTS01")
    assert [item.algorithm for item in capabilities] == ["ML-DSA-65"]


def test_an_appliance_that_lists_no_algorithms_claims_none():
    assert capabilities_from_observation("PAYMENTS01", {"model": "K7"},
                                         reference="observed:x") == []


def test_a_capability_without_evidence_cannot_be_constructed():
    with pytest.raises(UnevidencedRelationship):
        CapabilitySupport(hardware="PAYMENTS01", algorithm="RSA-3072", evidence=())
    with pytest.raises(UsageRejected):
        CapabilitySupport(hardware="PAYMENTS01", algorithm="  ",
                          evidence=(Evidence("CONFIG", "apps/x.yml#token"),))


def test_algorithm_families_are_classified_not_allowlisted():
    assert algorithm_family("RSA-3072") == "RSA"
    assert algorithm_family("ECDSA-P256") == "ECDSA"
    assert algorithm_family("AES-256-GCM") == "AES"
    assert is_pqc("ML-KEM-768") and is_pqc("SLH-DSA-SHA2-128s")
    assert is_pqc("ML-DSA-87") is True
    # An algorithm this module has never heard of is still reported, as "other".
    assert algorithm_family("BLOWFISH-448") == "other"
    assert is_pqc("BLOWFISH-448") is False


# -- the two views ---------------------------------------------------------- #


def test_used_by_and_supports_answer_different_questions():
    built = graph()
    assert [item["application"] for item in built.used_by("PAYMENTS01")] == ["Payment API"]
    assert len(built.supports("PAYMENTS01")) == 5
    assert built.of_application("Payment API")[0]["kind"] == "USES_HSM"


def test_the_graph_reports_its_own_shape():
    payload = graph().to_dict()
    assert payload["schema"] == "cryptoscan.hardware-usage-graph/1"
    assert payload["resolved"] == 1 and payload["unresolved"] == 0
    assert payload["hardware"] == ["PAYMENTS01", "hsm-cluster-01"]


def test_a_kmip_config_names_the_cluster_and_lands_as_its_own_edge():
    built = graph(applications=[("Card Authorization", "apps/cards/hsm.yml", KMIP_CONFIG)])
    assert [item["application"] for item in built.used_by("hsm-cluster-01")] == [
        "Card Authorization"]


def test_an_evidence_reference_may_not_carry_a_secret():
    with pytest.raises(UnevidencedRelationship):
        Evidence("CONFIG", "apps/payment/config.yml#pin=1234")


def test_usage_edges_are_hardware_edges_so_blast_radius_can_walk_them():
    built = graph()
    edge = built.edges[0].edge
    assert isinstance(edge, HardwareEdge) and edge.kind == "USES_HSM"
