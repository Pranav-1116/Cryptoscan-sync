"""The estate measured against what the bank says should be there.

Spec 94 §4 draws the coverage table with a denominator — *Servers 118/120, HSMs 7/8* —
and §11 asks for accuracy "separately for asset discovery, cryptographic identification,
relationships, key sizes, certificates, ownership and other claim types". Neither could
be produced before: every coverage number the platform had was attempted/expected **per
collector**, which is a fact about a collector run and not about the estate.

These tests pin the two things that are easy to get wrong and expensive to get wrong: a
denominator must never be invented, and the absence of a claim is not evidence of a
disagreement.
"""

import pytest

from shared_models import estate_ground_truth as gt
from shared_models.estate_graph import build_graph
from test_estate_twin import _payload


@pytest.fixture()
def graph():
    return build_graph(_payload())


DECLARATION = {
    "declared_by": "bank/inventory-2026Q4",
    "declared_at": "2026-11-01T00:00:00Z",
    "basis": "BANK_INVENTORY_DECLARATION",
    "asset_population": {
        "SYSTEM": 1,
        "APPLICATION": 2,
        "HOST": 1,
        "HSM": 2,
        "DATABASE": 1,
        "LOAD_BALANCER": 1,
    },
    "claims": [
        {"claim_id": "c1", "type": "ASSET_PRESENCE", "asset": "Payment API"},
        {"claim_id": "c2", "type": "RELATIONSHIP", "subject": "Payment API", "predicate": "depends_on",
         "object": "PostgreSQL"},
        {"claim_id": "c3", "type": "ALGORITHM_USE", "asset": "Payment API", "algorithm": "AES-256-GCM"},
        {"claim_id": "c4", "type": "OWNERSHIP", "asset": "Payment API", "owner": "Payments Platform"},
    ],
}


def _claims(result):
    return {item["claim_id"]: item for item in result["claims"]["results"]}


# -- the denominator --------------------------------------------------------- #


def test_a_declared_population_is_measured_against_the_estate_not_invented(graph):
    result = gt.measure(graph, DECLARATION)

    rows = {row["asset_type"]: row for row in result["population"]["rows"]}
    assert rows["APPLICATION"]["declared"] == 2
    assert rows["APPLICATION"]["status"] == "COMPLETE"
    # HSM is declared twice and the estate holds one: PARTIAL, and 50% is a real ratio
    assert rows["HSM"]["status"] == "PARTIAL"
    assert rows["HSM"]["collected_percent"] == 50.0
    assert result["population"]["classes_with_a_denominator"] == len(DECLARATION["asset_population"])


def test_finding_more_than_was_declared_is_a_disagreement_not_a_percentage(graph):
    declaration = {**DECLARATION, "asset_population": {"APPLICATION": 1}}
    result = gt.measure(graph, declaration)

    row = next(r for r in result["population"]["rows"] if r["asset_type"] == "APPLICATION")
    assert row["status"] == "OVER_DECLARED"
    assert row["collected"] == 2
    # no percentage: the denominator was exceeded, so a ratio would restate it as a pass
    assert row["collected_percent"] is None
    assert "identity resolution" in row["note"]
    assert row in result["population"]["disagreements"]


def test_a_declared_class_the_estate_cannot_see_is_a_collection_gap_not_coverage(graph):
    declaration = {**DECLARATION, "asset_population": {"KMS_KEY": 4}}
    result = gt.measure(graph, declaration)

    row = next(r for r in result["population"]["rows"] if r["asset_type"] == "KMS_KEY")
    assert row["status"] == "EMPTY"
    assert row["collected_percent"] == 0.0
    assert "collection gap, not an empty estate" in row["note"]


def test_a_class_with_no_denominator_prints_no_percentage(graph):
    declaration = {**DECLARATION, "asset_population": {"APPLICATION": 2}}
    result = gt.measure(graph, declaration)

    row = next(r for r in result["population"]["rows"] if r["asset_type"] == "LIBRARY")
    assert row["status"] == "NOT_DECLARED"
    assert row["declared"] is None
    assert row["collected_percent"] is None
    assert result["population"]["classes_not_declared"] >= 1


def test_unevidenced_assets_are_counted_beside_the_population(graph):
    result = gt.measure(graph, DECLARATION)

    row = next(r for r in result["population"]["rows"] if r["asset_type"] == "APPLICATION")
    assert row["evidenced"] >= 1
    assert row["unevidenced"] == row["collected"] - row["evidenced"]


# -- the claims -------------------------------------------------------------- #


def test_a_claim_the_estate_agrees_with_is_matched_and_cites_its_evidence(graph):
    claims = _claims(gt.measure(graph, DECLARATION))

    assert claims["c1"]["verdict"] == "MATCHED"
    assert claims["c1"]["evidence"]
    assert "APPLICATION" in claims["c1"]["reason"]


def test_a_relationship_the_estate_holds_is_matched(graph):
    claims = _claims(gt.measure(graph, DECLARATION))

    assert claims["c2"]["verdict"] == "MATCHED"
    assert claims["c2"]["evidence"][0]["predicate"] == "depends_on"


def test_a_relationship_the_estate_does_not_hold_is_missing_never_denied(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "RELATIONSHIP", "subject": "Payment API",
         "predicate": "uses_hsm", "object": "PostgreSQL"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "MISSING_FROM_ESTATE"
    assert "never a statement that the two are unrelated" in claim["reason"]


def test_a_refusal_of_a_different_predicate_does_not_contradict_this_claim(graph):
    """The graph refuses `uses` between these two; that is not a finding about `uses_hsm`."""
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "RELATIONSHIP", "subject": "Payment API",
         "predicate": "uses_hsm", "object": "PostgreSQL"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "MISSING_FROM_ESTATE"
    assert "refused for its own reason" in claim["reason"]


def test_a_relationship_the_graph_refused_is_contradicted_with_the_reason(graph):
    """`uses` on imported basis cannot be established — and the refusal is the finding."""
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "RELATIONSHIP", "subject": "Payment API",
         "predicate": "uses", "object": "PostgreSQL"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "CONTRADICTED"
    assert "refused" in claim["reason"]
    assert claim["evidence"][0]["reason"]


def test_a_relationship_with_one_end_absent_cannot_be_judged_at_all(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "RELATIONSHIP", "subject": "Mainframe LPAR-7",
         "predicate": "connects_to", "object": "Payment API"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "MISSING_FROM_ESTATE"
    assert "cannot be confirmed or denied" in claim["reason"]


def test_an_asset_the_estate_does_not_hold_is_missing_without_guessing_why(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "ASSET_PRESENCE", "asset": "mainframe-lpar-7"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "MISSING_FROM_ESTATE"
    assert "collection gap or a declaration that has moved on" in claim["reason"]
    assert "does not guess" in claim["reason"]


def test_a_capability_list_does_not_satisfy_a_claim_about_use(graph):
    """§8's state table: OpenSSL supporting RSA is not the application using RSA."""
    payload = _payload()
    payload["evidence"] = [*payload["evidence"], {
        "evidence_id": "ev-lib", "source": "static", "collector": "static",
        "evidence_type": "STATIC_OBSERVED", "target": "ossl", "layer": "APPLICATION",
        "facts": {"name": "OpenSSL", "version": "3.0.13", "supported_algorithms": ["RSA", "AES-256"]},
    }]
    graph = build_graph(payload)
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "ALGORITHM_USE", "asset": "OpenSSL", "algorithm": "RSA"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "CONTRADICTED"
    assert "capability the asset supports" in claim["reason"]
    # and the reason names the rule, so an operator can check the rule
    assert "§8" in claim["reason"]


def test_a_key_size_the_estate_never_recorded_is_not_checkable_not_wrong(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "KEY_SIZE", "asset": "Payment API",
         "algorithm": "AES-256-GCM", "key_size": 256},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "NOT_CHECKABLE"
    assert "no evidence states a key size" in claim["reason"]
    assert "'no key size recorded' is not 'the declared key size is right'" in claim["reason"]


def test_a_key_size_the_estate_contradicts_is_a_disagreement(graph):
    payload = _payload()
    payload["evidence"] = [*payload["evidence"], {
        "evidence_id": "ev-rsa", "source": "pki", "collector": "pki",
        "evidence_type": "CERTIFICATE_OBSERVED", "target": "pg", "layer": "STORAGE",
        "facts": {"algorithm": "RSA", "key_size": 4096},
    }]
    graph = build_graph(payload)
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "KEY_SIZE", "asset": "PostgreSQL", "algorithm": "RSA", "key_size": 2048},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "CONTRADICTED"
    assert "[4096]" in claim["reason"]


def test_ownership_the_estate_states_differently_is_a_contradiction(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "OWNERSHIP", "asset": "Payment API", "owner": "Payments Team"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "CONTRADICTED"
    assert "Payments Platform" in claim["reason"] and "Payments Team" in claim["reason"]


def test_an_asset_with_no_recorded_owner_is_a_ownership_collection_gap(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "OWNERSHIP", "asset": "OpenSSL", "owner": "Payments Platform"},
    ]}
    claim = _claims(gt.measure(graph, declaration))["x"]

    assert claim["verdict"] == "NOT_CHECKABLE"
    assert "no source states an owner" in claim["reason"]


def test_a_claim_type_this_build_cannot_check_is_reported_not_skipped(graph):
    declaration = {**DECLARATION, "claims": [
        {"claim_id": "x", "type": "PAYMENT_AUTHORISATION", "asset": "Payment API"},
    ]}
    result = gt.measure(graph, declaration)

    claim = _claims(result)["x"]
    assert claim["verdict"] == "NOT_CHECKABLE"
    assert "expected one of" in claim["reason"]
    assert result["claims"]["unmeasurable_types"]


# -- what the measurement refuses to say ------------------------------------- #


def test_the_measurement_reports_agreement_not_precision_and_says_why(graph):
    result = gt.measure(graph, DECLARATION)

    by_type = result["claims"]["by_type"]
    assert by_type["ASSET_PRESENCE"]["basis"] == "DECLARED_SAMPLE_ONLY"
    assert by_type["ASSET_PRESENCE"]["agreement_rate"] == 1.0
    assert "precision is not reported" in result["claims"]["meaning"].lower()
    assert "not having declared an asset is not evidence" in result["claims"]["meaning"]


def test_every_claim_type_is_measured_separately(graph):
    result = gt.measure(graph, DECLARATION)

    assert set(result["claims"]["by_type"]) == set(gt.CLAIM_TYPES)
    # a type with no claims is still reported, with a null rate rather than 0%
    assert result["claims"]["by_type"]["CERTIFICATE"]["declared"] == 0
    assert result["claims"]["by_type"]["CERTIFICATE"]["agreement_rate"] is None


def test_an_unattributed_declaration_is_refused_rather_than_measured(graph):
    result = gt.measure(graph, {"asset_population": {"APPLICATION": 2}})

    assert result["status"] == "INVALID_DECLARATION"
    assert "declared_by" in result["detail"]
    assert result["live_state_modified"] is False


def test_a_declaration_naming_no_numeric_count_has_no_denominator(graph):
    result = gt.measure(graph, {**DECLARATION, "asset_population": {"APPLICATION": "a lot"}})

    row = next(r for r in result["population"]["rows"] if r["asset_type"] == "APPLICATION")
    assert row["status"] == "NOT_DECLARED"
    assert "not a number" in row["note"]


def test_a_malformed_claim_is_counted_rather_than_dropped(graph):
    result = gt.measure(graph, {**DECLARATION, "claims": ["not-a-claim", {"type": "ASSET_PRESENCE"}]})

    assert result["counts"]["claims_malformed"] == 1
    assert result["counts"]["claims_declared"] == 1


def test_measuring_edits_nothing(graph):
    before = graph.fingerprint()
    result = gt.measure(graph, DECLARATION)

    assert result["live_state_modified"] is False
    assert result["projection_id"] == before
    assert graph.fingerprint() == before
    # the limits say what the number is not, in the response rather than in a document
    assert any("measures the declaration, not the world" in limit for limit in result["limits"])
