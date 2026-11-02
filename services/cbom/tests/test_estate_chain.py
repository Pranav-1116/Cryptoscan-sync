"""The whole chain over one estate: the failures live at the seams.

Each layer has its own tests. These run every layer together over one estate
description and check the invariants that hold *between* them — a capability that
never becomes a document asset, a conflict that survives to the graph, a disabled
key that never reads as runtime evidence, a document that carries its own coverage.

The estate fixture is deliberately mixed: runtime evidence for one algorithm, an
SBOM-only capability for two others, an enabled key, a disabled key with a
recorded operation, a TLS endpoint, a static finding, and a version disagreement.
"""

from __future__ import annotations

import copy

from cbom import coverage_render as cr
from cbom import estate_chain as ec
from cbom import promotion as promo

OP = {
    "application": "payments-api", "pid": 9182, "provider": "OpenSSL",
    "provider_version": "3.0.11", "operation": "EVP_EncryptInit_ex",
    "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
    "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-1",
}

ESTATE = {
    "name": "bank-estate-2026-11",
    "as_of": "2026-11-02",
    "components": [{
        "name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
        "algorithms": ["AES-256-GCM", "RSA-2048", "AES-128-CBC"],
    }],
    "declared_versions": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1"}],
    "operations": [OP],
    "keys": [
        {"key_ref": "arn:aws:kms:eu:1:key/abc", "algorithm": "RSA", "key_size": 2048,
         "provider": "AWS_KMS", "status": "ENABLED", "created_at": "2025-01-01",
         "evidence_id": "KMS-1"},
        {"key_ref": "arn:aws:kms:eu:1:key/old", "algorithm": "AES", "key_size": 256,
         "provider": "AWS_KMS", "status": "DISABLED", "created_at": "2024-01-01",
         "evidence_id": "KMS-2"},
    ],
    "key_uses": [
        {"key_ref": "arn:aws:kms:eu:1:key/abc", "operation": "decrypt",
         "evidence_id": "KMS-USE-1", "observed_at": "2026-11-01"},
        {"key_ref": "arn:aws:kms:eu:1:key/old", "operation": "decrypt",
         "evidence_id": "KMS-USE-2", "observed_at": "2026-11-01"},
    ],
    "probes": [{"endpoint": "payments.bank.example:443", "status": "COMPLETED",
                "crypto": {"tls_version": "1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                "evidence_id": "NET-1", "observed_at": "2026-11-02T00:00:00Z"}],
    "findings": [{"algorithm": "AES-128-CBC", "file": "legacy.java", "line": 12,
                  "evidence_id": "STATIC-1"}],
    # Two kinds of disagreement, deliberately handled by two different mechanisms:
    # an SBOM declaration against a runtime observation is a version *mismatch* for
    # the process tracer, while two observing layers that disagree on the same fact
    # are a usage-evidence *conflict* that must survive to the graph.
    "conflicts": [
        {"field": "version", "fact": "3.0.13", "source": "sbom", "evidence_id": "SBOM-1"},
        {"field": "version", "fact": "3.0.11", "source": "runtime",
         "evidence_id": "RUNTIME-1"},
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "network",
         "evidence_id": "NET-1"},
        {"field": "cipher_suite", "fact": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "source": "runtime", "evidence_id": "RUNTIME-2"},
    ],
    "coverage": {
        "rollup": {"systems": 100, "with_cbom": 62,
                   "counts": {"CURRENT": 50, "STALE": 12, "NEVER_SCANNED": 25,
                              "FAILED": 8, "NO_TARGET": 5}},
        "files_scanned": 900,
    },
}


def _estate(**overrides):
    estate = copy.deepcopy(ESTATE)
    for key, value in overrides.items():
        if value is None:
            estate.pop(key, None)
        else:
            estate[key] = value
    return estate


def _running():
    return ec.run(_estate())


# --------------------------------------------------------------------------- #
# the shape of the answer


def test_the_chain_returns_every_layer_and_the_checks():
    result = _running()
    assert result["schema"] == ec.SCHEMA
    for layer in ("runtime", "keys", "evidence", "profiles", "promotion", "document",
                  "empty", "handoff", "conflicts", "graph", "coverage", "checks"):
        assert layer in result, layer


def test_every_check_in_the_contract_is_reported_once_and_in_order():
    result = _running()
    assert tuple(check["check"] for check in result["checks"]) == ec.CHECKS
    assert len(set(ec.CHECKS)) == len(ec.CHECKS)


def test_a_non_object_estate_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        ec.run(["not", "an", "estate"])


def test_an_estate_without_a_name_still_gets_an_identity():
    result = ec.run({"components": []})
    assert result["estate"] == "cryptoscan-estate"


# --------------------------------------------------------------------------- #
# invariant 1: no capability is documented as usage


def test_a_capability_only_estate_documents_nothing():
    result = ec.run({"name": "capabilities-only", "components": [
        {"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
         "algorithms": ["AES-256-GCM", "RSA-2048"]}]})
    assert result["document"]["components"] == []
    assert {candidate["algorithm"] for candidate in result["promotion"]["candidates"]} == {
        "AES-256-GCM", "RSA-2048"}


def test_a_capability_only_component_never_appears_in_the_document():
    result = _running()
    documented = {component["name"] for component in result["document"]["components"]}
    assert "AES-256-GCM" in documented
    assert "RSA-2048" not in documented
    assert "AES-128-CBC" not in documented


def test_every_documented_asset_reads_as_observed():
    result = _running()
    for component in result["document"]["components"]:
        properties = {row["name"]: row["value"] for row in component["properties"]}
        assert properties["cryptoscan:usage"] == "OBSERVED"


# --------------------------------------------------------------------------- #
# invariant 2: every documented asset is attributable


def test_every_documented_asset_carries_an_evidence_id():
    result = _running()
    for component in result["document"]["components"]:
        ids = [row["value"] for row in component["properties"]
               if row["name"] == "cryptoscan:evidence_id"]
        assert ids, component["name"]


def test_an_observation_without_an_evidence_id_is_refused_not_documented():
    result = ec.run(_estate(operations=[{**OP, "evidence_id": None}]))
    assert result["document"]["components"] == []
    assert result["evidence"]["refused"]


# --------------------------------------------------------------------------- #
# invariant 3: the promotion level matches the evidence


def test_the_promotion_level_is_recomputed_from_the_classes():
    result = _running()
    for asset in result["promotion"]["assets"]:
        assert asset["promotion_level"] == promo.promotion_level(
            asset["profile"]["observed_classes"])


def test_runtime_evidence_alone_never_reads_as_verified():
    result = _running()
    level = {asset["algorithm"]: asset["promotion_level"]
             for asset in result["promotion"]["assets"]}["AES-256-GCM"]
    assert level == "RUNTIME"


# --------------------------------------------------------------------------- #
# invariant 4: conflicts survive to the graph


def test_two_observing_layers_that_disagree_are_a_conflict_and_an_edge():
    result = _running()
    conflicts = result["conflicts"]["reconciled"]["conflicts"]
    assert [conflict["field"] for conflict in conflicts] == ["cipher_suite"]
    assert conflicts[0]["kind"] == "FACT_CONFLICT"
    assert result["conflicts"]["edges"]


def test_a_conflict_is_never_resolved_to_a_single_value():
    result = _running()
    resolved = [row for row in result["conflicts"]["reconciled"]["resolved"]
                if row["field"] == "cipher_suite"]
    assert resolved and all(row["value"] is None for row in resolved)


def test_a_declaration_against_an_observation_is_not_a_conflict():
    result = _running()
    assert all(conflict["field"] != "version"
               for conflict in result["conflicts"]["reconciled"]["conflicts"])


def test_the_version_mismatch_is_reported_by_the_process_tracer_instead():
    result = _running()
    kinds = {row["state"] for row in result["runtime"]["correlation"]}
    assert "VERSION_MISMATCH" in kinds


def test_every_claim_survives_as_a_row():
    result = _running()
    assert len(result["conflicts"]["reconciled"]["rows"]) == 4
    assert result["conflicts"]["reconciled"]["refused"] == []


def test_agreement_is_not_a_conflict():
    result = ec.run(_estate(conflicts=[
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "network",
         "evidence_id": "NET-1"},
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "runtime",
         "evidence_id": "RUNTIME-2"}]))
    assert result["conflicts"]["reconciled"]["conflicts"] == []
    assert result["conflicts"]["edges"] == []


# --------------------------------------------------------------------------- #
# invariant 5: a disabled key never produces runtime evidence


def test_the_key_layer_reports_the_operation_and_the_chain_refuses_it():
    result = _running()
    # the key layer reports both recorded operations, because a decrypt against a
    # disabled key is a fact worth seeing; only one of them may become evidence
    assert result["keys"]["events"]["operated"] == 2
    assert result["keys"]["events"]["configured"] == 1
    assert len(result["evidence"]["suppressed"]) == 1


def test_a_recorded_operation_on_a_disabled_key_is_suppressed_with_a_reason():
    result = _running()
    assert [row["key_ref"] for row in result["evidence"]["suppressed"]] == [
        "arn:aws:kms:eu:1:key/old"]
    assert "DISABLED" in result["evidence"]["suppressed"][0]["reason"]


def test_a_suppressed_key_operation_is_carried_as_a_refusal():
    result = _running()
    reasons = [row.get("reason", "") for row in result["evidence"]["refused"]]
    assert any("DISABLED" in reason for reason in reasons)


def test_no_evidence_event_mentions_the_disabled_key():
    result = _running()
    assert all(event.get("key_ref") != "arn:aws:kms:eu:1:key/old"
               for event in result["evidence"]["events"])


def test_the_check_has_teeth_a_leaked_event_fails_it():
    records = [{"key_ref": "k/old", "usable": False, "status": "DISABLED"}]
    leaked = [{"class": "RUNTIME_OBSERVED", "key_ref": "k/old", "evidence_id": "U-1"}]
    assert ec.disabled_key_check(leaked, records)["ok"] is False
    kept, suppressed = ec.suppress_unusable_key_events(leaked, records)
    assert kept == [] and suppressed[0]["reason"]


def test_a_suppression_without_a_reason_fails_the_check():
    records = [{"key_ref": "k/old", "usable": False, "status": "DISABLED"}]
    assert ec.disabled_key_check([], records, suppressed=[{"key_ref": "k/old"}])["ok"] is False


def test_a_usable_key_operation_is_kept():
    records = [{"key_ref": "k/live", "usable": True, "status": "ENABLED"}]
    event = {"class": "RUNTIME_OBSERVED", "key_ref": "k/live", "evidence_id": "U-1"}
    kept, suppressed = ec.suppress_unusable_key_events([event], records)
    assert kept == [event] and suppressed == []


# --------------------------------------------------------------------------- #
# invariant 6: coverage travels with the document


def test_the_document_carries_its_coverage():
    result = _running()
    properties = {row["name"]: row["value"]
                  for row in result["document"]["metadata"]["properties"]}
    assert cr.PROPERTY_COVERAGE in properties
    assert properties[cr.PROPERTY_COMPLETENESS] == "PARTIAL"


def test_the_document_does_not_claim_a_total_it_cannot_quote():
    result = _running()
    assert result["coverage"]["may_report_total"] is False


# --------------------------------------------------------------------------- #
# invariant 7: emptiness is explained


def test_an_empty_estate_says_why_it_is_empty():
    result = ec.run({})
    assert result["empty"]["empty"] is True
    properties = {row["name"]: row["value"]
                  for row in result["document"]["metadata"]["properties"]}
    assert properties[cr.PROPERTY_EMPTY] == "true"
    assert result["empty"]["statement"]


def test_an_empty_document_with_stated_coverage_is_not_called_unexplained():
    result = ec.run({"coverage": {"rollup": {"systems": 10, "with_cbom": 10},
                                  "files_scanned": 400}})
    assert result["checks"][-1]["ok"] is True


# --------------------------------------------------------------------------- #
# the document itself


def test_the_document_has_no_top_level_properties_array():
    result = _running()
    assert "properties" not in result["document"]
    assert result["document"]["metadata"]["properties"]


def test_the_document_records_what_it_left_out():
    result = _running()
    properties = {row["name"]: row["value"]
                  for row in result["document"]["metadata"]["properties"]}
    assert properties["cryptoscan:promoted_assets"] == "1"
    assert properties["cryptoscan:candidates_excluded"] == "2"


# --------------------------------------------------------------------------- #
# the graph and the summary


def test_the_graph_keeps_a_conflict_edge_for_the_disagreement():
    result = _running()
    kinds = {edge["kind"] for edge in result["graph"]["edges"]}
    assert "CONFLICTS_WITH" in kinds
    assert "USES_CRYPTO" in kinds


def test_the_summary_holds_when_every_check_holds():
    summary = ec.summary(_running())
    assert summary["status"] == "HOLDS"
    assert summary["checks_passed"] == summary["checks_total"] == len(ec.CHECKS)
    assert summary["failed_checks"] == []


def test_the_summary_reports_a_broken_pipeline():
    result = _running()
    result["checks"] = [dict(result["checks"][0], ok=False)]
    summary = ec.summary(result)
    assert summary["status"] == "BROKEN"
    assert summary["failed_checks"] == [result["checks"][0]["check"]]


def test_the_summary_counts_the_document_not_the_candidates():
    summary = ec.summary(_running())
    assert summary["documented_assets"] == 1
    assert summary["candidates_excluded"] == 2


def test_the_handoff_covers_only_the_documented_assets():
    result = _running()
    assert [row["algorithm"] for row in result["handoff"]["rows"]] == ["AES-256-GCM"]


# --------------------------------------------------------------------------- #
# network attribution inside the chain


def test_the_chain_keeps_the_network_attribution_separate_from_the_application():
    estate = _estate(probes=[{
        "from": "Internet", "to": "External LB", "endpoint": "payments.bank.example:443",
        "observed_on": "External LB", "status": "OK", "evidence_id": "NET-1",
        "crypto": {"cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "tls_version": "1.2"}}])
    result = ec.run(estate)
    network = result["network"]
    assert network["assets"]
    assert all(row["observed_on"] == "External LB" for row in network["assets"])
    assert all(row["application_inference"] == "NOT_PROVEN" for row in network["assets"])
    assert all("cryptoscan:application" not in {prop["name"] for prop in component["properties"]}
               for component in network["components"])


def test_the_chain_audits_its_own_graph_for_the_fronting_hop_overclaim():
    estate = _estate(probes=[{
        "from": "Internet", "to": "External LB", "endpoint": "payments.bank.example:443",
        "observed_on": "External LB", "status": "OK", "evidence_id": "NET-1",
        "crypto": {"cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "tls_version": "1.2"}}])
    result = ec.run(estate)
    audit = result["network"]["audit"]
    assert audit["checked_edges"] > 0
    assert audit["overclaims"]
    assert audit["overclaims"][0]["terminated_at"] == ["External LB"]


def test_a_network_observation_does_not_break_the_seven_checks():
    result = _running()
    assert result["network"]["audit"]["overclaims"] == []
    assert ec.summary(result)["status"] == "HOLDS"
