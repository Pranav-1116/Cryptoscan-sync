"""CBOM → digital twin: one graph, three consumers, no claim upgrades.

Review item 20's architecture: five evidence families feed the crypto graph, the
graph feeds the CBOM, the CBOM is projected into a twin, and three consumers —
drift, PQC migration, threat intelligence — read the twin. These tests are about
the projection's honesty: a node never claims more than its evidence, and a
consumer never claims more than its node.
"""

from __future__ import annotations

import pytest

from cbom import digital_twin as dt

ESTATE = {
    "name": "bank-estate",
    "as_of": "2026-11-02",
    "components": [{"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
                    "algorithms": ["AES-256-GCM", "RSA-2048", "AES-128-CBC",
                                   "AES-192-CBC"]}],
    "declared_versions": [{"name": "openssl", "version": "3.0.13",
                           "evidence_id": "SBOM-1"}],
    "operations": [{"application": "payments-api", "pid": 9182, "provider": "OpenSSL",
                    "provider_version": "3.0.11", "operation": "EVP_EncryptInit_ex",
                    "algorithm": "AES-256-GCM", "key_size": 256, "mode": "GCM",
                    "observed_at": "2026-11-02T10:42:11Z", "evidence_id": "RUNTIME-1"}],
    "keys": [{"key_ref": "kms/key/abc", "algorithm": "RSA", "key_size": 2048,
              "provider": "AWS_KMS", "status": "ENABLED", "created_at": "2025-01-01",
              "evidence_id": "KMS-1"}],
    "key_uses": [{"key_ref": "kms/key/abc", "operation": "decrypt",
                  "evidence_id": "KMS-USE-1"}],
    "probes": [{"endpoint": "payments.bank.example:443", "status": "OK",
                "crypto": {"tls_version": "1.3",
                           "cipher_suite": "TLS_AES_256_GCM_SHA384"},
                "evidence_id": "NET-1"}],
    "findings": [{"algorithm": "AES-128-CBC", "file_path": "legacy.java", "line": 12,
                  "key_size": 128, "mode": "CBC", "evidence_ids": ["STATIC-1"]}],
    "conflicts": [
        # declared vs observed is resolved by precedence, not a conflict
        {"field": "version", "fact": "3.0.13", "source": "sbom", "evidence_id": "SBOM-1"},
        {"field": "version", "fact": "3.0.11", "source": "runtime",
         "evidence_id": "RUNTIME-1"},
        # two observers disagreeing is a conflict, and it stays one
        {"field": "cipher_suite", "fact": "TLS_AES_256_GCM_SHA384", "source": "network",
         "evidence_id": "NET-1"},
        {"field": "cipher_suite", "fact": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
         "source": "runtime", "evidence_id": "RUNTIME-2"}],
    "coverage": {"rollup": {"systems": 10, "with_cbom": 6,
                            "counts": {"CURRENT": 6, "STALE": 4}},
                 "files_scanned": 90},
}


@pytest.fixture(scope="module")
def twin():
    return dt.build(ESTATE)


def _node(twin, node_id):
    return {node["id"]: node for node in twin["nodes"]}[node_id]


# --------------------------------------------------------------------------- #
# the projection


def test_a_non_object_estate_is_refused():
    with pytest.raises(ValueError):
        dt.build(["not", "an", "estate"])


def test_five_families_are_counted_and_the_missing_ones_are_named():
    twin = dt.build({**ESTATE, "probes": []})
    assert set(twin["families"]) == set(dt.FAMILIES)
    assert "network" in twin["unrepresented_families"]
    assert "no evidence yet from network" in twin["statement"]


def test_a_documented_algorithm_is_a_runtime_node(twin):
    node = _node(twin, "algorithm:AES-256-GCM")
    assert node["claim_level"] == "RUNTIME"
    assert node["families"] == ["network", "runtime"]
    assert node["evidence_ids"] == ["NET-1", "RUNTIME-1"]
    assert node["usage"] == "OBSERVED"


def test_a_library_stays_a_capability_even_when_its_algorithms_are_observed(twin):
    component = _node(twin, "component:openssl")
    assert component["claim_level"] == "CAPABILITY"
    assert component["families"] == ["sbom"]
    assert "AES-256-GCM" in component["declares"]


def test_a_capability_edge_does_not_borrow_the_algorithm_node_s_evidence(twin):
    supports = [edge for edge in twin["edges"] if edge["kind"] == "SUPPORTS"]
    assert supports and all(edge["evidence_ids"] == ["SBOM-1"] for edge in supports)
    assert all(edge["provenance"] == "UNATTRIBUTED" for edge in supports)


def test_the_provider_node_carries_the_version_the_process_loaded(twin):
    node = _node(twin, "provider:OpenSSL@3.0.11")
    assert node["kind"] == "PROVIDER"
    assert node["version"] == "3.0.11"
    assert node["claim_level"] == "RUNTIME"


def test_the_process_node_is_the_pid_not_the_application(twin):
    node = _node(twin, "process:payments-api/9182")
    assert node["kind"] == "PROCESS"
    assert node["claim_level"] == "RUNTIME"


def test_an_endpoint_owns_the_algorithm_it_negotiated(twin):
    node = _node(twin, "endpoint:payments.bank.example:443")
    assert node["claim_level"] == "NETWORK"
    edges = {(edge["from"], edge["kind"], edge["to"]) for edge in twin["edges"]}
    assert ("endpoint:payments.bank.example:443", "NEGOTIATES",
            "algorithm:AES-256-GCM") in edges


def test_a_key_is_configured_and_never_observed(twin):
    node = _node(twin, "key:kms/key/abc")
    assert node["claim_level"] == "CONFIGURED"
    assert node["private_material"] == "NOT STORED"
    assert "RUNTIME_OBSERVED" not in node["evidence_classes"]


def test_a_conflict_survives_as_an_edge_with_both_evidence_ids(twin):
    conflicts = [edge for edge in twin["edges"] if edge["kind"] == "CONFLICTS_WITH"]
    assert len(conflicts) == 1
    assert conflicts[0]["evidence_ids"] == ["NET-1", "RUNTIME-2"]
    assert conflicts[0]["field"] == "cipher_suite"


def test_no_edge_dangles(twin):
    ids = {node["id"] for node in twin["nodes"]}
    for edge in twin["edges"]:
        assert edge["from"] in ids and edge["to"] in ids, edge


def test_every_edge_carries_provenance_and_evidence(twin):
    for edge in twin["edges"]:
        assert edge["evidence_ids"]
        assert edge["provenance"] in {"OBSERVED", "DECLARED", "INFERRED", "UNATTRIBUTED"}


def test_the_twin_carries_the_cbom_it_was_projected_from(twin):
    assert twin["cbom"]["bomFormat"] == "CycloneDX"
    assert twin["chain_schema"] == "cryptoscan.cbom-estate-chain/1"


def test_a_precomputed_chain_is_not_recomputed():
    chain = {"schema": "cryptoscan.cbom-estate-chain/1", "estate": "given",
             "document": {"bomFormat": "CycloneDX", "components": []},
             "runtime": {}, "keys": {}, "network": {}, "graph": {}}
    twin = dt.build({"chain": chain})
    assert twin["estate"] == "given"
    assert twin["cbom"] is chain["document"]


@pytest.mark.parametrize("classes,level", [
    (["RUNTIME_OBSERVED"], "RUNTIME"),
    (["NETWORK_OBSERVED", "STATIC_OBSERVED"], "NETWORK"),
    (["STATIC_OBSERVED"], "STATIC"),
    (["CONFIGURED", "HSM_OBSERVED"], "CONFIGURED"),
    (["IMPORTED", "VENDOR_DECLARED"], "IMPORTED"),
    (["CAPABILITY"], "CAPABILITY"),
    ([], "CAPABILITY"),
    (["SOMETHING_ELSE"], "CAPABILITY"),
])
def test_claim_levels_are_ranked_by_one_table(classes, level):
    assert dt._level(classes) == level


# --------------------------------------------------------------------------- #
# drift


def _drift(twin, *policy):
    return dt.drift(twin, list(policy))


def test_an_observed_algorithm_nobody_decided_about_is_unattributed(twin):
    body = _drift(twin)
    states = {row["algorithm"]: row["state"] for row in body["findings"]}
    assert states == {"AES-128-CBC": "UNATTRIBUTED", "AES-256-GCM": "UNATTRIBUTED"}


def test_a_candidate_algorithm_is_never_reported_as_usage(twin):
    body = _drift(twin)
    assert [row["algorithm"] for row in body["findings"]] == ["AES-128-CBC", "AES-256-GCM"]
    assert "AES-192-CBC" not in {row["algorithm"] for row in body["findings"]}


def test_a_source_tree_finding_is_static_evidence(twin):
    node = _node(twin, "algorithm:AES-128-CBC")
    assert node["claim_level"] == "STATIC"
    assert node["families"] == ["static"]
    assert node["evidence_ids"] == ["STATIC-1"]


def test_a_policy_row_nothing_was_seen_using_is_not_drift(twin):
    body = _drift(twin, {"algorithm": "SHA-1", "allowed": False})
    row = [item for item in body["findings"] if item["algorithm"] == "SHA-1"][0]
    assert row["state"] == "POLICY_NOT_OBSERVED"
    assert "not evidence that nothing does" in row["detail"]
    assert body["clean"] is True and "SHA-1" not in {
        item["algorithm"] for item in body["findings"] if item["state"] == "UNEXPECTED_USE"}


def test_a_forbidden_algorithm_seen_in_use_is_drift(twin):
    body = _drift(twin, {"algorithm": "AES-256-GCM", "allowed": False})
    row = [item for item in body["findings"] if item["algorithm"] == "AES-256-GCM"][0]
    assert row["state"] == "UNEXPECTED_USE"
    assert row["evidence_ids"] == ["NET-1", "RUNTIME-1"]
    assert body["clean"] is False


def test_the_wrong_key_size_is_parameter_drift(twin):
    body = _drift(twin, {"algorithm": "AES-256-GCM", "key_size": 128})
    row = [item for item in body["findings"] if item["algorithm"] == "AES-256-GCM"][0]
    assert row["state"] == "PARAMETER_DRIFT"
    assert "expects key_size 128" in row["detail"]


def test_an_unrecorded_key_size_is_not_called_drift(twin):
    thin = dt.build({**ESTATE, "probes": [],
                     "operations": [{key: value for key, value in
                                     ESTATE["operations"][0].items()
                                     if key != "key_size"}]})
    body = _drift(thin, {"algorithm": "AES-256-GCM", "key_size": 256})
    row = [item for item in body["findings"] if item["algorithm"] == "AES-256-GCM"][0]
    assert row["state"] == "PARAMETER_UNKNOWN"
    assert "drift cannot be asserted" in row["detail"]


def test_a_clean_drift_report_says_so(twin):
    body = _drift(twin, {"algorithm": "AES-128-CBC", "key_size": 128})
    assert body["clean"] is True
    assert "1 unattributed" in body["statement"]  # AES-256-GCM, seen at runtime
    assert "policy not observed" not in body["statement"]


# --------------------------------------------------------------------------- #
# PQC migration


def test_migration_priority_is_escalated_by_observed_use(twin):
    body = dt.pqc_migration(twin)
    row = [item for item in body["rows"] if item["algorithm"] == "AES-256-GCM"][0]
    assert row["claim_level"] == "RUNTIME"
    assert row["status_basis"].startswith("REGISTRY_")


def test_rsa_observed_at_runtime_is_immediate(twin):
    estate = {**ESTATE, "operations": [{**ESTATE["operations"][0],
                                        "algorithm": "RSA-2048", "provider": "OpenSSL",
                                        "key_size": 2048}]}
    body = dt.pqc_migration(dt.build(estate))
    row = [item for item in body["rows"] if item["algorithm"] == "RSA-2048"][0]
    assert row["quantum_status"] == "QUANTUM_SENSITIVE"
    assert row["migration_priority"] == "IMMEDIATE"
    assert "IMMEDIATE priority" in body["statement"]


def test_the_queue_is_ordered_by_urgency(twin):
    body = dt.pqc_migration(twin)
    order = ["IMMEDIATE", "NEAR_TERM", "PLANNED", "MONITOR"]
    ranks = [order.index(row["migration_priority"]) for row in body["rows"]
             if row["migration_priority"] in order]
    assert ranks == sorted(ranks)


def test_a_capability_only_algorithm_cannot_lead_the_queue(twin):
    body = dt.pqc_migration(twin)
    capability = [row for row in body["rows"] if row["claim_level"] == "CAPABILITY"]
    for row in capability:
        assert row["migration_priority"] != "IMMEDIATE"


# --------------------------------------------------------------------------- #
# threat intelligence


ADVISORY = {"id": "CVE-2024-0001", "component": "openssl", "fixed_in": "3.0.14",
            "severity": "HIGH"}


def test_a_running_provider_is_executing_exposure(twin):
    body = dt.threat_intelligence(twin, [ADVISORY])
    exposures = {row["exposure"] for row in body["findings"]
                 if row["nodes"] == ["provider:OpenSSL@3.0.11"]}
    assert exposures == {"EXECUTING"}
    assert "a process has it loaded" in [row["detail"] for row in body["findings"]
                                         if row["nodes"] == ["provider:OpenSSL@3.0.11"]][0]


def test_an_installed_component_is_present_not_executing(twin):
    body = dt.threat_intelligence(twin, [ADVISORY])
    row = [item for item in body["findings"]
           if item["nodes"] == ["component:openssl"]][0]
    assert row["exposure"] == "PRESENT"
    assert "nothing saying it is loaded" in row["detail"]


def test_a_version_outside_the_range_is_not_affected(twin):
    body = dt.threat_intelligence(twin, [{**ADVISORY, "fixed_in": "3.0.9"}])
    assert all(row["exposure"] == "NOT_AFFECTED" for row in body["findings"])


def test_a_component_with_no_version_can_be_neither_confirmed_nor_cleared(twin):
    unversioned = dt.build({**ESTATE, "components": [
        {"name": "openssl", "algorithms": ["AES-256-GCM"], "evidence_id": "SBOM-9"}]})
    body = dt.threat_intelligence(unversioned, [ADVISORY])
    assert any(row["exposure"] == "VERSION_UNKNOWN" for row in body["findings"])
    assert "neither confirmed nor cleared" in [row["detail"] for row in body["findings"]
                                               if row["exposure"] == "VERSION_UNKNOWN"][0]


def test_an_unknown_component_is_not_present(twin):
    body = dt.threat_intelligence(twin, [{**ADVISORY, "component": "libcrypto"}])
    assert body["findings"][0]["exposure"] == "NOT_PRESENT"
    assert body["exposed"] == 0


def test_a_capability_algorithm_never_produces_exposure_on_its_own(twin):
    body = dt.threat_intelligence(
        twin, [{**ADVISORY, "component": "aes-128-cbc", "fixed_in": "99.0.0"}])
    assert body["findings"][0]["exposure"] == "NOT_PRESENT"


def test_an_advisory_without_a_component_is_skipped(twin):
    body = dt.threat_intelligence(twin, [{"id": "CVE-1"}, "junk"])
    assert body["findings"] == []


# --------------------------------------------------------------------------- #
# the three consumers together


def test_all_three_consumers_answer_and_nothing_is_upgraded(twin):
    body = dt.consumers(twin, policy=[{"algorithm": "AES-256-GCM", "key_size": 256}],
                        advisories=[ADVISORY])
    assert set(body["consumers"]) == set(dt.CONSUMERS)
    assert body["claim_check"]["ok"] is True
    assert "drift" not in body["statement"] or isinstance(body["statement"], str)


def test_the_summary_reports_the_three_questions(twin):
    body = dt.consumers(twin, policy=[], advisories=[ADVISORY])
    summary = dt.summary(twin, body)
    assert summary["nodes"] == len(twin["nodes"])
    assert summary["advisories"]["EXECUTING"] == 1
    assert summary["claim_check"] is True
    assert "advisories exposed=2" in summary["statement"]
