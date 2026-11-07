"""Scenario simulation — roadmap item 8 acceptance rows.

Standing directives: "A simulation must distinguish a proven dependency from an
assumed dependency. Never represent a hypothetical result as a real production
change." Runs refuse to start without a selected versioned snapshot.
"""

from __future__ import annotations

import json

import pytest

from shared_models.scenario_simulation import (
    SCENARIOS,
    SIMULATION_KIND,
    run_scenario,
    scenario_catalog,
)

SNAPSHOT = {"snapshot_id": "SNAP-2026-11-07-01", "version": 12,
            "captured_at": "2026-11-07T00:00:00+00:00"}

EDGES = [
    {"subject": "payments-api", "predicate": "uses", "object": "load-balancer",
     "basis": "CONFIGURATION", "evidence_ids": ["E1"]},
    {"subject": "load-balancer", "predicate": "uses", "object": "tls-cert",
     "basis": "CONFIGURATION", "evidence_ids": ["E2"]},
    {"subject": "reporting-svc", "predicate": "uses", "object": "tls-cert",
     "basis": "APPROVED_MAPPING", "evidence_ids": []},          # unknown edge
]
LOOKUP = {
    "E1": {"evidence_type": "RUNTIME_OBSERVED", "observed_at": "2026-11-01"},
    "E2": {"evidence_type": "CONFIGURED", "observed_at": "2026-11-01"},
}

ASSESSMENTS = [{
    "subject": "payments-api",
    "blockers": [{"dependency": "hsm-1", "kind": "HSM", "certainty": "PROVEN",
                  "evidence_ids": ["E9"],
                  "reason": "evidence shows this dependency lacks the required "
                            "capability: a proven migration blocker"}],
    "compatibility": [{"dependency": "tls-stack", "kind": "PROTOCOL",
                       "state": "NOT_ASSESSED",
                       "reason": "compatibility was never established: not "
                                 "assessed is never compatible",
                       "evidence_ids": []}],
    "cost": {"total_units": 26},
}]


class TestSnapshotRequirement:

    def test_a_run_refuses_without_a_versioned_snapshot(self):
        for broken in ({}, {"snapshot_id": "S"}, {"snapshot_id": "S", "version": 1},
                       {"snapshot_id": "S", "captured_at": "2026-11-07"}):
            with pytest.raises(ValueError, match="versioned snapshot"):
                run_scenario(scenario="HSM_FAILURE", snapshot=broken,
                             focal_asset="hsm-1")

    def test_the_output_echoes_the_snapshot_it_simulated(self):
        result = run_scenario(scenario="HSM_FAILURE", snapshot=SNAPSHOT,
                              focal_asset="tls-cert", edges=EDGES,
                              evidence_by_id=LOOKUP)
        assert result["snapshot"] == SNAPSHOT


class TestScenarioCatalog:

    def test_all_twelve_scenarios_run(self):
        for name in SCENARIOS:
            result = run_scenario(scenario=name, snapshot=SNAPSHOT,
                                  focal_asset="tls-cert", edges=EDGES,
                                  evidence_by_id=LOOKUP)
            assert result["scenario"] == name

    def test_an_unknown_scenario_is_refused(self):
        with pytest.raises(ValueError, match="unknown scenario"):
            run_scenario(scenario="MADE_UP", snapshot=SNAPSHOT,
                         focal_asset="tls-cert")

    def test_the_catalog_names_kinds_and_requirements(self):
        catalog = scenario_catalog()
        assert len(catalog["scenarios"]) == 12
        kinds = {row["kind"] for row in catalog["scenarios"]}
        assert kinds == {"change", "incident", "trust"}


class TestHypotheticalNeverReal:

    def test_every_result_is_labelled_a_simulation(self):
        result = run_scenario(scenario="RSA_2048_TO_ML_DSA", snapshot=SNAPSHOT,
                              focal_asset="payments-api", edges=EDGES,
                              evidence_by_id=LOOKUP)
        assert result["result_kind"] == SIMULATION_KIND
        assert result["hypothetical"] is True
        assert "never be shown as a real production change" in result["note"]

    def test_approvals_and_rollback_are_what_would_be_required(self):
        change = run_scenario(scenario="HYBRID_PQ_KEY_ESTABLISHMENT",
                              snapshot=SNAPSHOT, focal_asset="payments-api",
                              edges=EDGES, evidence_by_id=LOOKUP)
        assert "change advisory board approval" in change["approvals_required"]
        assert any("revert procedure" in row for row in change["rollback_plan"])
        incident = run_scenario(scenario="KMS_OUTAGE", snapshot=SNAPSHOT,
                                focal_asset="tls-cert", edges=EDGES,
                                evidence_by_id=LOOKUP)
        assert "incident commander assignment" in incident["approvals_required"]
        assert any("failover" in row for row in incident["rollback_plan"])


class TestProvenVersusAssumed:

    def test_proven_and_assumed_dependencies_are_kept_apart(self):
        result = run_scenario(scenario="CA_COMPROMISE", snapshot=SNAPSHOT,
                              focal_asset="tls-cert", edges=EDGES,
                              evidence_by_id=LOOKUP)
        proven = {row["asset"] for row in result["proven_dependencies"]}
        assumed = {row["asset"] for row in result["assumed_dependencies"]}
        assert "load-balancer" in proven        # backed by E1/E2
        assert "reporting-svc" in assumed       # unknown edge, no evidence
        assert proven & assumed == set()
        for row in result["assumed_dependencies"]:
            assert row["why_assumed"] in {"INFERRED", "UNKNOWN"}

    def test_an_unknown_chain_is_never_listed_as_proven(self):
        result = run_scenario(scenario="TLS_DOWNGRADE", snapshot=SNAPSHOT,
                              focal_asset="tls-cert", edges=EDGES,
                              evidence_by_id=LOOKUP)
        for row in result["proven_dependencies"]:
            assert row["chain"], "a proven dependency has a chain"
            for hop in row["chain"]:
                assert hop["provenance"] == "PROVEN"


class TestFoldedAssessments:

    def test_a_migration_scenario_carries_blockers_and_compatibility_failures(self):
        result = run_scenario(scenario="RSA_2048_TO_ML_DSA", snapshot=SNAPSHOT,
                              focal_asset="tls-cert", edges=EDGES,
                              evidence_by_id=LOOKUP,
                              assessments=ASSESSMENTS)
        assert result["blockers"][0]["certainty"] == "PROVEN"
        assert result["compatibility_failures"][0]["state"] == "NOT_ASSESSED"
        assert result["cost"]["assessment_units"] == 26

    def test_assessments_for_unaffected_subjects_are_not_folded_in(self):
        stranger = [{**ASSESSMENTS[0], "subject": "unrelated-batch-job"}]
        result = run_scenario(scenario="RSA_2048_TO_ML_DSA", snapshot=SNAPSHOT,
                              focal_asset="tls-cert", edges=EDGES,
                              evidence_by_id=LOOKUP,
                              assessments=stranger)
        assert result["blockers"] == []
        assert result["cost"]["assessment_units"] == 0


class TestDeterminism:

    def test_the_same_inputs_produce_the_same_simulation(self):
        def run():
            return json.dumps(run_scenario(
                scenario="VENDOR_RETIREMENT", snapshot=SNAPSHOT,
                focal_asset="tls-cert", edges=EDGES, evidence_by_id=LOOKUP,
                assessments=ASSESSMENTS), sort_keys=True, default=str)
        assert run() == run()
