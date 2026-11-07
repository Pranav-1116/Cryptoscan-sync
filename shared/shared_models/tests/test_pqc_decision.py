"""PQC decision engine — roadmap item 3 acceptance rows.

Standing directives pinned here: never mark an org PQC-ready because a library
supports ML-KEM; never confuse the usage levels; never treat "not assessed" as
"compatible"; a plan is hypothetical and never a production change; every cost
number is reproducible from its rule.
"""

from __future__ import annotations

import json

from shared_models.pqc_claims import claim, pqc_claim_report
from shared_models.pqc_decision import (
    COST_RULES,
    PLAN_KIND,
    assess_subject,
    classify_algorithm,
    plan_waves,
)


def at(days_ago: str) -> str:
    return f"2026-11-0{days_ago}T00:00:00+00:00"


class TestClassification:

    def test_shor_broken_classical_is_classical_vulnerable(self):
        assert classify_algorithm("RSA-2048")["class"] == "CLASSICAL_VULNERABLE"
        assert classify_algorithm("ECDSA-P256")["class"] == "CLASSICAL_VULNERABLE"

    def test_grover_affected_symmetric_is_its_own_class(self):
        assert classify_algorithm("AES-256")["class"] == "GROVER_AFFECTED"

    def test_pqc_families_are_post_quantum(self):
        for name in ("ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128f"):
            assert classify_algorithm(name)["class"] == "POST_QUANTUM", name

    def test_hybrid_key_establishment_is_its_own_class(self):
        row = classify_algorithm("X25519MLKEM768")
        assert row["class"] == "POST_QUANTUM_HYBRID"

    def test_an_unclassified_algorithm_is_unknown_never_fine(self):
        row = classify_algorithm("NOT-A-CIPHER")
        assert row["class"] == "UNCLASSIFIED"
        assert "never 'fine'" in row["reason"]


class TestBlockersAndCompatibility:

    def _assessment(self, dependencies):
        return assess_subject(
            subject="payments-api",
            current_algorithms=["RSA-2048"],
            dependencies=dependencies)

    def test_a_capability_gap_with_evidence_is_a_proven_blocker(self):
        result = self._assessment([
            {"kind": "HSM", "name": "hsm-1", "capability_state": "LACKS",
             "evidence_ids": ["E1"]}])
        blocker = result["blockers"][0]
        assert blocker["certainty"] == "PROVEN"
        assert blocker["evidence_ids"] == ["E1"]

    def test_an_asserted_gap_without_evidence_is_neither_blocker_nor_cleared(self):
        result = self._assessment([
            {"kind": "HSM", "name": "hsm-1", "capability_state": "LACKS",
             "evidence_ids": []}])
        assert result["blockers"][0]["certainty"] == "UNKNOWN"
        assert "neither a proven blocker nor a cleared" in result["blockers"][0]["reason"]

    def test_not_assessed_is_never_compatible(self):
        result = self._assessment([
            {"kind": "PROTOCOL", "name": "tls-1.2-stack",
             "capability_state": "NOT_ASSESSED", "evidence_ids": []}])
        compat = result["compatibility"][0]
        assert compat["state"] == "NOT_ASSESSED"
        assert "not assessed is never compatible" in compat["reason"]

    def test_support_without_evidence_is_not_compatible_either(self):
        result = self._assessment([
            {"kind": "APPLICATION", "name": "ledger-core",
             "capability_state": "SUPPORTS", "evidence_ids": []}])
        assert result["compatibility"][0]["state"] == "NOT_ASSESSED"

    def test_evidence_backed_support_is_compatible(self):
        result = self._assessment([
            {"kind": "KMS", "name": "kms-1", "capability_state": "SUPPORTS",
             "evidence_ids": ["E9"]}])
        row = result["compatibility"][0]
        assert row["state"] == "COMPATIBLE"
        assert row["evidence_ids"] == ["E9"]


class TestReadinessNeverAuto:

    def test_support_only_claims_never_make_a_subject_ready(self):
        report = pqc_claim_report([
            claim(stage="SUPPORT_AVAILABLE", subject="payments-api",
                  evidence_ids=["E1"], evidence_type="VENDOR_DECLARED",
                  observed_at=at(1), algorithm="ML-KEM-768")])
        result = assess_subject(subject="payments-api",
                                current_algorithms=["RSA-2048"],
                                claim_report=report)
        assert result["readiness"] == "SUPPORT_ONLY"
        assert "not PQC readiness" in result["readiness_reason"]
        assert result["readiness_source"] == "pqc-claims"

    def test_no_claims_at_all_is_unknown_never_fine(self):
        result = assess_subject(subject="payments-api",
                                current_algorithms=["ML-KEM-768"])
        assert result["readiness"] == "NO_EVIDENCE"
        assert "neither ready nor fine" in result["readiness_reason"]
        assert set(result["claim_stages"]) == {
            "SUPPORT_AVAILABLE", "CONFIGURED", "RUNTIME_OBSERVED",
            "NETWORK_NEGOTIATED", "MIGRATION_VALIDATED"}

    def test_the_validation_requirement_names_only_direct_evidence(self):
        result = assess_subject(subject="payments-api")
        assert result["validation_requirement"]["stage"] == "MIGRATION_VALIDATED"
        assert "VENDOR_DECLARED" not in result["validation_requirement"]["acceptable_evidence"]
        assert "RUNTIME_OBSERVED" in result["validation_requirement"]["acceptable_evidence"]


class TestPrioritisation:

    def test_contributions_are_named_and_blind_spots_are_flagged(self):
        result = assess_subject(
            subject="payments-api",
            current_algorithms=["RSA-2048"],
            quantum_threat_horizon_years=None,      # urgency unscoreable
            dependents=4,
            chain_counts={"proven": 2})
        prio = result["prioritisation"]
        assert "QUANTUM_URGENCY" in prio["missing_dimensions"]
        assert {c["dimension"] for c in prio["contributions"]} == {
            "CRYPTO_RISK", "OPERATIONAL_DEPENDENCY"}
        assert "blind spots" in prio["reason"]
        assert prio["priority_score"] is not None

    def test_nothing_scoreable_means_incomplete_not_low(self):
        result = assess_subject(subject="blank")
        prio = result["prioritisation"]
        assert prio["priority"] == "INCOMPLETE_ASSESSMENT"
        assert prio["priority_score"] is None

    def test_the_same_inputs_produce_the_same_assessment(self):
        kwargs = dict(subject="payments-api", current_algorithms=["RSA-2048"],
                      dependencies=[{"kind": "HSM", "name": "hsm-1",
                                     "capability_state": "SUPPORTS",
                                     "evidence_ids": ["E1"]}],
                      quantum_threat_horizon_years=5, dependents=3)
        first = json.dumps(assess_subject(**kwargs), sort_keys=True, default=str)
        second = json.dumps(assess_subject(**kwargs), sort_keys=True, default=str)
        assert first == second


class TestCost:

    def test_all_eight_scopes_are_priced_by_a_cited_rule(self):
        result = assess_subject(
            subject="payments-api",
            dependencies=[
                {"kind": "APPLICATION", "name": "a", "capability_state": "SUPPORTS",
                 "evidence_ids": ["E1"]},
                {"kind": "HOST", "name": "h", "capability_state": "SUPPORTS",
                 "evidence_ids": ["E2"]},
                {"kind": "HSM", "name": "s", "capability_state": "LACKS",
                 "evidence_ids": ["E3"]},
                {"kind": "CERTIFICATE", "name": "c", "capability_state": "SUPPORTS",
                 "evidence_ids": ["E4"]},
                {"kind": "PROTOCOL", "name": "p", "capability_state": "SUPPORTS",
                 "evidence_ids": ["E5"]},
            ])
        rows = {row["scope"]: row for row in result["cost"]["rows"]}
        assert set(rows) == set(COST_RULES)
        for scope, row in rows.items():
            assert row["rule"] in COST_RULES[scope]
        # CR-HSM: incompatible HSM = 5 + 2
        assert rows["HSM_KMS"]["units"] == 7
        assert rows["APPLICATIONS"]["units"] == 3
        assert rows["TESTING"]["units"] == 5
        total = sum(row["units"] for row in result["cost"]["rows"])
        assert result["cost"]["total_units"] == total

    def test_cost_is_reproducible(self):
        kwargs = dict(subject="x",
                      dependencies=[{"kind": "HOST", "name": "h",
                                     "capability_state": "SUPPORTS",
                                     "evidence_ids": ["E1"]}])
        assert (assess_subject(**kwargs)["cost"]
                == assess_subject(**kwargs)["cost"])


class TestWaves:

    def _assessments(self):
        blocked = assess_subject(
            subject="core-banking",
            current_algorithms=["RSA-2048"],
            dependencies=[{"kind": "HSM", "name": "hsm-1",
                           "capability_state": "LACKS", "evidence_ids": ["E1"]}],
            quantum_threat_horizon_years=5, dependents=9,
            chain_counts={"proven": 3})
        ready = assess_subject(
            subject="payments-api",
            current_algorithms=["RSA-2048"],
            quantum_threat_horizon_years=5, dependents=5)
        low = assess_subject(
            subject="intranet-wiki",
            current_algorithms=["AES-256"],
            quantum_threat_horizon_years=5, dependents=1)
        return [ready, blocked, low]

    def test_proven_blockers_go_to_wave_zero_first(self):
        plan = plan_waves(self._assessments())
        assert plan["waves"][0]["wave"] == 0
        assert plan["waves"][0]["mission"].startswith("BLOCKER_REMEDIATION")
        assert plan["waves"][0]["subjects"] == ["core-banking"]

    def test_the_rest_order_by_priority_desc(self):
        plan = plan_waves(self._assessments())
        migrated = plan["waves"][1]["subjects"]
        assert migrated[0] == "payments-api"   # RSA + 5 dependents outranks AES + 1
        assert migrated[1] == "intranet-wiki"

    def test_every_wave_rolls_back_and_validates(self):
        plan = plan_waves(self._assessments(), wave_capacity=1)
        for wave in plan["waves"]:
            assert "snapshot" in " ".join(wave["rollback_plan"]["requirements"])
            assert "MIGRATION_VALIDATED" in " ".join(
                wave["validation_plan"]["requirements"])
            assert "RUNTIME_OBSERVED" in wave["validation_plan"]["acceptable_evidence"]

    def test_the_plan_is_labelled_hypothetical(self):
        plan = plan_waves(self._assessments())
        assert plan["result_kind"] == PLAN_KIND
        assert "hypothetical" in plan["note"]
        assert "no wave here has been executed" in plan["note"]

    def test_wave_planning_is_deterministic(self):
        rows = self._assessments()
        first = json.dumps(plan_waves(rows), sort_keys=True, default=str)
        second = json.dumps(plan_waves(rows), sort_keys=True, default=str)
        assert first == second

    def test_capacity_chunks_the_migration_wave(self):
        plan = plan_waves(self._assessments(), wave_capacity=1)
        migration_waves = [w for w in plan["waves"] if w["wave"] > 0]
        assert len(migration_waves) == 2
        assert all(len(w["subjects"]) == 1 for w in migration_waves)


class TestTargets:

    def test_hybrid_targets_keep_their_own_class(self):
        result = assess_subject(
            subject="payments-api",
            targets={"key_establishment": {"algorithm": "X25519MLKEM768",
                                          "hybrid": True},
                     "signatures": "ML-DSA-65"})
        assert result["targets"]["key_establishment"]["class"] == "POST_QUANTUM_HYBRID"
        assert result["targets"]["signatures"]["class"] == "POST_QUANTUM"
