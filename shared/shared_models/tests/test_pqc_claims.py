"""PQC migration-stage claims — roadmap item 3 acceptance rows.

The standing directive: "Do not automatically mark an organization PQC-ready just
because a library supports ML-KEM." These tests pin that and the four sibling rules:
five stages never confused, validation needs direct evidence, unknown is never fine,
and a contradiction is preserved rather than resolved by overwriting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models.pqc_claims import (
    OBSERVED_NOT_VALIDATED,
    PQC_CLAIM_STAGES,
    READY_VALIDATED,
    SUPPORT_ONLY,
    claim,
    pqc_claim_report,
)

NOW = datetime(2026, 11, 7, 12, 0, 0, tzinfo=timezone.utc)


def at(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).isoformat()


def support_claim(subject: str = "payments-api", **over):
    base = dict(stage="SUPPORT_AVAILABLE", subject=subject,
                evidence_ids=["EVID-1"], evidence_type="VENDOR_DECLARED",
                observed_at=at(1), algorithm="ML-KEM-768")
    base.update(over)
    return claim(**base)


class TestClaimConstruction:

    def test_the_five_stages_are_the_five_named_stages(self):
        assert PQC_CLAIM_STAGES == (
            "SUPPORT_AVAILABLE", "CONFIGURED", "RUNTIME_OBSERVED",
            "NETWORK_NEGOTIATED", "MIGRATION_VALIDATED")

    def test_a_claim_without_evidence_ids_is_refused(self):
        with pytest.raises(ValueError, match="assertion"):
            claim(stage="SUPPORT_AVAILABLE", subject="payments-api",
                  evidence_ids=[], evidence_type="VENDOR_DECLARED",
                  observed_at=at(1))

    def test_a_claim_without_a_clock_is_refused(self):
        with pytest.raises(ValueError, match="observed_at"):
            claim(stage="SUPPORT_AVAILABLE", subject="payments-api",
                  evidence_ids=["EVID-1"], evidence_type="VENDOR_DECLARED",
                  observed_at="  ")

    def test_a_vendor_declaration_cannot_establish_a_validated_migration(self):
        with pytest.raises(ValueError, match="cannot establish MIGRATION_VALIDATED"):
            claim(stage="MIGRATION_VALIDATED", subject="payments-api",
                  evidence_ids=["EVID-1"], evidence_type="VENDOR_DECLARED",
                  observed_at=at(1))

    def test_a_capability_claim_cannot_establish_a_runtime_observation(self):
        with pytest.raises(ValueError, match="cannot establish RUNTIME_OBSERVED"):
            claim(stage="RUNTIME_OBSERVED", subject="payments-api",
                  evidence_ids=["EVID-1"], evidence_type="STATIC_OBSERVED",
                  observed_at=at(1))

    def test_every_accepted_claim_carries_evidence_and_a_timestamp(self):
        record = support_claim()
        assert record["evidence_ids"] == ["EVID-1"]
        assert record["observed_at"] == at(1)


class TestReadinessVerdicts:

    def test_support_only_is_never_ready(self):
        report = pqc_claim_report([support_claim()], now=NOW)
        entry = report["subjects"]["payments-api"]
        assert entry["readiness"] == SUPPORT_ONLY
        assert "a library supporting ML-KEM is not PQC readiness" in entry["readiness_reason"]

    def test_runtime_observation_without_validation_is_not_ready(self):
        rows = [
            support_claim(),
            claim(stage="RUNTIME_OBSERVED", subject="payments-api",
                  evidence_ids=["EVID-2"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(1), algorithm="ML-KEM-768",
                  quantum_class="POST_QUANTUM"),
        ]
        entry = pqc_claim_report(rows, now=NOW)["subjects"]["payments-api"]
        assert entry["readiness"] == OBSERVED_NOT_VALIDATED

    def test_only_a_validated_claim_makes_a_subject_ready(self):
        rows = [
            support_claim(),
            claim(stage="RUNTIME_OBSERVED", subject="payments-api",
                  evidence_ids=["EVID-2"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(1), quantum_class="POST_QUANTUM"),
            claim(stage="NETWORK_NEGOTIATED", subject="payments-api",
                  evidence_ids=["EVID-3"], evidence_type="NETWORK_ACTIVE_OBSERVED",
                  observed_at=at(1), quantum_class="POST_QUANTUM_HYBRID"),
            claim(stage="MIGRATION_VALIDATED", subject="payments-api",
                  evidence_ids=["EVID-4"], evidence_type="AUDIT_OBSERVED",
                  observed_at=at(0.5), quantum_class="POST_QUANTUM"),
        ]
        entry = pqc_claim_report(rows, now=NOW)["subjects"]["payments-api"]
        assert entry["readiness"] == READY_VALIDATED
        # and the five stages are tracked separately even here
        states = {stage: entry["stages"][stage]["state"] for stage in PQC_CLAIM_STAGES}
        assert states["SUPPORT_AVAILABLE"] == "CLAIMED"
        assert states["MIGRATION_VALIDATED"] == "CLAIMED"

    def test_a_subject_with_no_claims_is_unknown_never_fine(self):
        report = pqc_claim_report([], now=NOW)
        assert report["subjects"] == {}
        # and a claim-less stage is NOT_CLAIMED, with the honest reason
        entry = pqc_claim_report([support_claim()], now=NOW)["subjects"]["payments-api"]
        assert entry["stages"]["MIGRATION_VALIDATED"]["state"] == "NOT_CLAIMED"
        assert "never 'fine'" in entry["stages"]["MIGRATION_VALIDATED"]["reason"]

    def test_a_stale_validation_cannot_hold_readiness_alone(self):
        rows = [
            claim(stage="MIGRATION_VALIDATED", subject="payments-api",
                  evidence_ids=["EVID-9"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(20), quantum_class="POST_QUANTUM"),
        ]
        entry = pqc_claim_report(rows, now=NOW)["subjects"]["payments-api"]
        assert entry["readiness"] == "VALIDATION_STALE"
        assert "stale" in entry["readiness_reason"]
        # the claim itself is preserved in the stage history
        assert entry["stages"]["MIGRATION_VALIDATED"]["claims"][0]["evidence_ids"] == ["EVID-9"]


class TestContradictionPreservation:

    def test_a_later_classical_observation_contradicts_a_validated_claim(self):
        rows = [
            claim(stage="MIGRATION_VALIDATED", subject="payments-api",
                  evidence_ids=["EVID-4"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(3), algorithm="ML-DSA-65",
                  quantum_class="POST_QUANTUM"),
            claim(stage="RUNTIME_OBSERVED", subject="payments-api",
                  evidence_ids=["EVID-7"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(1), algorithm="RSA-2048",
                  quantum_class="CLASSICAL"),
        ]
        entry = pqc_claim_report(rows, now=NOW)["subjects"]["payments-api"]
        assert entry["readiness"] == "CONTRADICTION_UNRESOLVED"
        assert entry["contradictions"][0]["kind"] == (
            "VALIDATION_VS_LATER_CLASSICAL_OBSERVATION")
        # both records survive, neither overwrites the other
        kept = entry["contradictions"][0]
        assert kept["validated_claim"]["evidence_ids"] == ["EVID-4"]
        assert kept["conflicting_claim"]["evidence_ids"] == ["EVID-7"]

    def test_an_earlier_classical_then_validated_is_not_a_contradiction(self):
        rows = [
            claim(stage="RUNTIME_OBSERVED", subject="payments-api",
                  evidence_ids=["EVID-1"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(5), quantum_class="CLASSICAL"),
            claim(stage="MIGRATION_VALIDATED", subject="payments-api",
                  evidence_ids=["EVID-2"], evidence_type="RUNTIME_OBSERVED",
                  observed_at=at(1), quantum_class="POST_QUANTUM"),
        ]
        entry = pqc_claim_report(rows, now=NOW)["subjects"]["payments-api"]
        assert entry["contradictions"] == []
        assert entry["readiness"] == READY_VALIDATED
