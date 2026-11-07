"""Migration plan records (gap analysis §H) and the acceptance gates register
(§6), as tests.

"The migration plan must record its policy version, algorithm profiles, source
snapshot, assumptions, cost model and human approvals." The six asset states
are distinct: UNKNOWN is insufficient evidence, VALIDATED needs post-change
evidence. Gates pass on filed evidence only; external gates are never passed
by the platform or by synthetic drills.
"""

from __future__ import annotations

import pytest

from shared_models.acceptance_gates import (
    COLLECTOR_QUALIFICATION,
    NOT_PASSED,
    PASSED,
    RECOVERY,
    file_gate_evidence,
    gates_status,
)
from shared_models.migration_plan import (
    CAPABLE,
    UNKNOWN,
    VALIDATED,
    asset_state,
    make_plan,
    validate_migration,
)


def plan(**over):
    base = dict(
        plan_id="PLAN-1", policy_version="PQ-POLICY-3",
        algorithm_profiles=[{"from": "RSA-2048", "to": "ML-DSA-65"}],
        source_snapshot={"snapshot_id": "SNAP-9", "version": 3},
        assumptions=["the HSM firmware upgrade lands before wave 2"],
        cost_model={"currency": "EUR", "lines": [
            {"item": "HSM upgrade", "estimate": 40000}]},
        approvals=[{"actor": "ciso", "role": "EXECUTIVE",
                    "at": "2026-11-07T00:00:00+00:00"}],
    )
    base.update(over)
    return make_plan(**base)


class TestPlan:

    def test_the_plan_records_every_named_component(self):
        row = plan()
        for field in ("policy_version", "algorithm_profiles", "source_snapshot",
                      "assumptions", "cost_model", "approvals"):
            assert row[field], field

    def test_an_unversioned_or_unsnapshotted_plan_is_refused(self):
        with pytest.raises(ValueError, match="cannot be reproduced"):
            plan(policy_version="")
        with pytest.raises(ValueError, match="snapshot_id"):
            plan(source_snapshot={"version": 3})

    def test_silent_no_assumptions_and_zero_costs_are_refused(self):
        with pytest.raises(ValueError, match="assumptions"):
            plan(assumptions=[])
        with pytest.raises(ValueError, match="unmeasured zero"):
            plan(cost_model={"lines": [{"item": "training", "estimate": 0}]})

    def test_an_approval_needs_a_named_human(self):
        with pytest.raises(ValueError, match="approving itself"):
            plan(approvals=[{"actor": "", "at": "2026-11-07"}])
        with pytest.raises(ValueError, match="draft"):
            plan(approvals=[])


class TestStates:

    def test_no_evidence_is_unknown_not_capable(self):
        row = asset_state(evidence={})
        assert row["state"] == UNKNOWN
        assert "UNKNOWN is not CAPABLE" in row["reason"]

    def test_capability_and_observation_are_distinct_states(self):
        assert asset_state(
            evidence={"capable": ["SBOM-1"]})["state"] == CAPABLE
        assert asset_state(
            evidence={"capable": ["SBOM-1"], "observed": ["RUN-1"]}
        )["state"] == "OBSERVED"

    def test_validation_needs_post_change_evidence_and_a_human(self):
        with pytest.raises(ValueError, match="post-change evidence"):
            validate_migration(asset="app-1", claimed_state=VALIDATED,
                               before_state="CONFIGURED", evidence_ids=[],
                               validated_at="2026-11-08", validator="qa")
        with pytest.raises(ValueError, match="does not validate its own"):
            validate_migration(asset="app-1", claimed_state=VALIDATED,
                               before_state="CONFIGURED", evidence_ids=["V-1"],
                               validated_at="2026-11-08", validator="")
        with pytest.raises(ValueError, match="no change to validate"):
            validate_migration(asset="app-1", claimed_state=VALIDATED,
                               before_state=VALIDATED, evidence_ids=["V-1"],
                               validated_at="2026-11-08", validator="qa")
        ok = validate_migration(asset="app-1", claimed_state=VALIDATED,
                                before_state="CONFIGURED",
                                evidence_ids=["POST-RUN-1"],
                                validated_at="2026-11-08", validator="qa")
        assert ok["claimed_state"] == VALIDATED


class TestGates:

    def test_no_evidence_is_never_a_pass(self):
        report = gates_status([])
        assert report["counts"][NOT_PASSED] == 12
        assert report["pilot_ready"] is False
        assert "not passed" in report["gates"][RECOVERY]["reason"]

    def test_an_external_gate_is_never_passed_by_the_platform_or_synthetic_data(self):
        with pytest.raises(ValueError, match="cannot be the performer"):
            file_gate_evidence(gate=RECOVERY, evidence_ids=["R-1"],
                               performed_by="CryptoScan",
                               performed_at="2026-11-08")
        with pytest.raises(ValueError, match="synthetic drill is not"):
            file_gate_evidence(gate=COLLECTOR_QUALIFICATION, evidence_ids=["Q-1"],
                               performed_by="qa team",
                               performed_at="2026-11-08", synthetic=True)

    def test_a_filed_gate_passes_and_a_failing_result_does_not(self):
        passed = file_gate_evidence(
            gate="TENANT_SECURITY", evidence_ids=["CROSS-TENANT-1"],
            performed_by="qa team", performed_at="2026-11-08")
        report = gates_status([passed])
        assert report["gates"]["TENANT_SECURITY"]["status"] == PASSED
        assert report["gates"][RECOVERY]["status"] == NOT_PASSED

        failed = file_gate_evidence(
            gate="TENANT_SECURITY", evidence_ids=["CROSS-TENANT-2"],
            performed_by="qa team", performed_at="2026-11-09",
            result=NOT_PASSED)
        report = gates_status([passed, failed])
        assert report["gates"]["TENANT_SECURITY"]["status"] == NOT_PASSED
        assert "latest result is NOT_PASSED" in \
            report["gates"]["TENANT_SECURITY"]["reason"]

    def test_in_repo_synthetic_evidence_stays_labelled(self):
        synthetic = file_gate_evidence(
            gate="DIGITAL_TWIN", evidence_ids=["TWIN-REPLAY-1"],
            performed_by="qa team", performed_at="2026-11-08", synthetic=True)
        report = gates_status([synthetic])
        entry = report["gates"]["DIGITAL_TWIN"]
        assert entry["synthetic_only"] is True
        assert "labelled synthetic" in entry["reason"]
