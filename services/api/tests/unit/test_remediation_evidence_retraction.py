"""Current source-condition proofs must not consume withdrawn observations.

Authenticated SQLite/API fixtures, not PostgreSQL isolation or site qualification.
"""
from copy import deepcopy
from datetime import timedelta

import pytest

from api.assurance import store
from db.models.base import utcnow
from db.models.evidence_record import EvidenceRecord
from db.models.remediation_task import RemediationTask
from test_assurance_workflows import (
    P, admin, approval, assured as assured, banks as banks, done, new_scan,
)
from test_operator_decisions import check, reported, source_job
from test_launch_readiness import P as LAUNCH, pilot_setup as pilot_setup, ssh as ssh


@pytest.fixture()
def condition(assured):
    clients, db, _ = assured
    before = new_scan(db, algorithms=("MD5", "SHA1"))
    source_job(db, before)
    original, other = db.query(EvidenceRecord).filter_by(scan_id=before.id).order_by(EvidenceRecord.chain_position).all()
    original.compliance_status, other.compliance_status = "FAIL", "PASS"
    db.commit()
    task = done(clients["bank_a"].post(P + "/remediation-tasks", json={
        "evidence_id": original.id, "owner_ref": "payments"}))
    return {"clients": clients, "db": db, "original": original, "before_other": other, "task": task,
            "body": {"kind": "SOURCE_SITE", "owner_ref": "payments", "task_id": task["id"],
                "change_ref": "synthetic/withdrawal-check", "expected_algorithm": "SHA-256",
                "verification_criteria": "Compliant replacement at the exact original site",
                "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}}


def propose(case):
    row = done(case["clients"]["bank_a"].post(P + "/remediation-changes", json=case["body"]))
    case["identifier"] = row["subject_id"]
    return row


def approve(case):
    return done(admin(case["clients"]).post(P + f"/remediation-changes/{case['identifier']}/approve", json=approval()))


def prepare(case):
    propose(case)
    approve(case)
    reported(case["clients"], case["identifier"])
    after = new_scan(case["db"], algorithms=("SHA-256", "SHA-512"), start=utcnow() - timedelta(milliseconds=1))
    source_job(case["db"], after)
    replacement, other = case["db"].query(EvidenceRecord).filter_by(scan_id=after.id).order_by(EvidenceRecord.chain_position).all()
    replacement.compliance_status = other.compliance_status = "PASS"
    after.statistics = {**after.statistics, "file_observation_receipts": [
        {"file": "crypto.py", "sha256": "f" * 64, "parser_completed": True}]}
    case["db"].commit()
    case.update(after=after, replacement=replacement, after_other=other)


def retract(case, row, owner="a"):
    before = (row.content_hash, row.chain_hash, row.finding_data)
    result = done(admin(case["clients"], owner).post(f"/api/v1/findings/{row.id}/soft-delete", json={
        "reason": "Synthetic observation withdrawal; not current verification evidence"}), 200)
    case["db"].refresh(row)
    assert row.deleted_at and result["deleted_at"]
    assert (row.content_hash, row.chain_hash, row.finding_data) == before


def history(case):
    identifier = case["identifier"]
    return deepcopy(done(admin(case["clients"]).get(P + f"/records/remediation_change/{identifier}"), 200))


def inbox(case):
    return done(admin(case["clients"]).get(P + "/operator-decisions"), 200)["sections"]


def verify(case):
    return check(case["clients"], case["identifier"], case["after"])


def test_retracted_baseline_cannot_seed_a_new_change(condition):
    case = condition
    retract(case, case["original"])
    response = case["clients"]["bank_a"].post(P + "/remediation-changes", json=case["body"])
    assert response.status_code == 409, response.text
    assert store.latest(case["db"], "a", "remediation_change", "absent", required=False) is None
    from db.models.assurance import AssuranceRevision
    assert case["db"].query(AssuranceRevision).filter_by(kind="remediation_change").count() == 0


@pytest.mark.parametrize("stage", ["approve", "report"])
def test_withdrawn_baseline_blocks_next_authorized_transition(condition, stage):
    case = condition
    propose(case)
    if stage == "report":
        approve(case)
    before = history(case)
    retract(case, case["original"])
    if stage == "approve":
        response = admin(case["clients"]).post(P + f"/remediation-changes/{case['identifier']}/approve", json=approval())
    else:
        response = case["clients"]["bank_a"].post(P + f"/remediation-changes/{case['identifier']}/report-complete", json={
            "expected_revision": 2, "completed_at": utcnow().isoformat(), "evidence_ref": "synthetic/action"})
    assert response.status_code == 409, response.text
    assert history(case) == before


@pytest.mark.parametrize("target", ["original", "replacement"])
def test_withdrawn_observation_cannot_create_a_verified_proof(condition, target):
    case = condition
    prepare(case)
    retract(case, case[target])
    proof = verify(case)
    assert proof["payload"]["result"] == "INCONCLUSIVE", proof
    sections = inbox(case)
    assert sections["tasks"]["items"][0]["current_condition_verified"] is False
    assert sections["proofs"]["items"][0]["freshness_state"] == "STALE_OR_UNAVAILABLE"


@pytest.mark.parametrize("target", ["original", "replacement"])
def test_withdrawal_invalidates_current_read_and_audited_restore_preserves_history(condition, target):
    case = condition
    prepare(case)
    proof = verify(case)
    assert proof["payload"]["result"] == "VERIFIED"
    before = history(case)
    proof_history = done(admin(case["clients"]).get(P + f"/records/condition_proof/{proof['subject_id']}"), 200)
    retract(case, case[target])
    sections = inbox(case)
    task = sections["tasks"]["items"][0]
    assert task["current_condition_verified"] is False and task["needs_attention"] is True
    assert task["status"] == "VERIFIED"  # Historical label is not silently rewritten on GET.
    assert sections["proofs"]["items"][0]["result"] == "VERIFIED"
    assert sections["proofs"]["items"][0]["freshness_state"] == "STALE_OR_UNAVAILABLE"
    assert history(case) == before
    assert done(admin(case["clients"]).get(P + f"/records/condition_proof/{proof['subject_id']}"), 200) == proof_history
    done(admin(case["clients"]).post(f"/api/v1/findings/{case[target].id}/restore"), 200)
    restored = inbox(case)
    assert restored["tasks"]["items"][0]["current_condition_verified"] is True
    assert restored["proofs"]["items"][0]["freshness_state"] == "WITHIN_APPROVED_WINDOW"
    assert history(case) == before
    assert done(admin(case["clients"]).get(P + f"/records/condition_proof/{proof['subject_id']}"), 200) == proof_history


@pytest.mark.parametrize("target", ["before_other", "after_other"])
def test_withdrawn_comparison_member_is_not_silently_removed_as_clean_absence(condition, target):
    case = condition
    prepare(case)
    retract(case, case[target])
    assert verify(case)["payload"]["result"] == "INCONCLUSIVE"


def test_denied_and_foreign_retraction_do_not_change_current_proof(condition):
    case = condition
    prepare(case)
    assert verify(case)["payload"]["result"] == "VERIFIED"
    path = f"/api/v1/findings/{case['replacement'].id}/soft-delete"
    for client, status in [(case["clients"]["reader_a"], 403), (admin(case["clients"], "b"), 404)]:
        response = client.post(path, json={"reason": "Synthetic forbidden withdrawal"})
        assert response.status_code == status, response.text
    assert inbox(case)["tasks"]["items"][0]["current_condition_verified"] is True


def test_other_estate_withdrawal_does_not_invalidate_own_proof(condition):
    case = condition
    prepare(case)
    assert verify(case)["payload"]["result"] == "VERIFIED"
    foreign_scan = new_scan(case["db"], owner="b")
    foreign = case["db"].query(EvidenceRecord).filter_by(scan_id=foreign_scan.id).one()
    retract(case, foreign, owner="b")
    assert inbox(case)["tasks"]["items"][0]["current_condition_verified"] is True


@pytest.mark.parametrize("target", ["original", "replacement"])
def test_reverification_retains_old_proof_but_cannot_repeat_verified_after_withdrawal(condition, target):
    case = condition
    prepare(case)
    first = verify(case)
    assert first["payload"]["result"] == "VERIFIED"
    # Compare the same persisted GET projection: SQLite reloads DateTime without
    # the creation response's UTC offset. This must not mask payload/hash changes.
    retained = done(admin(case["clients"]).get(P + f"/records/condition_proof/{first['subject_id']}"), 200)["revisions"][0]
    retract(case, case[target])
    second = verify(case)
    assert second["payload"]["result"] == "INCONCLUSIVE"
    revisions = done(admin(case["clients"]).get(P + f"/records/condition_proof/{first['subject_id']}"), 200)["revisions"]
    assert len(revisions) == 2 and revisions[0] == retained
    assert inbox(case)["tasks"]["items"][0]["current_condition_verified"] is False


def test_withdrawal_during_comparison_is_rechecked_before_positive_proof(condition, monkeypatch):
    case = condition
    prepare(case)
    import remediation.verification as comparison
    original = comparison.verify_remediation
    def withdraw(*args, **kwargs):
        verdict = original(*args, **kwargs)
        assert verdict["result"] == "VERIFIED"
        # Explicit single-session boundary injection, NOT a PostgreSQL race drill.
        case["replacement"].deleted_at = utcnow()
        case["db"].commit()
        return verdict
    monkeypatch.setattr(comparison, "verify_remediation", withdraw)
    proof = verify(case)
    assert proof["payload"]["result"] == "INCONCLUSIVE"
    case["db"].refresh(case["replacement"])
    assert case["replacement"].deleted_at
    task = case["db"].get(RemediationTask, case["task"]["id"])
    assert task.status != "VERIFIED"


@pytest.mark.parametrize("target", ["original", "replacement"])
def test_pilot_gate_also_rechecks_withdrawn_source_proof(pilot_setup, target):
    clients, db, body, _ = pilot_setup
    original = db.query(EvidenceRecord).filter_by(scan_id=body["source_scan_id"]).one()
    original.compliance_status = "FAIL"
    db.commit()
    task = done(clients["bank_a"].post(P + "/remediation-tasks", json={
        "evidence_id": original.id, "owner_ref": "payments"}))
    case = {"clients": clients, "db": db, "original": original, "task": task,
            "body": {"kind": "SOURCE_SITE", "owner_ref": "payments", "task_id": task["id"],
                "change_ref": "synthetic/source-pilot", "expected_algorithm": "SHA-256",
                "verification_criteria": "Compliant replacement at the exact original site",
                "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}}
    prepare(case)
    assert verify(case)["payload"]["result"] == "VERIFIED"
    pilot = done(clients["bank_a"].post(LAUNCH + "/pilots", json={
        **body, "remediation_change_id": case["identifier"]}))
    path = LAUNCH + f"/pilots/{pilot['subject_id']}"
    before = done(clients["bank_a"].get(path + "/status"), 200)
    issue = "CURRENT_INDEPENDENT_REMEDIATION_PROOF_MISSING"
    assert issue not in before["issues"]
    retained = done(clients["bank_a"].get(P + f"/records/customer_pilot/{pilot['subject_id']}"), 200)
    retract(case, case[target])
    status = done(clients["bank_a"].get(path + "/status"), 200)
    assert issue in status["issues"], status
    assert status["evidence_loop_ready"] is status["commercial_acceptance_current"] is False
    assert done(clients["bank_a"].get(P + f"/records/customer_pilot/{pilot['subject_id']}"), 200) == retained
