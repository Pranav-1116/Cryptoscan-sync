"""Owned PostgreSQL pre-capture truth review and handoff serialization."""

from concurrent.futures import ThreadPoolExecutor
import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from db.models.user import AuditLog
from db.repositories.user_repository import verify_audit_chain
import test_oci_truth_api as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_precommit_separate_review_original_return_and_exact_reconciliation,
        contracts.test_unassigned_trust_user_cannot_review_and_pending_plan_blocks_handoff,
        contracts.test_truth_and_approval_are_write_once,
        contracts.test_reviewer_cannot_be_evidence_uploader,
        contracts.test_revoked_reviewer_authority_invalidates_qualification_not_original_evidence,
        contracts.test_missing_original_inputs_keep_unknown_counts_not_absence,
    ],
)
def test_postgres_truth_contract(assured, contract):
    contract(assured)


@pytest.mark.parametrize("action", ["truth.propose", "truth.approve"])
def test_postgres_truth_atomic_audit(assured, monkeypatch, action):
    contracts.test_truth_audit_failure_is_atomic(assured, monkeypatch, action)


def test_postgres_truth_approval_and_handoff_are_serialized(assured):
    clients, db, _, job, _, _ = contracts.planned(assured)
    path = contracts.P + f"/jobs/{job['subject_id']}"
    with ThreadPoolExecutor(max_workers=2) as pool:
        review = pool.submit(clients["reader_a"].post, path + "/truth/approve", json=contracts.existing.decision(1))
        handoff = pool.submit(clients["bank_a"].post, path + "/handoff", json={"expected_revision": 1})
        reviewed, handed = review.result(), handoff.result()
    assert reviewed.status_code == 200, reviewed.text
    assert handed.status_code in {200, 409}, handed.text
    if handed.status_code == 409:
        handed = clients["bank_a"].post(path + "/handoff", json={"expected_revision": 1})
        assert handed.status_code == 200, handed.text
    before = db.query(AuditLog).filter_by(action="collection.oci.truth.approve").one()
    after = db.query(AuditLog).filter_by(action="collection.oci.job.handoff").one()
    assert before.chain_sequence < after.chain_sequence
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_truth_duplicate_approval_has_one_winner(assured):
    clients, db, _, job, _, _ = contracts.planned(assured)
    path = contracts.P + f"/jobs/{job['subject_id']}/truth/approve"
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(
                lambda _: clients["reader_a"].post(path, json=contracts.existing.decision(1)).status_code, range(2)
            )
        )
    assert sorted(statuses) == [200, 409]
    assert db.query(AuditLog).filter_by(action="collection.oci.truth.approve").count() == 1
    assert verify_audit_chain(db)["status"] == "OK"
