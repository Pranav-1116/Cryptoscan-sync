"""Owned PostgreSQL review/revocation serialization; synthetic preflight facts only."""

from concurrent.futures import ThreadPoolExecutor
import pytest
from test_assurance_workflows import assured as assured, admin
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from db.models.user import User, AuditLog
from db.models.assurance import AssuranceRevision
from db.repositories.user_repository import UserRepository, verify_audit_chain
from api.assurance import traffic_control as core
import test_traffic_control_api as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_preflight_review_export_is_namespace_only,
        contracts.test_revoked_source_blocks_review_but_preserves_historical_read,
        contracts.test_same_human_cannot_assign_self_as_reviewer,
    ],
)
def test_postgres_contract(assured, monkeypatch, contract):
    contract(assured, monkeypatch)


def proposed(assured, monkeypatch):
    clients, db, auth, _, row = contracts.prepared(assured, monkeypatch)
    reviewer = db.query(User).filter_by(username="platform_admin").one()
    body = {
        "preflight_id": row["subject_id"],
        "expected_preflight_record_sha256": row["payload_sha256"],
        "reviewer_user_id": reviewer.id,
        "duration_seconds": 1,
        "reason": "Exercise separate review races using synthetic local preflight",
    }
    result = clients["bank_a"].post(contracts.P + "/validations", json=body)
    assert result.status_code == 201, result.text
    decision = {
        "expected_revision": 1,
        "evidence_ref": "change/owned-postgres-drill",
        "reason": "Review only disposable namespace validation under live source approval",
    }
    return clients, db, auth, result.json()["subject_id"], decision


def test_postgres_duplicate_review_commits_once(assured, monkeypatch):
    clients, db, _, key, body = proposed(assured, monkeypatch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda _: admin(clients).post(contracts.P + f"/validations/{key}/approve", json=body), range(2))
        )
    assert sorted(r.status_code for r in results) == [200, 409]
    assert db.query(AuditLog).filter_by(action="collection.traffic.validation.approve").count() == 1
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_revocation_serializes_review(assured, monkeypatch):
    clients, db, auth, key, body = proposed(assured, monkeypatch)
    revoke = {**body, "expected_revision": 2}
    with ThreadPoolExecutor(max_workers=2) as pool:
        review = pool.submit(admin(clients).post, contracts.P + f"/validations/{key}/approve", json=body)
        withdrawal = pool.submit(
            admin(clients).post, f"/api/v1/resource-monitoring/plans/{auth.plan_id}/revoke", json=revoke
        )
        reviewed, revoked = review.result(), withdrawal.result()
    assert revoked.status_code == 200, revoked.text
    assert reviewed.status_code in {200, 409}, reviewed.text
    if reviewed.status_code == 200:
        before = db.query(AuditLog).filter_by(action="collection.traffic.validation.approve").one()
        after = db.query(AuditLog).filter_by(action="collection.resource.plan.revoke").one()
        assert before.chain_sequence < after.chain_sequence
    assert clients["reader_a"].get(contracts.P + f"/validations/{key}/authorization").status_code == 409
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_audit_failure_rolls_back_review(assured, monkeypatch):
    clients, db, _, key, body = proposed(assured, monkeypatch)
    original = UserRepository.audit

    def audit(self, username, action, *args, **kwargs):
        if action == "collection.traffic.validation.approve":
            raise RuntimeError("synthetic audit failure")
        return original(self, username, action, *args, **kwargs)

    monkeypatch.setattr(UserRepository, "audit", audit)
    with pytest.raises(RuntimeError, match="synthetic audit failure"):
        admin(clients).post(contracts.P + f"/validations/{key}/approve", json=body)
    assert db.query(AssuranceRevision).filter_by(kind=core.CHANGE, subject_id=key).count() == 1
    assert db.query(AuditLog).filter_by(action="collection.traffic.validation.approve").count() == 0
