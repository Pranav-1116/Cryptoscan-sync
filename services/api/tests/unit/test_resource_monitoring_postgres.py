"""Owned PostgreSQL admission/withdrawal races and audit transactions, not production qualification."""

from concurrent.futures import ThreadPoolExecutor
import pytest
from test_assurance_workflows import assured as assured, admin
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from db.models.assurance import AssuranceRevision
from db.models.user import AuditLog
from db.repositories.user_repository import verify_audit_chain
from shared_models.host_collection import digest
from api.assurance import resource_monitoring as core
import test_resource_monitoring_api as contracts


@pytest.mark.parametrize("action", ["capture.intake", "traffic.propose"])
def test_postgres_resource_audit_rollback(assured, monkeypatch, action):
    contracts.test_audit_failure_rolls_back_resource_mutation(assured, monkeypatch, action)


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_postgres_resource_exact_estate(assured, monkeypatch, who):
    contracts.test_exact_estate_hides_plans_captures_proposals(assured, monkeypatch, who)


@pytest.mark.parametrize("target", ["capture", "proposal"])
def test_postgres_resource_source_recomputation(assured, monkeypatch, target):
    contracts.test_resealed_view_changes_fail_recomputation(assured, monkeypatch, target)


def test_postgres_resource_duplicate_capture_commits_once(assured, monkeypatch):
    clients, db, _, _, _, body = contracts.submitted(assured, monkeypatch)
    body["capture"]["capture_id"] = "22222222-2222-2222-2222-222222222222"
    body["expected_capture_sha256"] = digest(body["capture"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: clients["bank_a"].post(contracts.P + "/captures", json=body), range(2)))
    assert sorted(r.status_code for r in responses) == [201, 409]
    assert db.query(AssuranceRevision).filter_by(kind=core.CAPTURE).count() == 2
    assert db.query(AuditLog).filter_by(action="collection.resource.capture.intake").count() == 2
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("operation", ["capture", "proposal"])
def test_postgres_resource_revocation_serializes_new_work(assured, monkeypatch, operation):
    clients, db, auth, _, row, body = contracts.submitted(assured, monkeypatch)
    if operation == "capture":
        body["capture"]["capture_id"] = "22222222-2222-2222-2222-222222222222"
        body["expected_capture_sha256"] = digest(body["capture"])
        path = "/captures"
        kind = core.CAPTURE
        base = 1
        action = "capture.intake"
    else:
        body = contracts.proposal_body(row)
        path = "/traffic-proposals"
        kind = core.PROPOSAL
        base = 0
        action = "traffic.propose"
    with ThreadPoolExecutor(max_workers=2) as pool:
        submitted = pool.submit(clients["bank_a"].post, contracts.P + path, json=body)
        revoked = pool.submit(
            admin(clients).post, contracts.P + f"/plans/{auth.plan_id}/revoke", json=contracts.decision(2)
        )
        result, withdrawal = submitted.result(), revoked.result()
    assert withdrawal.status_code == 200, withdrawal.text
    assert result.status_code in {201, 409}, result.text
    assert db.query(AssuranceRevision).filter_by(kind=kind).count() == base + (result.status_code == 201)
    if result.status_code == 201:
        before = (
            db.query(AuditLog)
            .filter_by(action="collection.resource." + action)
            .order_by(AuditLog.chain_sequence.desc())
            .first()
        )
        after = db.query(AuditLog).filter_by(action="collection.resource.plan.revoke").one()
        assert before.chain_sequence < after.chain_sequence
    assert verify_audit_chain(db)["status"] == "OK"
