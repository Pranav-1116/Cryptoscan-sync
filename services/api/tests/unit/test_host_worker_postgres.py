"""Owned PostgreSQL only: actual concurrent claims/finalization and audit rollback."""

import secrets
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_host_worker as contracts
from api.assurance import host_worker, collection as core
from db.tenancy import tenant_scope
from db.models.assurance import AssuranceBlob
from db.models.scan import Scan
from db.repositories.user_repository import verify_audit_chain, UserRepository
from inventory.isolation import collect_isolated
from shared_models.collection import TargetSpec


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_local_worker_exact_verified_stage_external_signer_original_intake_and_six_boms,
        contracts.test_enqueue_cancel_rbac_cross_tenant_and_current_revision,
        contracts.test_claim_no_takeover_wrong_token_checkpoint_and_completion_cancellation,
    ],
)
def test_postgres_worker(assured, contract):
    contract(assured)


@pytest.mark.parametrize(
    "change",
    [
        "revoked",
        "role",
        "membership",
        "tenant-status",
        "environment",
        "user-disabled",
        "credential-revoked",
        "credential-expired",
        "stop",
        "policy-exclusion",
        "environment-stop",
    ],
)
def test_postgres_fresh_admission(assured, change):
    contracts.test_fresh_admission_refuses_revoked_queued_work(assured, change)


def test_concurrent_claims_commit_exactly_one_attempt(assured):
    clients, db, _, _, job, binding, _, _, _, _ = contracts.queued(assured)
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)

    def attempt(_):
        with tenant_scope("a"), factory() as session:
            try:
                host_worker.claim(session, binding, job["subject_id"], secrets.token_hex(32))
                return 200
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(attempt, range(2)))
    assert sorted(statuses) == [200, 409]
    assert verify_audit_chain(db)["status"] == "OK"
    with tenant_scope("a"):
        assert core.chain(db, "a", core.JOB, job["subject_id"])[-1].revision == 3


def test_cancel_and_finish_share_actual_target_mutex(assured):
    clients, db, body, _, job, binding, _, _, _, _ = contracts.queued(assured)
    token = secrets.token_hex(32)
    jid = job["subject_id"]
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    with tenant_scope("a"):
        host_worker.claim(db, binding, jid, token)
    snapshot, report = collect_isolated(TargetSpec.model_validate(body))

    def finish():
        with tenant_scope("a"), factory() as session:
            try:
                return host_worker.finish(
                    session, binding, jid, token, snapshot, report, {"source_lock_sha256": binding.source_lock_sha256}
                )
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        final = pool.submit(finish)
        cancel = pool.submit(
            lambda: clients["bank_a"].post(contracts.P + f"/jobs/{jid}/cancel", json=contracts.decision(3))
        )
        result, response = final.result(), cancel.result()
    assert (isinstance(result, dict) and response.status_code == 409) or (result == 409 and response.status_code == 200)
    with tenant_scope("a"):
        row = core.chain(db, "a", core.JOB, jid)[-1]
        assert row.payload["state"] in {"AWAITING_EVIDENCE", "CANCELLED"}
        assert db.query(AssuranceBlob).count() == (1 if row.payload["state"] == "AWAITING_EVIDENCE" else 0)
    assert verify_audit_chain(db)["status"] == "OK" and db.query(Scan).count() == 0


def test_worker_result_and_audit_are_one_transaction(assured, monkeypatch):
    _, db, body, _, job, binding, _, _, _, _ = contracts.queued(assured)
    token = secrets.token_hex(32)
    jid = job["subject_id"]
    with tenant_scope("a"):
        host_worker.claim(db, binding, jid, token)
    snapshot, report = collect_isolated(TargetSpec.model_validate(body))
    original = UserRepository.audit

    def fail(self, user, action, **kw):
        if action == "collection.worker.collected":
            raise RuntimeError("owned audit failure")
        return original(self, user, action, **kw)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with tenant_scope("a"), pytest.raises(RuntimeError):
        host_worker.finish(
            db, binding, jid, token, snapshot, report, {"source_lock_sha256": binding.source_lock_sha256}
        )
    with tenant_scope("a"):
        assert core.chain(db, "a", core.JOB, jid)[-1].payload["state"] == "RUNNING"
        assert db.query(AssuranceBlob).count() == 0
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("state", ["QUEUED", "RUNNING", "CANCELLED", "REFUSED", "AWAITING_EVIDENCE"])
def test_postgres_signer_does_not_bypass_worker_result(assured, state):
    contracts.test_trusted_signature_cannot_bypass_exact_worker_result(assured, state)
