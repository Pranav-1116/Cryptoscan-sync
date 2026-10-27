"""Owned PostgreSQL OCI intake/cancellation/revocation concurrency, never customer DB."""

from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from test_assurance_workflows import assured as assured, admin
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from db.models.assurance import AssuranceRevision
from db.models.user import AuditLog
from db.repositories.user_repository import verify_audit_chain
from db.tenancy import tenant_scope
from api.assurance.oci_collection import lock_target
import test_oci_collection_api as contracts


@pytest.mark.parametrize("outcome", ["COMPLETED", "PARTIAL", "FAILED"])
def test_postgres_oci_real_capture_and_projections(assured, outcome):
    contracts.test_real_offline_capture_to_committed_evidence_and_six_views(assured, outcome)


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_postgres_oci_exact_estate(assured, who):
    contracts.test_exact_estate_hides_all_oci_records(assured, who)


@pytest.mark.parametrize("change", ["revoke", "update", "expire", "system_environment"])
def test_postgres_oci_current_authority(assured, monkeypatch, change):
    contracts.test_current_authority_is_revalidated_at_intake(assured, monkeypatch, change)


@pytest.mark.parametrize("action", ["evidence.consume", "evidence.intake", "job.complete"])
def test_postgres_oci_atomic_audit(assured, monkeypatch, action):
    contracts.test_intake_and_audit_rollback_as_one_transaction(assured, monkeypatch, action)


def test_postgres_oci_duplicate_return_commits_once(assured):
    clients, db, target, _, job = contracts.prepare(assured)
    value = contracts.capture(target, job)
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: contracts.submit(clients, target, job, value).status_code, range(2)))
    assert sorted(statuses) == [201, 409]
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_evidence").count() == 1
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_consumed").count() == 1
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("withdrawal", ["revoke", "update", "cancel"])
def test_postgres_oci_intake_and_withdrawal_are_serialized(assured, withdrawal):
    clients, db, target, auth, job = contracts.prepare(assured)
    value = contracts.capture(target, job)

    def withdraw():
        if withdrawal == "revoke":
            return admin(clients).post(
                contracts.P + f"/targets/{auth['subject_id']}/revoke", json=contracts.decision(2)
            )
        if withdrawal == "update":
            return admin(clients).put(
                contracts.P + f"/targets/{auth['subject_id']}",
                json={"expected_revision": 2, "target": target.model_dump(mode="json")},
            )
        return clients["bank_a"].post(contracts.P + f"/jobs/{job['subject_id']}/cancel", json={"expected_revision": 2})

    with ThreadPoolExecutor(max_workers=2) as pool:
        submit = pool.submit(contracts.submit, clients, target, job, value)
        withdraw = pool.submit(withdraw)
        intake, withdrawn = submit.result(), withdraw.result()
    assert intake.status_code in {201, 409}, intake.text
    assert withdrawn.status_code == 200 or (
        withdrawal == "cancel" and intake.status_code == 201 and withdrawn.status_code == 409
    ), withdrawn.text
    count = db.query(AssuranceRevision).filter_by(kind="oci_collection_evidence").count()
    assert count == (1 if intake.status_code == 201 else 0)
    if intake.status_code == 201 and withdrawal != "cancel":
        before = db.query(AuditLog).filter_by(action="collection.oci.job.complete").one()
        after = (
            db.query(AuditLog)
            .filter_by(action="collection.oci.target." + ("revoke" if withdrawal == "revoke" else "register"))
            .order_by(AuditLog.chain_sequence.desc())
            .first()
        )
        assert before.chain_sequence < after.chain_sequence
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_oci_target_mutex_is_real_row_lock(assured):
    _, db, _, auth, _ = contracts.prepare(assured)
    with tenant_scope("a"):
        lock_target(db, "a", auth["subject_id"])
    with db.bind.connect() as other:
        other.execute(text("SET LOCAL lock_timeout='100ms'"))
        with pytest.raises(OperationalError) as failure:
            other.execute(
                text(
                    "UPDATE assurance_revisions SET updated_at=NOW() WHERE kind='oci_collection_target' AND subject_id=:id AND revision=1"
                ),
                {"id": auth["subject_id"]},
            )
        assert failure.value.orig.pgcode == "55P03"
        other.rollback()
    db.rollback()
