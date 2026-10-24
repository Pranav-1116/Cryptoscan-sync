"""Explicitly owned PostgreSQL foundation/Phase 2 witnesses, no customer DB."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_collection_foundation as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_phase_one_end_to_end_single_evidence_source_and_six_projections,
        contracts.test_historical_envelope_remains_inspectable_after_revoke,
        contracts.test_stable_target_identity_updates_require_fresh_authorization,
        contracts.test_changed_source_or_revision_is_never_silently_reprojected,
        contracts.test_phase_two_linux_os_metadata_joins_same_envelope_and_not_crypto,
        contracts.test_software_metadata_slot_is_stable_across_versioned_collection_history,
        contracts.test_failed_collection_is_not_an_empty_success_or_asset_absence,
        contracts.test_phase_two_native_runtime_one_intake_and_supported_domain_projections,
    ],
)
def test_postgres_foundation(assured, contract):
    contract(assured)


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_postgres_roles(assured, role):
    contracts.test_readers_inspect_but_cannot_change_registry_or_jobs(assured, role)


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_postgres_exact_scope(assured, who):
    contracts.test_exact_estate_even_for_unselected_platform_admin(assured, who)


@pytest.mark.parametrize("change", ["revoke", "update"])
def test_postgres_registry_cannot_be_bypassed(assured, change):
    contracts.test_revocation_or_scope_update_blocks_old_handoff_and_legacy_intake(assured, change)


@pytest.mark.parametrize("action", ["target.register", "target.authorize", "job.complete"])
def test_postgres_atomic_audit(assured, monkeypatch, action):
    contracts.test_atomic_audit_failure_never_leaves_partial_control_transition(assured, monkeypatch, action)


def test_postgres_duplicate_job_consumption_commits_once(assured):
    from concurrent.futures import ThreadPoolExecutor
    from db.models.assurance import AssuranceRevision
    from db.repositories.user_repository import verify_audit_chain

    clients, db, body, auth, job = contracts.prepared(assured)
    jid = job["subject_id"]
    assert (
        clients["bank_a"].post(contracts.P + f"/jobs/{jid}/handoff", json={"expected_revision": 1}).status_code == 200
    )
    assert contracts.imported(clients, body, auth).status_code == 201
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(
                lambda _: (
                    clients["bank_a"]
                    .post(contracts.P + f"/jobs/{jid}/complete", json={"expected_revision": 2})
                    .status_code
                ),
                range(2),
            )
        )
    assert sorted(statuses) == [200, 409]
    assert db.query(AssuranceRevision).filter_by(kind="collection_job", subject_id=jid).count() == 3
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_revoke_and_ingestion_are_serialized(assured):
    from concurrent.futures import ThreadPoolExecutor
    from db.models.user import AuditLog
    from db.models.scan import Scan

    clients, db, body, auth, job = contracts.prepared(assured)
    tid = auth["subject_id"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        importing = pool.submit(contracts.imported, clients, body, auth)
        revoking = pool.submit(
            lambda: admin(clients).post(contracts.P + f"/targets/{tid}/revoke", json=contracts.decision(2))
        )
        intake, revoke = importing.result(), revoking.result()
    assert revoke.status_code == 200, revoke.text
    assert intake.status_code in {201, 409}, intake.text
    if intake.status_code == 201:
        source = db.query(AuditLog).filter_by(action="host.intake").one()
        withdrawal = db.query(AuditLog).filter_by(action="collection.target.revoke").one()
        assert source.chain_sequence < withdrawal.chain_sequence
    else:
        assert db.query(Scan).count() == 0


def test_postgres_admission_mutex_is_a_real_row_lock(assured):
    from sqlalchemy import text
    from sqlalchemy.exc import OperationalError
    from api.assurance.collection import lock_target
    from db.tenancy import tenant_scope

    clients, db, body, auth, job = contracts.prepared(assured)
    with tenant_scope("a"):
        lock_target(db, "a", auth["subject_id"])
    with db.bind.connect() as other:
        other.execute(text("SET LOCAL lock_timeout='100ms'"))
        with pytest.raises(OperationalError) as failure:
            other.execute(
                text(
                    "UPDATE assurance_revisions SET updated_at=NOW() WHERE kind='collection_target' AND subject_id=:id AND revision=1"
                ),
                {"id": auth["subject_id"]},
            )
        assert failure.value.orig.pgcode == "55P03"
        other.rollback()
    db.rollback()
