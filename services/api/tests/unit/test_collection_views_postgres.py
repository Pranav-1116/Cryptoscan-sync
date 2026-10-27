"""Owned PostgreSQL snapshots/drift, audit atomicity and unique-writer races."""

from concurrent.futures import ThreadPoolExecutor
import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from db.models.assurance import AssuranceRevision
from db.repositories.user_repository import verify_audit_chain
import test_collection_views_api as contracts
import test_oci_collection_api as oci


@pytest.mark.parametrize("family", ["host", "oci"])
def test_postgres_original_source_six_views_graph(assured, monkeypatch, family):
    contracts.test_snapshot_is_durable_six_view_graph_over_original_source_without_execution(
        assured, monkeypatch, family
    )


@pytest.mark.parametrize("case", ["version", "gap", "scope"])
def test_postgres_successive_image_drift(assured, case):
    contracts.test_successive_oci_images_retain_slots_but_distinguish_changes_gaps_and_scope(assured, case)


@pytest.mark.parametrize("kind", ["snapshot", "metadata-drift"])
def test_postgres_audit_transaction_rollback(assured, monkeypatch, kind):
    contracts.test_materialization_and_audit_rollback_together(assured, monkeypatch, kind)


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_postgres_exact_selected_estate(assured, who):
    contracts.test_other_estates_cannot_read_or_reference_snapshots_or_drift(assured, who)


@pytest.mark.parametrize("change", ["graph", "source", "drift"])
def test_postgres_resealed_tamper_detection(assured, change):
    contracts.test_resealed_tampering_is_recomputed_against_original_closure(assured, change)


def test_postgres_duplicate_snapshot_commits_one_record_and_audit(assured):
    clients, db, _, _, job = oci.complete(assured)
    body = contracts.request_for(clients, "oci", job)
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: clients["bank_a"].post(contracts.P + "/snapshots", json=body), range(2)))
    assert sorted(r.status_code for r in responses) == [201, 409]
    assert db.query(AssuranceRevision).filter_by(kind="collection_snapshot").count() == 1
    from db.models.user import AuditLog

    assert db.query(AuditLog).filter_by(action="collection.snapshot.create").count() == 1
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_duplicate_drift_commits_one_record_and_audit(assured):
    clients, db, first, latest = contracts.pair(assured)
    body = {"baseline_snapshot_id": first["subject_id"], "candidate_snapshot_id": latest["subject_id"]}
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(lambda _: clients["bank_a"].post(contracts.P + "/metadata-drift", json=body), range(2))
        )
    assert sorted(r.status_code for r in responses) == [201, 409]
    assert db.query(AssuranceRevision).filter_by(kind="collection_metadata_drift").count() == 1
    from db.models.user import AuditLog

    assert db.query(AuditLog).filter_by(action="collection.metadata-drift.create").count() == 1
    assert verify_audit_chain(db)["status"] == "OK"
