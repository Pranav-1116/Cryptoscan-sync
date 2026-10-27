"""Owned PostgreSQL replay of host associations, including real concurrency."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from test_ssh_receipt_contract import ssh as ssh
import test_host_associations as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_no_relationships_from_coexistence_and_pending_is_not_a_graph_edge,
        contracts.test_all_six_boms_are_connected_only_by_explicit_reviewed_associations,
        contracts.test_scope_ownership_and_generic_approval_cannot_bypass_host_adapter,
        contracts.test_retraction_and_stale_revision_do_not_delete_provenance,
        contracts.test_host_input_reference_ids_are_unambiguous,
        contracts.test_pending_retraction_retains_the_original_proposer,
    ],
)
def test_postgres_graph_contract(assured, contract):
    contract(assured)


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_postgres_reader_boundary(assured, role):
    contracts.test_readers_cannot_propose_review_retract_or_modify_scans(assured, role)


@pytest.mark.parametrize(
    "change", ["fingerprint", "expired", "foreign", "hardware_claim", "vendor_claim", "target_deleted"]
)
def test_postgres_stale_target(assured, change):
    contracts.test_stale_target_removes_only_reviewed_association_not_history(assured, change)


@pytest.mark.parametrize("change", ["host_content", "association_hash", "missing_predecessor", "history_budget"])
def test_postgres_integrity(assured, change, monkeypatch):
    contracts.test_graph_fails_closed_on_integrity_or_budget_failure(assured, change, monkeypatch)


@pytest.mark.parametrize("change", ["target_changed", "role_revoked", "audit_failure", "source_changed"])
def test_postgres_current_review(assured, monkeypatch, change):
    contracts.test_review_revalidates_current_authority_and_source_atomically(assured, monkeypatch, change)


@pytest.mark.parametrize("change", ["audit_deleted", "audit_changed", "retraction_tail_deleted"])
def test_postgres_audit_closure(assured, change):
    contracts.test_audit_commitment_detects_missing_or_changed_history(assured, change)


@pytest.mark.parametrize(
    "change", ["wrong_package", "wrong_environment", "retracted_deployment", "binding_hash", "original_bytes"]
)
def test_postgres_sbom_closure(assured, monkeypatch, change):
    contracts.test_exact_sbom_and_deployment_closure_are_reopened(assured, monkeypatch, change)


@pytest.mark.parametrize(
    "change", ["unsupported_phase", "old_observation", "missing_time", "no_keys", "endpoint_mismatch"]
)
def test_postgres_unknown_network(assured, change):
    contracts.test_unsupported_stale_or_incomplete_network_metadata_stays_unresolved(assured, change)


def test_postgres_audit_failure(assured, monkeypatch):
    contracts.test_association_audit_failure_is_atomic(assured, monkeypatch)


def test_postgres_real_ssh_producer(assured, ssh):
    contracts.test_real_ssh_receipt_producer_can_be_associated_without_claiming_endpoint_identity(assured, ssh)


def test_postgres_complete_byte_budget(assured, monkeypatch):
    contracts.test_complete_projection_byte_budget_is_an_explicit_refusal(assured, monkeypatch)


def test_postgres_concurrent_reviews_commit_exactly_once(assured):
    from concurrent.futures import ThreadPoolExecutor
    from db.models.assurance import AssuranceRevision
    from db.repositories.user_repository import verify_audit_chain

    clients, db, identifier, targets = contracts.ready(assured)
    row = contracts.create(
        clients, identifier, contracts.proposal(clients, identifier, "hardware", targets["hardware"])
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: contracts.decide(clients, identifier, row).status_code, range(2)))
    assert sorted(statuses) == [200, 409]
    assert db.query(AssuranceRevision).filter_by(kind="bom_relationship").count() == 2
    assert verify_audit_chain(db)["status"] == "OK"
    assert contracts.graph(clients["reader_a"], identifier).status_code == 200


def test_postgres_scope_lock_serializes_association_count(assured, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from db.models.assurance import AssuranceRevision
    from api.assurance import host_associations

    clients, db, identifier, targets = contracts.ready(assured)
    bodies = [contracts.proposal(clients, identifier, t, targets[t]) for t in ("hardware", "vendor")]
    monkeypatch.setattr(host_associations, "MAX_ASSOCIATIONS", 1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(
                lambda b: clients["bank_a"].post(contracts.path(identifier) + "/associations", json=b).status_code,
                bodies,
            )
        )
    assert sorted(statuses) == [201, 409]
    assert db.query(AssuranceRevision).filter_by(kind="bom_relationship").count() == 1
    assert contracts.graph(clients["reader_a"], identifier).status_code == 200
