"""Owned disposable PostgreSQL: same contracts plus actual competing row locks."""

from concurrent.futures import ThreadPoolExecutor
import pytest
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from fastapi import HTTPException
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
from test_qualification_workflow import people as people
import test_qualification_workflow as contracts
from api.assurance import qualification as core
from db.models.assurance import AssuranceBlob
from db.tenancy import tenant_scope
from db.repositories.user_repository import verify_audit_chain
from shared_models.qualification_workflow import SubmitReview


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_actual_users_original_bytes_two_separate_external_signatures_no_dispatch,
        contracts.test_unassigned_pending_no_people_or_execution_invented,
        contracts.test_missing_originals_and_native_gaps_cannot_freeze,
        contracts.test_signed_rejection_retained_and_cannot_be_overwritten,
        contracts.test_frozen_assignments_originals_withdrawal_and_rbac,
        contracts.test_original_tamper_never_remains_verified,
        contracts.test_channel_reference_required_and_never_inferred_from_endpoint,
    ],
)
def test_postgres_public_intake_and_external_decisions(people, contract):
    contract(people)


def test_postgres_blob_revision_audit_atomic_rollback(people, monkeypatch):
    contracts.test_blob_and_audit_publication_roll_back_atomically(people, monkeypatch)


@pytest.mark.parametrize("change", ["role", "membership", "user-disabled", "review-expiry"])
def test_postgres_live_status(people, monkeypatch, change):
    contracts.test_live_status_rechecks_authority_and_expiry(people, monkeypatch, change)


def test_postgres_competing_originals_one_expected_revision_one_blob(people):
    clients, db, identifier, value, _, _, _, _, _, assignments = contracts.created(people)
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    revision = value["record"]["revision"]
    actor = assignments["verifier"]["user_id"]

    def intake(n):
        with tenant_scope("a"), factory() as session:
            try:
                core.upload(
                    session,
                    "a",
                    identifier,
                    revision,
                    "public_json",
                    ('{"public_witness":' + str(n) + "}").encode(),
                    "test/concurrent",
                    actor,
                    "verifier_person",
                )
                return 201
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(intake, range(2)))
    assert sorted(statuses) == [201, 409]
    with tenant_scope("a"):
        db.expire_all()
        row = core.load(db, "a", identifier)
        assert row.revision == revision + 1 and len(row.payload["artifacts"]) == 1
        assert db.query(AssuranceBlob).count() == 1
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_competing_signed_reviews_then_explicit_retry(people):
    _, db, identifier, value, _, _, reviews, _, _, assignments = contracts.frozen(people)
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    revision = value["record"]["revision"]

    def review(n, rev):
        role = ["independent_assessor", "bank_acceptor"][n]
        with tenant_scope("a"), factory() as session:
            try:
                core.review(
                    session,
                    "a",
                    identifier,
                    SubmitReview(expected_revision=rev, evidence_reference="test/concurrent-review", review=reviews[n]),
                    assignments[role]["user_id"],
                    ["assessor_person", "acceptor_person"][n],
                )
                return 200
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda n: review(n, revision), range(2)))
    assert sorted(statuses) == [200, 409]
    assert review(statuses.index(409), revision + 1) == 200
    with tenant_scope("a"):
        db.expire_all()
        current = core.status(db, "a", core.load(db, "a", identifier))
        assert current["state"] == "SCOPED_EXTERNAL_RECORD_VERIFIED"
        assert current["record"]["revision"] == revision + 2
    assert verify_audit_chain(db)["status"] == "OK"


def test_postgres_root_lock_covers_all_mutation_types(people):
    _, db, identifier, _, _, _, _, _, _, _ = contracts.created(people)
    with tenant_scope("a"):
        core.load(db, "a", identifier, lock=True)
        with db.get_bind().connect() as other:
            other.execute(text("SET LOCAL lock_timeout='100ms'"))
            with pytest.raises(OperationalError) as failure:
                other.execute(
                    text(
                        "SELECT id FROM assurance_revisions WHERE kind='host_qualification' AND subject_id=:id AND revision=1 FOR UPDATE"
                    ),
                    {"id": identifier},
                )
            assert failure.value.orig.pgcode == "55P03"
            other.rollback()
        db.rollback()


@pytest.mark.parametrize("kind", ["machine", "legacy-nondurable"])
def test_postgres_metadata_is_human_only(people, kind):
    contracts.test_all_routes_require_current_typed_durable_human_even_for_metadata(people, kind)


def test_postgres_reserved_withdrawal_after_budget_exhaustion(people, monkeypatch):
    contracts.test_history_budget_always_reserves_a_durable_withdrawal(people, monkeypatch)
