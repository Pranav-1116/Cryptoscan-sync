"""Real human-session precommit/review contracts over synthetic image truth."""

import hashlib
from copy import deepcopy
from pathlib import Path
import json
import os
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from db.models.user import User
from db.models.assurance import AssuranceRevision
from db.repositories.user_repository import UserRepository, verify_audit_chain
from shared_models.host_collection import HostFact
from services.inventory.tests.test_oci_evidence import DPKG, OS
import test_oci_collection_api as existing

P = existing.P


def ready(assured, outcome="COMPLETED"):
    clients, db, target, row = existing.register(assured, outcome=outcome)
    UserRepository(db).set_roles("reader_a", ["auditor"])
    db.commit()
    auth = admin(clients).post(P + f"/targets/{row['subject_id']}/authorize", json=existing.decision(1))
    assert auth.status_code == 200, auth.text
    created = clients["bank_a"].post(P + "/jobs", json={"target_id": row["subject_id"], "expected_target_revision": 2})
    assert created.status_code == 201, created.text
    job = created.json()
    # Independent fixture truth: constants and explicit metadata, not scanner output.
    source_bytes = {"packages": DPKG, "os": OS, "library": b"\x7fELFowned-fixture-not-real-library"}
    facts = {
        "packages": HostFact(
            kind="SOFTWARE",
            local_basis="OBSERVED",
            purpose="PACKAGE_DATABASE_RECORD",
            software_name="openssl",
            software_version="3.0.17",
        ),
        "os": HostFact(
            kind="OS_RELEASE",
            local_basis="DECLARED",
            purpose="OS_RELEASE_METADATA",
            software_name="debian",
            software_version="12",
        ),
        "library": HostFact(kind="BINARY", local_basis="OBSERVED", purpose="FILE_PRESENCE", binary_format="ELF"),
    }
    reviewer_id = db.query(User).filter_by(username="reader_a").one().id
    body = {
        "target_sha256": job["payload"]["target_sha256"],
        "target_record_sha256": job["payload"]["target_record_sha256"],
        "reviewer_user_id": reviewer_id,
        "source_reference": "independent-build-register/fixture-17",
        "expected": [
            {
                "source": i.model_dump(mode="json"),
                "expected_content_sha256": hashlib.sha256(source_bytes[i.input_id]).hexdigest(),
                "facts": [facts[i.input_id].model_dump(mode="json")],
            }
            for i in target.inputs
        ],
    }
    return clients, db, target, job, body


def planned(assured, mutate=None, outcome="COMPLETED"):
    clients, db, target, job, body = ready(assured, outcome)
    if mutate:
        mutate(body)
    proposal = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=body)
    assert proposal.status_code == 201, proposal.text
    return clients, db, target, job, body, proposal.json()


def approved(assured, mutate=None, outcome="COMPLETED"):
    clients, db, target, job, body, row = planned(assured, mutate, outcome)
    response = clients["reader_a"].post(P + f"/jobs/{job['subject_id']}/truth/approve", json=existing.decision(1))
    assert response.status_code == 200, response.text
    return clients, db, target, job, body, response.json()


def finished(assured, mutate=None, uploader="bank_a", outcome="COMPLETED"):
    clients, db, target, job, body, review = approved(assured, mutate, outcome)
    handoff = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 1})
    assert handoff.status_code == 200, handoff.text
    handed = handoff.json()
    if uploader == "reader_a":
        # Give the reviewer upload authority only to exercise separation refusal.
        UserRepository(db).set_roles("reader_a", ["ciso"])
        db.commit()
    capture = existing.capture(target, handed)
    submitted = existing.submit({**clients, "bank_a": clients[uploader]}, target, handed, capture)
    assert submitted.status_code == 201, submitted.text
    return clients, db, target, job, body, review, capture


def comparison(clients, job):
    return clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/truth/reconciliation")


def test_precommit_separate_review_original_return_and_exact_reconciliation(assured):
    clients, db, _, job, body, review, capture = finished(assured)
    response = comparison(clients, job)
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["verdict"] == "MATCHED_SEPARATELY_REVIEWED_METADATA"
    assert value["identity_separation_verified"] and value["agreed_metadata_matched"]
    assert len(value["inputs"]) == 3 and all(i["comparison_performed"] for i in value["inputs"])
    for key in [
        "customer_independent_truth_verified",
        "source_authenticity_verified",
        "organizational_independence_verified",
        "whole_image_software_complete",
        "whole_estate_complete",
        "bank_production_accepted",
        "production_execution_qualified",
    ]:
        assert value[key] is False
    assert verify_audit_chain(db)["status"] == "OK"
    if os.environ.get("CRYPTOSCAN_OCI_TRUTH_WITNESS_DIR"):
        out = Path(os.environ["CRYPTOSCAN_OCI_TRUTH_WITNESS_DIR"])
        out.mkdir(parents=True, exist_ok=True)
        for name, record in [
            ("expected-truth.json", body),
            ("review.json", review),
            ("original-return.json", capture.model_dump(mode="json")),
            ("comparison.json", value),
        ]:
            (out / name).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


@pytest.mark.parametrize("change", ["missing_input", "reorder", "target", "authorization", "source_kind"])
def test_exact_denominator_cannot_be_reduced_or_reassigned(assured, change):
    clients, _, _, job, body = ready(assured)
    if change == "missing_input":
        body["expected"].pop()
    if change == "reorder":
        body["expected"].reverse()
    if change == "target":
        body["target_sha256"] = "0" * 64
    if change == "authorization":
        body["target_record_sha256"] = "0" * 64
    if change == "source_kind":
        body["expected"][0]["source"]["path"] = "wrong/path"
    result = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=body)
    assert result.status_code in {409, 422}, result.text


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_expected_truth_and_comparison_are_exact_estate(assured, who):
    clients, _, _, job, _, _ = planned(assured)
    for suffix in ["truth", "truth/reconciliation"]:
        assert clients[who].get(P + f"/jobs/{job['subject_id']}/{suffix}").status_code == 404


def test_no_self_approval_and_no_foreign_reviewer(assured):
    clients, db, _, job, body = ready(assured)
    UserRepository(db).set_roles("bank_a", ["ciso"])
    UserRepository(db).set_roles("bank_b", ["auditor"])
    db.commit()
    for name, status in [("bank_a", 409), ("bank_b", 404)]:
        changed = deepcopy(body)
        changed["reviewer_user_id"] = db.query(User).filter_by(username=name).one().id
        response = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=changed)
        assert response.status_code == status, response.text


def test_unassigned_trust_user_cannot_review_and_pending_plan_blocks_handoff(assured):
    clients, _, _, job, _, _ = planned(assured)
    result = admin(clients).post(P + f"/jobs/{job['subject_id']}/truth/approve", json=existing.decision(1))
    assert result.status_code == 409, result.text
    result = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 1})
    assert result.status_code == 409, result.text
    assert (
        clients["reader_a"].post(P + f"/jobs/{job['subject_id']}/truth/approve", json=existing.decision(1)).status_code
        == 200
    )


def test_late_expected_truth_cannot_be_added_after_handoff(assured):
    clients, _, _, job, body = ready(assured)
    assert (
        clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 1}).status_code
        == 200
    )
    assert clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=body).status_code == 409


def test_truth_and_approval_are_write_once(assured):
    clients, db, _, job, body, _ = approved(assured)
    assert clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=body).status_code == 409
    assert (
        clients["reader_a"].post(P + f"/jobs/{job['subject_id']}/truth/approve", json=existing.decision(1)).status_code
        == 409
    )
    assert db.query(AssuranceRevision).filter_by(kind="oci_truth_plan").count() == 2


@pytest.mark.parametrize("change", ["source_hash", "record_version"])
def test_independently_expected_mismatch_is_not_success_or_absence(assured, change):
    def mutate(body):
        if change == "source_hash":
            body["expected"][0]["expected_content_sha256"] = "0" * 64
        else:
            body["expected"][0]["facts"][0]["software_version"] = "3.0.18"

    clients, _, _, job, _, _, _ = finished(assured, mutate)
    result = comparison(clients, job).json()
    assert result["verdict"] == "BLOCKED_EXPECTED_TRUTH_MISMATCH_OR_GAPS"
    row = result["inputs"][0]
    assert not row["asset_absence_proven"] and not row["exact_record_multiset_matched"]
    if change == "source_hash":
        assert row["missing_records"] is None and not row["comparison_performed"]
    else:
        assert row["comparison_performed"] and row["missing_records"] == row["unexpected_records"] == 1


def test_reviewer_cannot_be_evidence_uploader(assured):
    clients, _, _, job, _, _, _ = finished(assured, uploader="reader_a")
    result = comparison(clients, job).json()
    assert result["verdict"] == "BLOCKED_REVIEW_IDENTITY_OR_PRECOMMIT_ORDER"
    assert not result["identity_separation_verified"]


def test_revoked_reviewer_authority_invalidates_qualification_not_original_evidence(assured):
    clients, db, _, job, _, _, _ = finished(assured)
    UserRepository(db).set_roles("reader_a", ["readonly"])
    db.commit()
    assert comparison(clients, job).json()["verdict"] == "BLOCKED_REVIEWER_NO_LONGER_AUTHORIZED"
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence").status_code == 200


def test_no_plan_and_unreviewed_plan_are_explicit_blockers(assured):
    clients, _, _, job, body = ready(assured)
    assert comparison(clients, job).json()["verdict"] == "BLOCKED_NO_PRECOMMITTED_TRUTH"
    assert clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=body).status_code == 201
    assert comparison(clients, job).json()["verdict"] == "BLOCKED_TRUTH_NOT_APPROVED"


@pytest.mark.parametrize("revision", [1, 2])
def test_changed_truth_rows_fail_hash_revalidation(assured, revision):
    clients, db, _, job, _, _, _ = finished(assured)
    row = db.query(AssuranceRevision).filter_by(kind="oci_truth_plan", revision=revision).one()
    db.query(AssuranceRevision).filter_by(id=row.id).update({"payload": {**row.payload, "corrupt": True}})
    db.commit()
    assert comparison(clients, job).status_code == 409


@pytest.mark.parametrize("action", ["truth.propose", "truth.approve"])
def test_truth_audit_failure_is_atomic(assured, monkeypatch, action):
    if action == "truth.propose":
        clients, db, _, job, body = ready(assured)
    else:
        clients, db, _, job, body, _ = planned(assured)
    before = db.query(AssuranceRevision).count()
    original = UserRepository.audit

    def fail(self, *args, **kw):
        if args[1] == "collection.oci." + action:
            raise RuntimeError("owned truth audit failure")
        return original(self, *args, **kw)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="owned truth"):
        if action == "truth.propose":
            clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/truth", json=body)
        else:
            clients["reader_a"].post(P + f"/jobs/{job['subject_id']}/truth/approve", json=existing.decision(1))
    assert db.query(AssuranceRevision).count() == before


def test_missing_original_inputs_keep_unknown_counts_not_absence(assured):
    clients, _, _, job, _, _, _ = finished(assured, outcome="PARTIAL")
    result = comparison(clients, job).json()
    assert result["verdict"] == "BLOCKED_EXPECTED_TRUTH_MISMATCH_OR_GAPS"
    missing = [x for x in result["inputs"] if x["receipt_status"] != "PARSED"]
    assert missing and all(
        x["observed_records"] is None and x["missing_records"] is None and not x["asset_absence_proven"]
        for x in missing
    )
