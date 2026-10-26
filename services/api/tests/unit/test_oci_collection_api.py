"""Actual session/tenant SQL contracts for imported OCI metadata, not bank qualification."""

from datetime import timedelta
from pathlib import Path
import subprocess
import os
import json
import sys

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from db.models.system import System
from db.repositories.user_repository import UserRepository, verify_audit_chain
from inventory.oci_job_capture import capture_oci_job
from shared_models.host_collection import digest
from shared_models.oci_collection import ImageInput
from shared_models.oci_intake import OciCaptureBinding, OciJobReturn
from services.inventory.tests.test_oci_evidence import fixture, tar, OS

P = "/api/v1/collection/oci"
ROOT = Path(__file__).resolve().parents[4]


def register(assured, *, outcome="COMPLETED"):
    clients, db, tmp = assured
    inputs = None
    layers = None
    if outcome == "PARTIAL":
        layers = [tar([("etc/os-release", OS, "file")])]
    if outcome == "FAILED":
        inputs = [ImageInput(input_id="missing", kind="BINARY_METADATA", path="missing/file")]
    target, _ = fixture(tmp, layers=layers, inputs=inputs)
    target = target.model_copy(update={"system_id": "system-a", "environment": "prod"})
    row = clients["bank_a"].post(P + "/targets", json=target.model_dump(mode="json"))
    assert row.status_code == 201, row.text
    return clients, db, target, row.json()


def decision(revision):
    return {
        "expected_revision": revision,
        "evidence_ref": "change/oci-intake-17",
        "reason": "Reviewed exact image digest and selected offline metadata scope",
    }


def prepare(assured, *, outcome="COMPLETED"):
    clients, db, target, row = register(assured, outcome=outcome)
    auth = admin(clients).post(P + f"/targets/{row['subject_id']}/authorize", json=decision(1))
    assert auth.status_code == 200, auth.text
    auth = auth.json()
    job = clients["bank_a"].post(P + "/jobs", json={"target_id": auth["subject_id"], "expected_target_revision": 2})
    assert job.status_code == 201, job.text
    jid = job.json()["subject_id"]
    handoff = clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1})
    assert handoff.status_code == 200, handoff.text
    return clients, db, target, auth, handoff.json()


def capture(target, job):
    binding = OciCaptureBinding.model_validate(job["payload"]["capture_binding"])
    return capture_oci_job(target, binding, digest(target), digest(binding))


def submit(clients, target, job, value=None):
    value = value or capture(target, job)
    return clients["bank_a"].post(
        P + f"/jobs/{job['subject_id']}/intake",
        json={
            "expected_revision": job["revision"],
            "capture": value.model_dump(mode="json"),
            "expected_evidence_sha256": digest(value.evidence),
        },
    )


def complete(assured, *, outcome="COMPLETED"):
    clients, db, target, auth, job = prepare(assured, outcome=outcome)
    result = submit(clients, target, job)
    assert result.status_code == 201, result.text
    return clients, db, target, auth, result.json()


@pytest.mark.parametrize("outcome", ["COMPLETED", "PARTIAL", "FAILED"])
def test_real_offline_capture_to_committed_evidence_and_six_views(assured, outcome):
    clients, db, target, auth, job = complete(assured, outcome=outcome)
    assert job["payload"]["state"] == outcome
    response = clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence")
    assert response.status_code == 200, response.text
    retained = OciJobReturn.model_validate(response.json())
    assert retained.evidence.target == target
    assert not retained.producer_authenticity_verified and not retained.evidence.image_executed
    views = clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/projections")
    assert views.status_code == 200, views.text
    value = views.json()
    assert all(name in value for name in ["SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"])
    assert value["NBOM"]["state"] == value["HBOM"]["state"] == "UNKNOWN"
    assert not value["graph_persisted"] and not value["cyclonedx_export"]
    if outcome == "COMPLETED":
        assert value["SBOM"]["facts"][0]["evidence_id"] == value["TechBOM"]["facts"][0]["evidence_id"]
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_evidence").count() == 1
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_consumed").count() == 1
    assert verify_audit_chain(db)["status"] == "OK"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_exact_estate_hides_all_oci_records(assured, who):
    clients, _, _, auth, job = complete(assured)
    for path in [
        f"/targets/{auth['subject_id']}",
        f"/jobs/{job['subject_id']}",
        f"/jobs/{job['subject_id']}/evidence",
        f"/jobs/{job['subject_id']}/projections",
    ]:
        assert clients[who].get(P + path).status_code == 404
    assert clients[who].get(P + "/targets").json()["items"] == []
    assert clients[who].get(P + "/jobs").json()["items"] == []


@pytest.mark.parametrize("role", ["readonly", "auditor", "developer"])
def test_readers_cannot_register_authorize_revoke_handoff_or_submit(assured, role):
    clients, db, target, auth, job = prepare(assured)
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    c = clients["reader_a"]
    assert c.get(P + f"/targets/{auth['subject_id']}").status_code == 200
    for path, body in [
        ("/targets", target.model_dump(mode="json")),
        (f"/targets/{auth['subject_id']}/authorize", decision(2)),
        (f"/targets/{auth['subject_id']}/revoke", decision(2)),
        (f"/jobs/{job['subject_id']}/handoff", {"expected_revision": 2}),
        (f"/jobs/{job['subject_id']}/cancel", {"expected_revision": 2}),
        (
            f"/jobs/{job['subject_id']}/intake",
            {
                "expected_revision": 2,
                "capture": capture(target, job).model_dump(mode="json"),
                "expected_evidence_sha256": "0" * 64,
            },
        ),
    ]:
        assert c.post(P + path, json=body).status_code == 403, path


def test_analyst_cannot_self_grant_trust_permission(assured):
    clients, _, _, row = register(assured)
    assert clients["bank_a"].post(P + f"/targets/{row['subject_id']}/authorize", json=decision(1)).status_code == 403


@pytest.mark.parametrize("change", ["revoke", "update", "expire", "system_environment"])
def test_current_authority_is_revalidated_at_intake(assured, monkeypatch, change):
    clients, db, target, auth, job = prepare(assured)
    value = capture(target, job)
    if change == "revoke":
        response = admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2))
        assert response.status_code == 200, response.text
    elif change == "update":
        response = admin(clients).put(
            P + f"/targets/{auth['subject_id']}",
            json={"expected_revision": 2, "target": target.model_dump(mode="json")},
        )
        assert response.status_code == 200, response.text
        assert response.json()["payload"]["state"] == "REGISTERED"
    elif change == "expire":
        monkeypatch.setattr("api.assurance.oci_collection.utcnow", lambda: target.expires_at + timedelta(seconds=1))
    else:
        db.query(System).filter_by(id="system-a").one().environment = "different"
        db.commit()
    assert submit(clients, target, job, value).status_code == 409
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_evidence").count() == 0


@pytest.mark.parametrize("change", ["nonce", "job", "expected_sha", "future_timestamp", "before_handoff"])
def test_wrong_binding_or_evidence_is_not_consumed(assured, change):
    clients, db, target, _, job = prepare(assured)
    value = capture(target, job)
    body = {
        "expected_revision": 2,
        "capture": value.model_dump(mode="json"),
        "expected_evidence_sha256": digest(value.evidence),
    }
    if change == "nonce":
        body["capture"]["binding"]["nonce"] = "0" * 64
    if change == "job":
        body["capture"]["binding"]["job_id"] = "00000000-0000-0000-0000-000000000000"
    if change == "expected_sha":
        body["expected_evidence_sha256"] = "0" * 64
    if change == "future_timestamp":
        future = utcnow() + timedelta(minutes=5)
        updated = value.evidence.model_copy(update={"finished_at": future})
        body["capture"]["evidence"] = updated.model_dump(mode="json")
        body["expected_evidence_sha256"] = digest(updated)
    if change == "before_handoff":
        body["capture"]["evidence"]["started_at"] = (value.binding.issued_at - timedelta(seconds=1)).isoformat()
    response = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/intake", json=body)
    assert response.status_code in {409, 422}, response.text
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_consumed").count() == 0


def test_duplicate_job_handoff_and_intake_cannot_replay(assured):
    clients, db, target, auth, job = prepare(assured)
    assert (
        clients["bank_a"]
        .post(P + "/jobs", json={"target_id": auth["subject_id"], "expected_target_revision": 2})
        .status_code
        == 409
    )
    assert (
        clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 2}).status_code
        == 409
    )
    value = capture(target, job)
    assert submit(clients, target, job, value).status_code == 201
    assert submit(clients, target, job, value).status_code == 409
    assert db.query(AssuranceRevision).filter_by(kind="oci_collection_evidence").count() == 1


def test_cancel_survives_revocation_and_never_collects(assured):
    clients, db, target, auth, job = prepare(assured)
    value = capture(target, job)
    assert admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2)).status_code == 200
    result = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/cancel", json={"expected_revision": 2})
    assert result.status_code == 200 and result.json()["payload"]["state"] == "CANCELLED"
    assert submit(clients, target, job, value).status_code == 409
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence").status_code == 409


def test_historical_evidence_remains_readable_without_image_or_current_authorization(assured, monkeypatch):
    clients, _, _, auth, job = complete(assured)
    assert admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2)).status_code == 200

    def denied(*args, **kwargs):
        raise AssertionError("HTTP never reads images or executes collection")

    monkeypatch.setattr("inventory.oci_evidence.collect_oci", denied)
    monkeypatch.setattr("inventory.oci_evidence.read_public", denied)
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/projections").status_code == 200


@pytest.mark.parametrize(
    "kind", ["oci_collection_evidence", "oci_collection_job", "oci_collection_target", "oci_collection_consumed"]
)
def test_changed_original_row_fails_revalidation(assured, kind):
    clients, db, _, _, job = complete(assured)
    row = db.query(AssuranceRevision).filter_by(kind=kind).first()
    db.query(AssuranceRevision).filter_by(id=row.id).update({"payload": {**row.payload, "injected": "corruption"}})
    db.commit()
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/projections").status_code == 409


@pytest.mark.parametrize("action", ["evidence.consume", "evidence.intake", "job.complete"])
def test_intake_and_audit_rollback_as_one_transaction(assured, monkeypatch, action):
    clients, db, target, _, job = prepare(assured)
    value = capture(target, job)
    baseline = db.query(AssuranceRevision).count()
    original = UserRepository.audit

    def fail(self, *args, **kw):
        if args[1] == "collection.oci." + action:
            raise RuntimeError("owned OCI audit failure")
        return original(self, *args, **kw)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="owned OCI"):
        submit(clients, target, job, value)
    assert db.query(AssuranceRevision).count() == baseline
    assert verify_audit_chain(db)["status"] == "OK"


def test_stable_identity_and_exact_system_are_not_reassignable(assured):
    clients, _, target, row = register(assured)
    for changed in [
        target.model_copy(update={"target_id": "another"}),
        target.model_copy(update={"system_id": "system-b"}),
    ]:
        response = admin(clients).put(
            P + f"/targets/{row['subject_id']}",
            json={"expected_revision": 1, "target": changed.model_dump(mode="json")},
        )
        assert response.status_code in {404, 409}
    assert (
        clients["bank_a"]
        .post(P + "/targets", json=target.model_copy(update={"system_id": "system-b"}).model_dump(mode="json"))
        .status_code
        == 404
    )


def test_wire_cap_duplicate_json_and_no_store(assured):
    clients, _, target, _ = register(assured)
    response = clients["bank_a"].post(
        P + "/targets", content=b"x" * (2 * 1048576 + 1), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413 and response.headers["cache-control"] == "no-store"
    raw = '{"target_id":"duplicate",' + target.model_dump_json()[1:]
    response = clients["bank_a"].post(P + "/targets", content=raw, headers={"Content-Type": "application/json"})
    assert response.status_code == 422


def test_bound_cli_return_is_accepted_but_original_evidence_contract_stays_unchanged(assured):
    clients, _, target, _, job = prepare(assured)
    folder = Path(target.layout_path).parent
    target_path, binding_path, output = [folder / x for x in ["target.json", "binding.json", "capture.json"]]
    binding = OciCaptureBinding.model_validate(job["payload"]["capture_binding"])
    target_path.write_text(target.model_dump_json())
    binding_path.write_text(binding.model_dump_json())
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/capture_oci_job_evidence.py"),
            "--target",
            str(target_path),
            "--binding",
            str(binding_path),
            "--approved-target-sha256",
            digest(target),
            "--approved-binding-sha256",
            digest(binding),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    value = OciJobReturn.model_validate_json(output.read_bytes())
    completion = submit(clients, target, job, value)
    assert completion.status_code == 201, completion.text
    retained = clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence")
    projected = clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/projections")
    if os.environ.get("CRYPTOSCAN_OCI_INTAKE_WITNESS_DIR"):
        witness = Path(os.environ["CRYPTOSCAN_OCI_INTAKE_WITNESS_DIR"])
        witness.mkdir(parents=True, exist_ok=True)
        records = {
            "api-target-history.json": clients["reader_a"].get(P + f"/targets/{job['payload']['target_id']}").json(),
            "api-handoff.json": job,
            "bound-return.json": value.model_dump(mode="json"),
            "api-completion.json": completion.json(),
            "api-retained-return.json": retained.json(),
            "api-projections.json": projected.json(),
        }
        for name, record in records.items():
            (witness / name).write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")


def test_unqualified_production_boundary_remains_closed(assured, monkeypatch):
    clients, _, target, auth, job = prepare(assured)
    monkeypatch.setattr("api.assurance.collection.required", lambda: True)
    assert clients["bank_a"].post(P + "/targets", json=target.model_dump(mode="json")).status_code == 409
    assert clients["reader_a"].get(P + f"/targets/{auth['subject_id']}").status_code == 409
    assert (
        clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 2}).status_code
        == 409
    )


def test_authorization_cannot_be_issued_months_before_its_window(assured):
    clients, _, tmp = assured
    target, _ = fixture(tmp)
    future = utcnow() + timedelta(days=2)
    target = target.model_copy(
        update={
            "system_id": "system-a",
            "environment": "prod",
            "not_before": future,
            "expires_at": future + timedelta(hours=1),
        }
    )
    row = clients["bank_a"].post(P + "/targets", json=target.model_dump(mode="json"))
    assert row.status_code == 201, row.text
    response = admin(clients).post(P + f"/targets/{row.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409, response.text
