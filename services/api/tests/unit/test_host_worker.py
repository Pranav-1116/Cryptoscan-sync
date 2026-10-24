"""Local candidate: real tenant/API ledger, signed stage and native child.

Fixture signatures are disposable; no physical-host or production qualification.
"""

import base64
from datetime import datetime, timezone
import secrets
import pytest
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled
from test_collection_foundation import target_body, decision, P
from services.inventory.tests.test_collector_release import release, ROOT
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from api.assurance import collection as core, host_worker
from db.models.user import User, UserSession
from db.models.tenant import TenantMembership, Tenant
from db.models.system import System
from db.models.scan import Scan
from db.tenancy import tenant_scope
from shared_models.host_worker import LocalWorkerBinding
from shared_models.collector_identity import CollectorIdentityPolicy, prepare_statement, statement_bytes
from shared_models.host_collection import digest
from inventory.collection import OfflineLinuxCollector
from shared_models.collection import TargetSpec


def queued(assured, *, enqueue=True):
    clients, db, body = target_body(assured)
    raw, sig, pub, sha = release()
    private = Ed25519PrivateKey.generate()
    identity = CollectorIdentityPolicy(
        key_id="external-envelope",
        public_key=base64.b64encode(
            private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode(),
        release_sha256=sha,
    )
    target = clients["bank_a"].post(P + "/targets", json=body)
    assert target.status_code == 201, target.text
    tid = target.json()["subject_id"]
    auth = admin(clients).post(
        P + f"/targets/{tid}/authorize",
        json={
            **decision(1),
            "worker": {"binding_id": "payments-local-node", "source_lock_sha256": sha},
            "collector_identity": identity.model_dump(mode="json"),
        },
    )
    assert auth.status_code == 200, auth.text
    auth = auth.json()
    job = clients["bank_a"].post(P + "/jobs", json={"target_id": tid, "expected_target_revision": 2})
    assert job.status_code == 201, job.text
    job = job.json()
    if enqueue:
        q = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/enqueue", json=decision(1))
        assert q.status_code == 200, q.text
        job = q.json()
    binding = LocalWorkerBinding(
        binding_id="payments-local-node",
        source_lock_sha256=sha,
        tenant_id="a",
        system_id="system-a",
        target_id=tid,
        host_id=body["manifest"]["host_id"],
        release_public_key=pub,
    )
    return clients, db, body, auth, job, binding, raw, sig, identity, private


def proof(clients, auth, snapshot, identity, private):
    aid = auth["payload"]["approval_id"]
    approval = clients["reader_a"].get("/api/v1/host-evidence/approvals/" + aid).json()["payload"]
    statement = prepare_statement(snapshot, aid, approval["collector_nonce"], identity, datetime.now(timezone.utc))
    return {
        "snapshot": snapshot.model_dump(mode="json"),
        "collector_attestation": {
            "statement": statement.model_dump(mode="json"),
            "signature": base64.b64encode(private.sign(statement_bytes(statement))).decode(),
        },
    }


def test_local_worker_exact_verified_stage_external_signer_original_intake_and_six_boms(assured):
    clients, db, _, auth, job, binding, raw, sig, identity, private = queued(assured)
    jid = job["subject_id"]
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    snapshot = host_worker.run_local(factory, binding, jid, ROOT, raw, sig)
    row = clients["reader_a"].get(P + "/jobs/" + jid).json()
    assert row["payload"]["state"] == "AWAITING_EVIDENCE" and row["revision"] == 4
    assert row["payload"]["worker_snapshot_sha256"] == digest(snapshot)
    assert row["payload"]["worker_release"]["source_lock_sha256"] == binding.source_lock_sha256
    assert (
        not row["payload"]["worker_release"]["host_attested"] and not row["payload"]["production_execution_qualified"]
    )
    blob_uri = "/api/v1/assurance/evidence-blobs/" + row["payload"]["worker_snapshot_blob_id"] + "/content"
    recovered = admin(clients).get(blob_uri)
    assert recovered.status_code == 200 and recovered.json() == snapshot.model_dump(mode="json")
    assert recovered.headers["cache-control"] == "no-store"
    assert clients["bank_a"].get(blob_uri).status_code == 403
    assert clients["bank_b"].get(blob_uri).status_code == 404
    assert db.query(Scan).count() == 0  # worker never silently writes imported evidence
    uri = "/api/v1/host-evidence/approvals/" + auth["payload"]["approval_id"] + "/intake"
    signed = proof(clients, auth, snapshot, identity, private)
    response = clients["bank_a"].post(uri, json=signed)
    assert response.status_code == 201, response.text
    assert response.json()["collector_identity_verified"] and not response.json()["host_identity_attested"]
    assert clients["bank_a"].post(uri, json=signed).status_code == 200
    done = clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 4})
    assert done.status_code == 200, done.text
    assert done.json()["payload"]["state"] == "PARTIAL"
    response = clients["reader_a"].get(P + f"/jobs/{jid}/projections")
    assert response.status_code == 200, response.text
    assert set(response.json()["domains"]) == {"NBOM", "CBOM", "TechBOM", "HBOM", "VBOM", "SBOM"}
    evidence = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
    assert evidence["runtime_use"] == "UNKNOWN"
    from db.repositories.user_repository import verify_audit_chain

    assert verify_audit_chain(db)["status"] == "OK"
    with pytest.raises(HTTPException):
        host_worker.run_local(factory, binding, jid, ROOT, raw, sig)
    assert db.query(Scan).count() == 1


@pytest.mark.parametrize("state", ["QUEUED", "RUNNING", "CANCELLED", "REFUSED", "AWAITING_EVIDENCE"])
def test_trusted_signature_cannot_bypass_exact_worker_result(assured, state):
    clients, db, body, auth, job, binding, raw, sig, identity, private = queued(assured)
    jid = job["subject_id"]
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    if state == "AWAITING_EVIDENCE":
        host_worker.run_local(factory, binding, jid, ROOT, raw, sig)
    elif state in {"RUNNING", "REFUSED"}:
        token = secrets.token_hex(32)
        with tenant_scope("a"):
            host_worker.claim(db, binding, jid, token)
        if state == "REFUSED":
            with tenant_scope("a"):
                host_worker.refuse(db, binding, jid, token)
    elif state == "CANCELLED":
        result = clients["bank_a"].post(P + f"/jobs/{jid}/cancel", json=decision(2))
        assert result.status_code == 200, result.text
    snapshot = OfflineLinuxCollector().collect(TargetSpec.model_validate(body))
    response = clients["bank_a"].post(
        "/api/v1/host-evidence/approvals/" + auth["payload"]["approval_id"] + "/intake",
        json=proof(clients, auth, snapshot, identity, private),
    )
    assert response.status_code == 409, response.text
    assert db.query(Scan).count() == 0


@pytest.mark.parametrize("change", ["tenant", "binding", "target", "host", "system", "release", "signature", "key"])
def test_queue_hint_or_release_mismatch_cannot_consume_claim(assured, change):
    clients, db, _, _, job, binding, raw, sig, _, _ = queued(assured)
    changes = {
        "tenant": {"tenant_id": "b"},
        "binding": {"binding_id": "other"},
        "target": {"target_id": "12345678-1234-1234-1234-123456789abc"},
        "host": {"host_id": "other"},
        "system": {"system_id": "system-b"},
        "release": {"source_lock_sha256": "a" * 64},
        "key": {"release_public_key": release()[2]},
    }
    if change == "signature":
        sig = base64.b64encode(b"X" * 64).decode()
    else:
        binding = binding.model_copy(update=changes[change])
    with pytest.raises((HTTPException, ValueError)):
        host_worker.run_local(sessionmaker(bind=db.get_bind()), binding, job["subject_id"], ROOT, raw, sig)
    assert clients["reader_a"].get(P + "/jobs/" + job["subject_id"]).json()["payload"]["state"] == "QUEUED"
    assert db.query(Scan).count() == 0


@pytest.mark.parametrize(
    "change",
    [
        "revoked",
        "expiry",
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
def test_fresh_admission_refuses_revoked_queued_work(assured, change):
    clients, db, _, auth, job, binding, raw, sig, _, _ = queued(assured)
    if change == "revoked":
        assert admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2)).status_code == 200
    elif change == "expiry":
        from datetime import timedelta
        from unittest.mock import patch

        with (
            tenant_scope("a"),
            patch("api.assurance.collection.utcnow", return_value=datetime.now(timezone.utc) + timedelta(days=2)),
            pytest.raises(HTTPException),
        ):
            host_worker.claim(db, binding, job["subject_id"], secrets.token_hex(32))
        return
    elif change == "role":
        db.query(User).filter_by(username="bank_a").one().roles = "readonly"
    elif change == "membership":
        db.delete(db.query(TenantMembership).filter_by(username="bank_a", tenant_id="a").one())
    elif change == "tenant-status":
        db.get(Tenant, "a").status = "SUSPENDED"
    elif change == "environment":
        db.get(System, "system-a").environment = "stage"
    elif change == "user-disabled":
        db.query(User).filter_by(username="bank_a").one().is_active = False
    elif change == "credential-revoked":
        db.query(UserSession).filter_by(username="bank_a").one().revoked_at = datetime.now(timezone.utc)
    elif change == "credential-expired":
        from datetime import timedelta

        db.query(UserSession).filter_by(username="bank_a").one().expires_at = datetime.now(timezone.utc) - timedelta(
            seconds=1
        )
    else:
        from db.models.control_plane import SafeScanPolicy

        db.add(
            SafeScanPolicy(
                name="worker-stop",
                mode="emergency_stop" if change in {"stop", "environment-stop"} else "standard",
                scope_environment="prod" if change == "environment-stop" else None,
                emergency_stop=change in {"stop", "environment-stop"},
                excluded_assets=["payments-1"] if change == "policy-exclusion" else [],
                is_active=True,
            )
        )
    db.commit()
    with pytest.raises(HTTPException):
        host_worker.run_local(sessionmaker(bind=db.get_bind()), binding, job["subject_id"], ROOT, raw, sig)
    assert db.query(Scan).count() == 0
    with tenant_scope("a"):
        assert core.chain(db, "a", core.JOB, job["subject_id"])[-1].payload["state"] == "QUEUED"


def test_claim_no_takeover_wrong_token_checkpoint_and_completion_cancellation(assured):
    clients, db, _, _, job, binding, _, _, _, _ = queued(assured)
    jid = job["subject_id"]
    token = secrets.token_hex(32)
    with tenant_scope("a"):
        host_worker.claim(db, binding, jid, token)
        with pytest.raises(HTTPException):
            host_worker.claim(db, binding, jid, secrets.token_hex(32))
        with pytest.raises(HTTPException):
            host_worker.running(db, binding, jid, "wrong")
    cancel = clients["bank_a"].post(P + f"/jobs/{jid}/cancel", json=decision(3))
    assert cancel.status_code == 200, cancel.text
    with tenant_scope("a"):
        with pytest.raises(HTTPException):
            host_worker.running(db, binding, jid, token)
        host_worker.refuse(db, binding, jid, token)
        assert core.chain(db, "a", core.JOB, jid)[-1].payload["state"] == "CANCELLED"


@pytest.mark.parametrize("change", ["cancel", "role", "child-failure", "final-stop"])
def test_inflight_gate_and_failure_never_publish_snapshot(assured, monkeypatch, change):
    clients, db, _, _, job, binding, raw, sig, _, _ = queued(assured)
    factory = sessionmaker(bind=db.get_bind(), expire_on_commit=False)
    import inventory.isolation as isolation

    original = isolation.collect_isolated

    def controlled_collect(*args, **kw):
        if change == "cancel":
            result = clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/cancel", json=decision(3))
            assert result.status_code == 200, result.text
        if change == "role":
            db.query(User).filter_by(username="bank_a").one().roles = "readonly"
            db.commit()
        if change == "child-failure":
            raise isolation.IsolationUnavailable("refused actual supported stage")
        if change == "final-stop":
            snapshot, report = original(*args, **kw)
            from db.models.control_plane import SafeScanPolicy

            db.add(SafeScanPolicy(name="final-stop", mode="emergency_stop", emergency_stop=True, is_active=True))
            db.commit()
            return snapshot, report
        kw["checkpoint"]()
        raise AssertionError("revoked worker reached native collection")

    monkeypatch.setattr(isolation, "collect_isolated", controlled_collect)
    with pytest.raises((HTTPException, isolation.IsolationUnavailable)):
        host_worker.run_local(factory, binding, job["subject_id"], ROOT, raw, sig)
    with tenant_scope("a"):
        row = core.chain(db, "a", core.JOB, job["subject_id"])[-1]
        assert row.payload["state"] == ("CANCELLED" if change == "cancel" else "REFUSED")
        assert "worker_snapshot_sha256" not in row.payload
    assert db.query(Scan).count() == 0


def test_enqueue_cancel_rbac_cross_tenant_and_current_revision(assured):
    clients, db, _, _, job, _, _, _, _, _ = queued(assured, enqueue=False)
    jid = job["subject_id"]
    assert clients["reader_a"].post(P + f"/jobs/{jid}/enqueue", json=decision(1)).status_code == 403
    assert clients["bank_b"].post(P + f"/jobs/{jid}/enqueue", json=decision(1)).status_code == 404
    assert clients["bank_a"].post(P + f"/jobs/{jid}/enqueue", json=decision(2)).status_code == 409
    assert clients["bank_a"].post(P + f"/jobs/{jid}/enqueue", json=decision(1)).status_code == 200
    assert clients["bank_a"].post(P + f"/jobs/{jid}/enqueue", json=decision(2)).status_code == 409
    assert clients["reader_a"].post(P + f"/jobs/{jid}/cancel", json=decision(2)).status_code == 403
    assert clients["bank_b"].post(P + f"/jobs/{jid}/cancel", json=decision(2)).status_code == 404
    assert clients["bank_a"].post(P + f"/jobs/{jid}/cancel", json=decision(1)).status_code == 409
    assert clients["bank_a"].post(P + f"/jobs/{jid}/cancel", json=decision(2)).status_code == 200


def test_no_worker_binding_or_missing_identity_cannot_enqueue(assured):
    from test_collection_foundation import prepared

    clients, _, _, _, job = prepared(assured)
    assert clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/enqueue", json=decision(1)).status_code == 409
