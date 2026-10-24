"""Actual scoped API/DB identity checks; keys are disposable test keys only."""

import base64
from datetime import datetime, timezone
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled
from test_collection_foundation import target_body, decision, P
from inventory.collection import OfflineLinuxCollector
from shared_models.collection import TargetSpec
from shared_models.collector_identity import CollectorIdentityPolicy, prepare_statement, statement_bytes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from db.models.scan import Scan
from db.repositories.user_repository import verify_audit_chain


def signed_setup(assured):
    clients, db, body = target_body(assured)
    private = Ed25519PrivateKey.generate()
    policy = CollectorIdentityPolicy(
        key_id="fixture-key",
        public_key=base64.b64encode(
            private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).decode(),
        release_sha256="a" * 64,
    )
    target = clients["bank_a"].post(P + "/targets", json=body).json()
    auth = admin(clients).post(
        P + f"/targets/{target['subject_id']}/authorize",
        json={**decision(1), "collector_identity": policy.model_dump(mode="json")},
    )
    assert auth.status_code == 200, auth.text
    auth = auth.json()
    aid = auth["payload"]["approval_id"]
    approval = clients["reader_a"].get("/api/v1/host-evidence/approvals/" + aid).json()
    snapshot = OfflineLinuxCollector().collect(TargetSpec.model_validate(body))
    statement = prepare_statement(
        snapshot, aid, approval["payload"]["collector_nonce"], policy, datetime.now(timezone.utc)
    )
    proof = {
        "statement": statement.model_dump(mode="json"),
        "signature": base64.b64encode(private.sign(statement_bytes(statement))).decode(),
    }
    return clients, db, auth, snapshot, proof, private


def test_signed_collector_intake_inspection_and_replay(assured):
    clients, db, auth, snapshot, proof, _ = signed_setup(assured)
    uri = "/api/v1/host-evidence/approvals/" + auth["payload"]["approval_id"] + "/intake"
    response = clients["bank_a"].post(
        uri, json={"snapshot": snapshot.model_dump(mode="json"), "collector_attestation": proof}
    )
    assert response.status_code == 201, response.text
    assert response.json()["collector_identity_verified"] and not response.json()["host_identity_attested"]
    assert (
        clients["bank_a"]
        .post(uri, json={"snapshot": snapshot.model_dump(mode="json"), "collector_attestation": proof})
        .status_code
        == 200
    )
    assert clients["bank_a"].post(uri, json={"snapshot": snapshot.model_dump(mode="json")}).status_code == 409
    detail = clients["reader_a"].get(uri.replace("/intake", "/snapshot"))
    assert detail.status_code == 200 and detail.json()["collector_identity_verified"]
    assert db.query(Scan).count() == 1 and verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize(
    "change",
    ["unsigned", "wrong-key", "nonce", "host", "release", "snapshot", "future", "approval", "revoked", "cross-bank"],
)
def test_signature_failures_never_commit_evidence(assured, change):
    clients, db, auth, snapshot, proof, private = signed_setup(assured)
    uri = "/api/v1/host-evidence/approvals/" + auth["payload"]["approval_id"] + "/intake"
    if change == "wrong-key":
        proof["signature"] = base64.b64encode(Ed25519PrivateKey.generate().sign(b"not the trusted statement")).decode()
    elif change in {"nonce", "host", "release", "snapshot", "approval"}:
        key = {
            "nonce": "nonce",
            "host": "host_id",
            "release": "release_sha256",
            "snapshot": "snapshot_sha256",
            "approval": "approval_id",
        }[change]
        proof["statement"][key] = (
            "b" * 64
            if change in {"nonce", "release", "snapshot"}
            else "other-host"
            if change == "host"
            else "12345678-1234-1234-1234-123456789abc"
        )
    elif change == "future":
        proof["statement"]["signed_at"] = "2099-01-01T00:00:00Z"
    elif change == "revoked":
        assert admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2)).status_code == 200
    if change in {"nonce", "host", "release", "snapshot", "future", "approval"}:
        # Scope tests use a cryptographically VALID signature by the pinned key,
        # so rejecting them cannot be explained by stale/invalid signatures.
        from shared_models.collector_identity import CollectorStatement

        proof["signature"] = base64.b64encode(
            private.sign(statement_bytes(CollectorStatement.model_validate(proof["statement"])))
        ).decode()
    body = {"snapshot": snapshot.model_dump(mode="json")}
    if change != "unsigned":
        body["collector_attestation"] = proof
    response = clients["bank_b" if change == "cross-bank" else "bank_a"].post(uri, json=body)
    assert response.status_code == (404 if change == "cross-bank" else 409), response.text
    assert db.query(Scan).count() == 0


def test_attestation_tamper_is_detected_on_inspection(assured):
    from db.models.assurance import AssuranceRevision

    clients, db, auth, snapshot, proof, _ = signed_setup(assured)
    aid = auth["payload"]["approval_id"]
    uri = "/api/v1/host-evidence/approvals/" + aid
    assert (
        clients["bank_a"]
        .post(uri + "/intake", json={"snapshot": snapshot.model_dump(mode="json"), "collector_attestation": proof})
        .status_code
        == 201
    )
    row = db.query(AssuranceRevision).filter_by(kind="host_intake", subject_id=aid).one()
    # Even a recomputed local row hash cannot bless an invalid external signature.
    import copy
    from shared_models.host_collection import digest

    value = copy.deepcopy(row.payload)
    value["collector_attestation"]["statement"]["release_sha256"] = "b" * 64
    db.execute(
        AssuranceRevision.__table__.update()
        .where(AssuranceRevision.id == row.id)
        .values(payload=value, payload_sha256=digest(value))
    )
    db.commit()
    assert clients["reader_a"].get(uri + "/snapshot").status_code == 409
