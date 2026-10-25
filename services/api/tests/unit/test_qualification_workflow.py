"""Actual typed sessions/tenant SQL; named users and signatures are synthetic fixtures."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import pytest
from fastapi.testclient import TestClient
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from db.models.user import User
from db.models.tenant import TenantMembership
from db.models.assurance import AssuranceBlob
from db.repositories.user_repository import UserRepository, verify_audit_chain
from api.security.passwords import hash_password
from api.security.session_manager import SessionManager
from shared.shared_models.tests.test_qualification_acceptance import setup as packet_setup, signed
from shared_models.tpm_quote_verification import canonical, sha
from shared_models.qualification_acceptance import NativeEvidence

P = "/api/v1/collection/qualification/campaigns"


@pytest.fixture()
def people(assured):
    clients, db, _ = assured
    extra = {}
    ids = {}
    for name, role in [
        ("linux_person", "security_analyst"),
        ("windows_person", "security_analyst"),
        ("verifier_person", "security_analyst"),
        ("assessor_person", "auditor"),
        ("acceptor_person", "ciso"),
    ]:
        repo = UserRepository(db)
        user = repo.create_user(name, hash_password("unused-disposable-test-password"), [role])
        ids[name] = user.id
        db.add(TenantMembership(tenant_id="a", username=name, tenant_role="member"))
        db.commit()
        token = SessionManager().create_session(name, roles=[])
        repo.create_session(token, name, datetime.now(timezone.utc) + timedelta(hours=1), ip="127.0.0.1")
        db.commit()
        client = TestClient(clients["bank_a"].app)
        client.cookies.set("cryptoscan_session", token)
        extra[name] = client
    try:
        yield {**clients, **extra}, db, ids
    finally:
        for client in extra.values():
            client.close()


def packet():
    policy, index, reviews, artifacts, _, keys = packet_setup()
    policy = policy.model_copy(update={"tenant_id": "a"})
    old = next(d for d in artifacts if d not in index.native.values())
    artifacts.pop(old)
    data = canonical(
        {
            "schema_version": "engineering.public-witness/v1",
            "summary": "Synthetic worker witness, not independent operational clearance",
        }
    )
    new = hashlib.sha256(data).hexdigest()
    artifacts[new] = data
    index = index.model_copy(
        update={
            "tenant_id": "a",
            "policy_sha256": sha(policy),
            "checks": {k: [new if d == old else d for d in values] for k, values in index.checks.items()},
        }
    )
    reviews = [
        signed(
            key,
            r.statement.model_copy(update={"tenant_id": "a", "policy_sha256": sha(policy), "index_sha256": sha(index)}),
        )
        for key, r in zip(keys, reviews)
    ]
    return policy, index, reviews, artifacts, keys


def created(people, *, assigned=True):
    clients, db, ids = people
    policy, index, reviews, artifacts, keys = packet()
    response = admin(clients).post(
        P,
        json={
            "policy": policy.model_dump(mode="json"),
            "return_channel_reference": "synthetic/channel-approval-reference-only",
            "evidence_reference": "change/qualification-product",
        },
    )
    assert response.status_code == 201, response.text
    value = response.json()
    identifier = value["record"]["subject_id"]
    assignments = {
        role: {
            "user_id": ids[name],
            **(
                {"reviewer_id": policy.reviewers[n].reviewer_id}
                if role in {"independent_assessor", "bank_acceptor"}
                else {}
            ),
        }
        for role, name, n in [
            ("linux_operator", "linux_person", 0),
            ("windows_operator", "windows_person", 0),
            ("verifier", "verifier_person", 0),
            ("independent_assessor", "assessor_person", 0),
            ("bank_acceptor", "acceptor_person", 1),
        ]
    }
    if assigned:
        response = admin(clients).post(
            P + f"/{identifier}/assignments",
            json={
                "expected_revision": 1,
                "evidence_reference": "change/named-real-user-ids",
                "assignments": assignments,
            },
        )
        assert response.status_code == 200, response.text
        value = response.json()
    return clients, db, identifier, value, policy, index, reviews, artifacts, keys, assignments


def upload_all(clients, identifier, value, index, artifacts):
    for digest, data in artifacts.items():
        category = next((c for c, d in index.native.items() if d == digest), None)
        who = "windows_person" if category == "windows" else "linux_person" if category else "verifier_person"
        response = clients[who].post(
            P + f"/{identifier}/artifacts",
            params={
                "expected_revision": value["record"]["revision"],
                "kind": "native" if category else "public_json",
                "evidence_reference": "operator/original-fixture",
            },
            content=data,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 201, response.text
        value = response.json()
    return value


def frozen(people):
    clients, db, identifier, value, policy, index, reviews, artifacts, keys, assignments = created(people)
    value = upload_all(clients, identifier, value, index, artifacts)
    response = clients["verifier_person"].post(
        P + f"/{identifier}/freeze",
        json={
            "expected_revision": value["record"]["revision"],
            "evidence_reference": "verifier/originals",
            "index": index.model_dump(mode="json"),
        },
    )
    assert response.status_code == 200, response.text
    return clients, db, identifier, response.json(), policy, index, reviews, artifacts, keys, assignments


def test_actual_users_original_bytes_two_separate_external_signatures_no_dispatch(people):
    clients, db, identifier, value, _, index, reviews, artifacts, _, _ = frozen(people)
    assert value["state"] == "WAITING_FOR_SEPARATE_SIGNED_REVIEWS"
    for name, proof in zip(["assessor_person", "acceptor_person"], reviews):
        response = clients[name].post(
            P + f"/{identifier}/reviews",
            json={
                "expected_revision": value["record"]["revision"],
                "evidence_reference": "external/signed-fixture-only",
                "review": proof.model_dump(mode="json"),
            },
        )
        assert response.status_code == 200, response.text
        value = response.json()
    assert (
        value["state"] == "SCOPED_EXTERNAL_RECORD_VERIFIED" and value["verification"]["independent_signatures_verified"]
    )
    assert value["dispatch"] == "NOT_DISPATCHED_NO_REMOTE_EXECUTION"
    assert not value["full_worker_production_clearance"] and not value["host_identity_attested"]
    assert not value["production_execution_qualified"]
    exported = clients["reader_a"].get(P + f"/{identifier}/export")
    assert exported.status_code == 200 and exported.headers["cache-control"] == "no-store"
    assert exported.json()["state"] == "SCOPED_EXTERNAL_RECORD_VERIFIED"
    assert exported.json()["assignees"]["linux_operator"]["username"] == "linux_person"
    assert clients["bank_b"].get(P + f"/{identifier}/export").status_code == 404
    digest = index.native["systemd"]
    original = admin(clients).get(P + f"/{identifier}/artifacts/{digest}")
    assert (
        original.status_code == 200
        and original.content == artifacts[digest]
        and original.headers["cache-control"] == "no-store"
    )
    assert clients["linux_person"].get(P + f"/{identifier}/artifacts/{digest}").status_code == 403
    assert (
        clients["assessor_person"].get(P + f"/{identifier}/artifacts/{digest}").status_code == 403
    )  # raw privilege unchanged
    assert clients["bank_b"].get(P + f"/{identifier}").status_code == 404
    assert clients["platform_admin"].get(P + f"/{identifier}").status_code == 404
    assert clients["reader_a"].get(P + f"/{identifier}").status_code == 200
    assert clients["reader_a"].get("/api/v1/assurance/records?kind=host_qualification").status_code == 200
    assert clients["reader_a"].get(f"/api/v1/assurance/records/host_qualification/{identifier}").status_code == 200
    assert verify_audit_chain(db)["status"] == "OK"


def test_unassigned_pending_no_people_or_execution_invented(people):
    clients, _, identifier, value, _, index, _, artifacts, _, _ = created(people, assigned=False)
    assert value["record"]["payload"]["return_channel_reference"] == "synthetic/channel-approval-reference-only"
    assert value["assignees"] == {}
    assert value["state"] == "WAITING_FOR_ASSIGNMENTS" and not value["record"]["payload"]["assignments"]
    assert clients["bank_a"].get(P).json()["campaigns"][0]["state"] == "WAITING_FOR_ASSIGNMENTS"
    data = artifacts[index.native["systemd"]]
    response = clients["linux_person"].post(
        P + f"/{identifier}/artifacts",
        params={"expected_revision": 1, "kind": "native", "evidence_reference": "not/assigned"},
        content=data,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 409


@pytest.mark.parametrize(
    "change",
    [
        "same-reviewer",
        "reviewer-operator",
        "policy-approver",
        "foreign-user",
        "disabled-user",
        "missing-user",
        "wrong-key",
        "wrong-role",
        "no-membership",
    ],
)
def test_named_assignment_constraints(people, change):
    clients, db, identifier, _, _, _, _, _, _, assignments = created(people, assigned=False)
    if change == "same-reviewer":
        assignments["bank_acceptor"]["user_id"] = assignments["independent_assessor"]["user_id"]
    elif change == "reviewer-operator":
        assignments["linux_operator"]["user_id"] = assignments["bank_acceptor"]["user_id"]
    elif change == "policy-approver":
        assignments["bank_acceptor"]["user_id"] = db.query(User).filter_by(username="platform_admin").one().id
        db.add(TenantMembership(tenant_id="a", username="platform_admin", tenant_role="member"))
        db.commit()
    elif change == "foreign-user":
        assignments["linux_operator"]["user_id"] = db.query(User).filter_by(username="bank_b").one().id
    elif change == "disabled-user":
        db.get(User, assignments["linux_operator"]["user_id"]).is_active = False
        db.commit()
    elif change == "missing-user":
        assignments["linux_operator"]["user_id"] = "12345678-1234-1234-1234-123456789abc"
    elif change == "wrong-key":
        assignments["independent_assessor"]["reviewer_id"] = "unapproved"
    elif change == "wrong-role":
        db.get(User, assignments["linux_operator"]["user_id"]).roles = "readonly"
        db.commit()
    else:
        db.delete(db.query(TenantMembership).filter_by(username="linux_person", tenant_id="a").one())
        db.commit()
    result = admin(clients).post(
        P + f"/{identifier}/assignments",
        json={"expected_revision": 1, "evidence_reference": "change/bad-assignments", "assignments": assignments},
    )
    assert result.status_code == 409, result.text


@pytest.mark.parametrize(
    "change",
    ["wrong-operator", "stale", "private-key", "credential-key", "bearer", "duplicate-json", "binary", "oversized"],
)
def test_upload_refusals_do_not_retain_content(people, change):
    clients, db, identifier, _, _, index, _, artifacts, _, _ = created(people)
    data = artifacts[index.native["systemd"]]
    who = "linux_person"
    kind = "native"
    media = "application/json"
    revision = 2
    if change == "wrong-operator":
        who = "windows_person"
    elif change == "stale":
        revision = 1
    elif change == "private-key":
        data = b'{"note":"-----BEGIN PRIVATE KEY-----"}'
        kind = "public_json"
    elif change == "credential-key":
        data = b'{"access_token":"do-not-retain"}'
        kind = "public_json"
    elif change == "bearer":
        data = b'{"note":"Bearer do-not-retain"}'
        kind = "public_json"
    elif change == "duplicate-json":
        data = b'{"x":1,"x":2}'
        kind = "public_json"
    elif change == "binary":
        data = b"not-a-public-tpm-signature"
        kind = "tpm_signature"
        media = "application/octet-stream"
    else:
        data = b" " * (2 * 1048576 + 1)
    response = clients[who].post(
        P + f"/{identifier}/artifacts",
        params={"expected_revision": revision, "kind": kind, "evidence_reference": "operator/negative"},
        content=data,
        headers={"Content-Type": media},
    )
    assert response.status_code in {403, 409, 413, 422}, response.text
    assert db.query(AssuranceBlob).count() == 0
    assert "do-not-retain" not in response.text


def test_missing_originals_and_native_gaps_cannot_freeze(people):
    clients, _, identifier, value, _, index, _, artifacts, _, _ = created(people)
    response = clients["verifier_person"].post(
        P + f"/{identifier}/freeze",
        json={"expected_revision": 2, "evidence_reference": "verifier/missing", "index": index.model_dump(mode="json")},
    )
    assert response.status_code == 409
    from shared_models.host_collection import HostReceipt

    old = index.native["tpm"]
    e = NativeEvidence.model_validate_json(artifacts.pop(old))
    e = e.model_copy(
        update={
            "snapshot": e.snapshot.model_copy(
                update={"receipts": [HostReceipt(input_id="tpm", status="UNAVAILABLE", reason="NOT_FOUND")]}
            )
        }
    )
    data = canonical(e)
    new = hashlib.sha256(data).hexdigest()
    artifacts[new] = data
    index = index.model_copy(
        update={"native": {**index.native, "tpm": new}, "checks": {**index.checks, "native_tpm": [new]}}
    )
    value = upload_all(clients, identifier, value, index, artifacts)
    assert value["record"]["payload"]["artifacts"][new]["native_result"] == "BLOCKED_NATIVE_GAPS_OR_TRUTH_MISMATCH"
    response = clients["verifier_person"].post(
        P + f"/{identifier}/freeze",
        json={
            "expected_revision": value["record"]["revision"],
            "evidence_reference": "verifier/gap",
            "index": index.model_dump(mode="json"),
        },
    )
    assert response.status_code == 409


@pytest.mark.parametrize("change", ["operator-review", "other-reviewer", "signature", "index", "tenant", "expired"])
def test_review_requires_assigned_human_and_exact_external_signature(people, change):
    clients, _, identifier, value, _, _, reviews, _, keys, _ = frozen(people)
    proof = reviews[0]
    who = "assessor_person"
    if change == "operator-review":
        who = "linux_person"
    elif change == "other-reviewer":
        who = "acceptor_person"
    elif change == "signature":
        proof = proof.model_copy(update={"signature": base64.b64encode(b"x" * 64).decode()})
    else:
        field = "index_sha256" if change == "index" else "tenant_id" if change == "tenant" else "expires_at"
        new = (
            "a" * 64
            if change == "index"
            else "other-bank"
            if change == "tenant"
            else datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        proof = signed(keys[0], proof.statement.model_copy(update={field: new}))
    response = clients[who].post(
        P + f"/{identifier}/reviews",
        json={
            "expected_revision": value["record"]["revision"],
            "evidence_reference": "negative/review",
            "review": proof.model_dump(mode="json"),
        },
    )
    assert response.status_code in {403, 422}, response.text
    assert not clients["reader_a"].get(P + f"/{identifier}").json()["record"]["payload"]["reviews"]


def test_signed_rejection_retained_and_cannot_be_overwritten(people):
    clients, _, identifier, value, _, _, reviews, _, keys, _ = frozen(people)
    rejected = signed(keys[0], reviews[0].statement.model_copy(update={"decision": "REJECT"}))
    body = {
        "expected_revision": value["record"]["revision"],
        "evidence_reference": "independent/real-decision",
        "review": rejected.model_dump(mode="json"),
    }
    response = clients["assessor_person"].post(P + f"/{identifier}/reviews", json=body)
    assert response.status_code == 200, response.text
    result = response.json()
    assert (
        result["state"] == "BLOCKED"
        and result["record"]["payload"]["reviews"]["independent_assessor"]["statement"]["decision"] == "REJECT"
    )
    body.update(expected_revision=result["record"]["revision"], review=reviews[0].model_dump(mode="json"))
    assert clients["assessor_person"].post(P + f"/{identifier}/reviews", json=body).status_code == 409


@pytest.mark.parametrize("change", ["role", "membership", "user-disabled", "review-expiry"])
def test_live_status_rechecks_authority_and_expiry(people, monkeypatch, change):
    clients, db, identifier, value, _, _, reviews, _, _, assignments = frozen(people)
    for who, proof in zip(["assessor_person", "acceptor_person"], reviews):
        response = clients[who].post(
            P + f"/{identifier}/reviews",
            json={
                "expected_revision": value["record"]["revision"],
                "evidence_reference": "signed/fixture",
                "review": proof.model_dump(mode="json"),
            },
        )
        assert response.status_code == 200
        value = response.json()
    assert value["state"] == "SCOPED_EXTERNAL_RECORD_VERIFIED"
    if change == "role":
        db.get(User, assignments["linux_operator"]["user_id"]).roles = "readonly"
        db.commit()
    elif change == "user-disabled":
        db.get(User, assignments["linux_operator"]["user_id"]).is_active = False
        db.commit()
    elif change == "membership":
        db.delete(db.query(TenantMembership).filter_by(tenant_id="a", username="assessor_person").one())
        db.commit()
    else:
        monkeypatch.setattr(
            "api.assurance.qualification.utcnow", lambda: datetime.now(timezone.utc) + timedelta(hours=2)
        )
    value = clients["reader_a"].get(P + f"/{identifier}").json()
    assert value["state"] == "BLOCKED" and value["blockers"] and value["verification"] is None


def test_frozen_assignments_originals_withdrawal_and_rbac(people):
    clients, _, identifier, value, policy, index, _, artifacts, _, assignments = frozen(people)
    rev = value["record"]["revision"]
    assert (
        clients["bank_a"]
        .post(
            P,
            json={
                "policy": policy.model_dump(mode="json"),
                "return_channel_reference": "synthetic/channel-approval-reference-only",
                "evidence_reference": "not/trust",
            },
        )
        .status_code
        == 403
    )
    assert clients["bank_b"].get(P).json()["campaigns"] == []
    assert (
        admin(clients)
        .post(
            P + f"/{identifier}/assignments",
            json={"expected_revision": rev, "evidence_reference": "change/frozen", "assignments": assignments},
        )
        .status_code
        == 409
    )
    data = next(iter(artifacts.values()))
    assert (
        clients["linux_person"]
        .post(
            P + f"/{identifier}/artifacts",
            params={"expected_revision": rev, "kind": "public_json", "evidence_reference": "frozen/input"},
            content=data,
            headers={"Content-Type": "application/json"},
        )
        .status_code
        == 409
    )
    assert (
        clients["bank_a"]
        .post(P + f"/{identifier}/withdraw", json={"expected_revision": rev, "evidence_reference": "not/trust"})
        .status_code
        == 403
    )
    withdrawn = admin(clients).post(
        P + f"/{identifier}/withdraw", json={"expected_revision": rev, "evidence_reference": "change/withdrawn"}
    )
    assert withdrawn.status_code == 200
    assert withdrawn.json()["state"] == "WITHDRAWN"
    assert (
        clients["verifier_person"]
        .post(
            P + f"/{identifier}/freeze",
            json={
                "expected_revision": rev + 1,
                "evidence_reference": "withdrawn/retry",
                "index": index.model_dump(mode="json"),
            },
        )
        .status_code
        == 409
    )


def test_blob_and_audit_publication_roll_back_atomically(people, monkeypatch):
    clients, db, identifier, _, _, index, _, artifacts, _, _ = created(people)
    original = UserRepository.audit

    def fail(self, user, action, **kwargs):
        if action == "qualification.artifact_received":
            raise RuntimeError("owned audit failure")
        return original(self, user, action, **kwargs)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="owned audit failure"):
        clients["linux_person"].post(
            P + f"/{identifier}/artifacts",
            params={"expected_revision": 2, "kind": "native", "evidence_reference": "test/audit-failure"},
            content=artifacts[index.native["systemd"]],
            headers={"Content-Type": "application/json"},
        )
    assert db.query(AssuranceBlob).count() == 0
    assert clients["reader_a"].get(P + f"/{identifier}").json()["record"]["revision"] == 2


def test_original_tamper_never_remains_verified(people):
    clients, db, identifier, value, _, _, _, _, _, _ = frozen(people)
    entry = next(iter(value["record"]["payload"]["artifacts"].values()))
    # Deliberate administrator/Core tamper; do not weaken append-only ORM guard.
    db.connection().execute(
        AssuranceBlob.__table__.update().where(AssuranceBlob.__table__.c.id == entry["blob_id"]).values(data=b"corrupt")
    )
    db.commit()
    assert clients["reader_a"].get(P + f"/{identifier}").status_code == 409


@pytest.mark.parametrize("kind", ["machine", "legacy-nondurable"])
def test_all_routes_require_current_typed_durable_human_even_for_metadata(people, kind):
    clients, db, identifier, _, policy, index, _, originals, _, assignments = created(people)
    client = TestClient(clients["bank_a"].app)
    try:
        if kind == "machine":
            from db.repositories.api_key_repository import ApiKeyRepository

            _, raw = ApiKeyRepository(db).create(
                name="synthetic-qualification-key", created_by="bank_a", roles=["ciso"], tenant_id="a"
            )
            db.commit()
            headers = {"X-API-Key": raw}
        else:
            token = SessionManager().create_session("bank_a", roles=["ciso"])
            client.cookies.set("cryptoscan_session", token)
            headers = {}
        for suffix in [
            "",
            f"/{identifier}",
            f"/{identifier}/export",
            f"/{identifier}/artifacts/{index.native['systemd']}",
        ]:
            assert client.get(P + suffix, headers=headers).status_code in {401, 403}
        for path in [
            "/api/v1/assurance/records?kind=host_qualification",
            f"/api/v1/assurance/records/host_qualification/{identifier}",
        ]:
            assert client.get(path, headers=headers).status_code in {401, 403}
        response = client.post(
            P,
            json={
                "policy": policy.model_dump(mode="json"),
                "return_channel_reference": "synthetic/channel-only",
                "evidence_reference": "synthetic/ref",
            },
            headers=headers,
        )
        assert response.status_code in {401, 403}
        response = client.post(
            P + f"/{identifier}/assignments",
            json={"expected_revision": 2, "evidence_reference": "synthetic/ref", "assignments": assignments},
            headers=headers,
        )
        assert response.status_code in {401, 403}
        response = client.post(
            P + f"/{identifier}/artifacts",
            params={"expected_revision": 2, "kind": "native", "evidence_reference": "synthetic/ref"},
            content=originals[index.native["systemd"]],
            headers={**headers, "Content-Type": "application/json"},
        )
        assert response.status_code in {401, 403}
    finally:
        client.close()
    assert db.query(AssuranceBlob).count() == 0


def test_channel_reference_required_and_never_inferred_from_endpoint(people):
    clients, _, _ = people
    policy, *_ = packet()
    response = admin(clients).post(
        P, json={"policy": policy.model_dump(mode="json"), "evidence_reference": "synthetic/ref"}
    )
    assert response.status_code == 422
    assert admin(clients).get(P).json()["campaigns"] == []


def test_history_budget_always_reserves_a_durable_withdrawal(people, monkeypatch):
    clients, _, identifier, _, _, index, _, originals, _, _ = created(people)
    monkeypatch.setattr("api.assurance.qualification.MAX_REV", 3)
    response = clients["linux_person"].post(
        P + f"/{identifier}/artifacts",
        params={"expected_revision": 2, "kind": "native", "evidence_reference": "synthetic/budget"},
        content=originals[index.native["systemd"]],
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 409
    response = admin(clients).post(
        P + f"/{identifier}/withdraw", json={"expected_revision": 2, "evidence_reference": "synthetic/reserved-stop"}
    )
    assert response.status_code == 200
    assert response.json()["state"] == "WITHDRAWN" and response.json()["record"]["revision"] == 3
    assert admin(clients).get(P + f"/{identifier}/export").json()["state"] == "WITHDRAWN"
