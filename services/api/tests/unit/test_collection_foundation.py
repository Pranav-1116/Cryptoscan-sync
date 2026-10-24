"""Phase 1 uses actual sessions, approvals, original evidence and existing storage."""

from datetime import datetime, timedelta, timezone
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_host_evidence import setup
from test_execution_controls import controlled as controlled
from db.models.assurance import AssuranceRevision
from db.repositories.user_repository import UserRepository, verify_audit_chain
from shared_models.collection import TargetSpec
from inventory.collection import OfflineLinuxCollector

P = "/api/v1/collection"


def target_body(assured):
    clients, db, _, body, _ = setup(assured)
    value = {
        "target_key": "payments-linux-01",
        "system_id": "system-a",
        "owner": "Payments platform",
        "environment": "prod",
        "collection_method": "offline_host",
        "address": "payments-1",
        "credential_ref": None,
        "allowed_operations": ["READ_APPROVED_METADATA"],
        "not_before": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "manifest": body["manifest"],
    }
    return clients, db, value


def registered(assured):
    clients, db, body = target_body(assured)
    row = clients["bank_a"].post(P + "/targets", json=body)
    assert row.status_code == 201, row.text
    return clients, db, body, row.json()


def decision(revision):
    return {
        "expected_revision": revision,
        "evidence_ref": "change/phase-one-17",
        "reason": "Approved explicit metadata scope for controlled offline handoff",
    }


def prepared(assured):
    clients, db, body, row = registered(assured)
    authorized = admin(clients).post(P + f"/targets/{row['subject_id']}/authorize", json=decision(1))
    assert authorized.status_code == 200, authorized.text
    auth = authorized.json()
    job = clients["bank_a"].post(P + "/jobs", json={"target_id": row["subject_id"], "expected_target_revision": 2})
    assert job.status_code == 201, job.text
    return clients, db, body, auth, job.json()


def imported(clients, body, auth):
    snapshot = OfflineLinuxCollector().collect(TargetSpec.model_validate(body))
    response = clients["bank_a"].post(
        "/api/v1/host-evidence/approvals/" + auth["payload"]["approval_id"] + "/intake",
        json={"snapshot": snapshot.model_dump(mode="json")},
    )
    return response


def completed(assured):
    clients, db, body, auth, job = prepared(assured)
    jid = job["subject_id"]
    handoff = clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1})
    assert handoff.status_code == 200, handoff.text
    intake = imported(clients, body, auth)
    assert intake.status_code == 201, intake.text
    finish = clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 2})
    assert finish.status_code == 200, finish.text
    return clients, db, body, auth, finish.json()


def test_phase_one_end_to_end_single_evidence_source_and_six_projections(assured):
    clients, db, body, auth, job = completed(assured)
    assert job["payload"]["state"] == "PARTIAL"  # missing approved certificate remains a collection gap
    jid = job["subject_id"]
    evidence = clients["reader_a"].get(P + f"/jobs/{jid}/evidence")
    assert evidence.status_code == 200, evidence.text
    value = evidence.json()
    assert value["provenance"] == "IMPORTED" and value["runtime_use"] == value["pqc_use"] == "UNKNOWN"
    assert value["coverage"]["approved_inputs"] == 4 and value["coverage"]["parsed_inputs"] == 3
    assert value["coverage"]["whole_host_percent"] is None
    assert value["errors"][0]["asset_absence_proven"] is False
    assert all(o["evidence_id"] and o["fact_sha256"] and o["provenance"] == "IMPORTED" for o in value["observations"])
    projection = clients["reader_a"].get(P + f"/jobs/{jid}/projections").json()
    assert set(projection["domains"]) == {"SBOM", "CBOM", "NBOM", "HBOM", "VBOM", "TechBOM"}
    assert not projection["domains"]["NBOM"]["observations"] and not projection["standard_document"]
    assert projection["envelope_sha256"] == value["envelope_sha256"]
    from db.models.scan import Scan

    assert db.query(Scan).count() == 1
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_readers_inspect_but_cannot_change_registry_or_jobs(assured, role):
    clients, db, body, auth, job = completed(assured)
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    reader = clients["reader_a"]
    tid = auth["subject_id"]
    jid = job["subject_id"]
    assert reader.get(P + f"/targets/{tid}").status_code == 200
    assert reader.get(P + f"/jobs/{jid}/evidence").status_code == 200
    assert reader.post(P + "/targets", json=body).status_code == 403
    assert reader.post(P + f"/targets/{tid}/revoke", json=decision(2)).status_code == 403
    assert reader.post(P + f"/jobs/{jid}/complete", json={"expected_revision": 3}).status_code == 403
    assert clients["bank_a"].post(P + f"/targets/{tid}/authorize", json=decision(2)).status_code == 403


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_exact_estate_even_for_unselected_platform_admin(assured, who):
    clients, _, _, auth, job = completed(assured)
    for suffix in [
        f"/targets/{auth['subject_id']}",
        f"/jobs/{job['subject_id']}",
        f"/jobs/{job['subject_id']}/evidence",
    ]:
        assert clients[who].get(P + suffix).status_code == 404


@pytest.mark.parametrize("change", ["revoke", "update"])
def test_revocation_or_scope_update_blocks_old_handoff_and_legacy_intake(assured, change):
    clients, db, body, auth, job = prepared(assured)
    tid = auth["subject_id"]
    if change == "revoke":
        response = admin(clients).post(P + f"/targets/{tid}/revoke", json=decision(2))
    else:
        response = admin(clients).put(P + f"/targets/{tid}", json={"expected_revision": 2, "target": body})
    assert response.status_code == 200, response.text
    assert imported(clients, body, auth).status_code == 409
    assert (
        clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 1}).status_code
        == 409
    )
    assert (
        clients["reader_a"].get(P + f"/jobs/{job['subject_id']}").json()["current_authorization_admits_new_work"]
        is False
    )


def test_historical_envelope_remains_inspectable_after_revoke(assured):
    clients, db, body, auth, job = completed(assured)
    assert admin(clients).post(P + f"/targets/{auth['subject_id']}/revoke", json=decision(2)).status_code == 200
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence").status_code == 200


def test_stable_target_identity_updates_require_fresh_authorization(assured):
    clients, db, body, auth, job = prepared(assured)
    tid = auth["subject_id"]
    changed = {**body, "owner": "New team"}
    updated = admin(clients).put(P + f"/targets/{tid}", json={"expected_revision": 2, "target": changed})
    assert updated.status_code == 200 and updated.json()["subject_id"] == tid
    assert updated.json()["payload"]["state"] == "REGISTERED"
    assert (
        clients["bank_a"].post(P + "/jobs", json={"target_id": tid, "expected_target_revision": 3}).status_code == 409
    )
    assert (
        admin(clients)
        .put(P + f"/targets/{tid}", json={"expected_revision": 3, "target": {**changed, "target_key": "different"}})
        .status_code
        == 409
    )


@pytest.mark.parametrize("change", ["exclusion", "secret", "remote_operation", "expiry_number"])
def test_scope_and_secret_validation(assured, change):
    clients, _, body = target_body(assured)
    if change == "exclusion":
        body["exclusions"] = ["cert"]
    if change == "secret":
        body["credential_ref"] = "password-secret"
    if change == "remote_operation":
        body["allowed_operations"] = ["RUN_COMMAND"]
    if change == "expiry_number":
        body["not_before"] = 123
    assert clients["bank_a"].post(P + "/targets", json=body).status_code == 422


def test_unadapted_collectors_register_but_cannot_be_authorized(assured):
    clients, _, body = target_body(assured)
    body.update(collection_method="network", manifest=None, address="10.0.0.0/8")
    registered = clients["bank_a"].post(P + "/targets", json=body)
    assert registered.status_code == 201
    assert (
        admin(clients).post(P + f"/targets/{registered.json()['subject_id']}/authorize", json=decision(1)).status_code
        == 409
    )


@pytest.mark.parametrize("action", ["target.register", "target.authorize", "job.complete"])
def test_atomic_audit_failure_never_leaves_partial_control_transition(assured, monkeypatch, action):
    if action == "target.register":
        clients, db, body = target_body(assured)
    else:
        clients, db, body, auth, job = prepared(assured)
    if action == "job.complete":
        assert (
            clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/handoff", json={"expected_revision": 1}).status_code
            == 200
        )
        assert imported(clients, body, auth).status_code == 201
    baseline = db.query(AssuranceRevision).count()
    original = UserRepository.audit

    def fail(self, *args, **kw):
        if args[1] == "collection." + action:
            raise RuntimeError("synthetic atomic failure")
        return original(self, *args, **kw)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="atomic failure"):
        if action == "target.register":
            clients["bank_a"].post(P + "/targets", json=body)
        elif action == "target.authorize":
            # Renew registration so this is a fresh valid authorization attempt.
            admin(clients).put(P + f"/targets/{auth['subject_id']}", json={"expected_revision": 2, "target": body})
            baseline += 1
            admin(clients).post(P + f"/targets/{auth['subject_id']}/authorize", json=decision(3))
        else:
            clients["bank_a"].post(P + f"/jobs/{job['subject_id']}/complete", json={"expected_revision": 2})
    assert db.query(AssuranceRevision).count() == baseline


def test_changed_source_or_revision_is_never_silently_reprojected(assured):
    clients, db, _, _, job = completed(assured)
    from db.models.evidence_record import EvidenceRecord

    db.query(EvidenceRecord).first().finding_data = {"corrupt": True}
    db.commit()
    assert clients["reader_a"].get(P + f"/jobs/{job['subject_id']}/evidence").status_code == 409


def test_phase_two_linux_os_metadata_joins_same_envelope_and_not_crypto(assured):
    clients, db, body = target_body(assured)
    _, _, tmp = assured
    path = tmp / "os-release"
    path.write_text('ID=ubuntu\nVERSION_ID="24.04"\nPASSWORD=never-upload\n')
    body["manifest"]["inputs"].append({"input_id": "os", "kind": "LINUX_OS_RELEASE", "path": str(path)})
    target = clients["bank_a"].post(P + "/targets", json=body).json()
    auth = admin(clients).post(P + f"/targets/{target['subject_id']}/authorize", json=decision(1)).json()
    job = (
        clients["bank_a"]
        .post(P + "/jobs", json={"target_id": target["subject_id"], "expected_target_revision": 2})
        .json()
    )
    jid = job["subject_id"]
    assert clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1}).status_code == 200
    intake = imported(clients, body, auth)
    assert intake.status_code == 201, intake.text
    result = clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 2})
    assert result.status_code == 200, result.text
    envelope = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
    os = next(o for o in envelope["observations"] if o["fact"]["kind"] == "OS_RELEASE")
    assert os["contributes_to"] == ["TechBOM"] and os["provenance"] == "IMPORTED"
    assert os["fact"]["local_basis"] == "DECLARED" and os["fact"]["software_version"] == "24.04"
    assert "never-upload" not in str(envelope)
    cbom = clients["reader_a"].get("/api/v1/host-evidence/approvals/" + auth["payload"]["approval_id"] + "/cbom")
    assert cbom.status_code == 200 and cbom.json()["specVersion"] == "1.6"
    assert all(c.get("name") != "ubuntu" for c in cbom.json().get("components", []))


def test_software_metadata_slot_is_stable_across_versioned_collection_history(assured):
    clients, db, body = target_body(assured)
    _, _, tmp = assured
    path = tmp / "dpkg-status"
    body["manifest"]["inputs"] = [{"input_id": "packages", "kind": "DPKG_STATUS", "path": str(path)}]
    target = clients["bank_a"].post(P + "/targets", json=body).json()
    tid = target["subject_id"]
    slots = []
    observations = []
    versions = []
    for index, version in enumerate(["3.0.13", "3.0.17"]):
        revision = 1 if index == 0 else 3
        if index:
            assert (
                admin(clients).put(P + f"/targets/{tid}", json={"expected_revision": 2, "target": body}).status_code
                == 200
            )
        auth = admin(clients).post(P + f"/targets/{tid}/authorize", json=decision(revision)).json()
        job = (
            clients["bank_a"]
            .post(P + "/jobs", json={"target_id": tid, "expected_target_revision": revision + 1})
            .json()
        )
        jid = job["subject_id"]
        assert clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1}).status_code == 200
        path.write_text(f"Package: openssl\nStatus: install ok installed\nVersion: {version}\n\n")
        result = imported(clients, body, auth)
        assert result.status_code == 201, result.text
        assert clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 2}).status_code == 200
        evidence = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
        obs = evidence["observations"][0]
        slots.append(obs["identity_slot"])
        observations.append(obs["observation_id"])
        versions.append(obs["fact"]["software_version"])
        assert obs["source"]["path"] == str(path) and obs["source"]["input_content_sha256"]
    assert slots[0] == slots[1] and observations[0] != observations[1] and versions == ["3.0.13", "3.0.17"]


@pytest.mark.parametrize(
    "method,budget,scope", [("post", 10, "host_write"), ("put", 10, "host_write"), ("get", 60, "host_read")]
)
def test_universal_routes_inherit_actual_strict_rate_buckets(assured, method, budget, scope):
    from fastapi.testclient import TestClient
    from api.middleware.rate_limit import RateLimitMiddleware

    clients, db, _ = assured
    with TestClient(RateLimitMiddleware(clients["bank_a"].app)) as limited:
        limited.cookies.update(clients["bank_a"].cookies)
        if method == "get":
            request = lambda: limited.get(P + "/targets/missing")
        elif method == "put":
            request = lambda: limited.put(P + "/targets/missing", json={})
        else:
            request = lambda: limited.post(P + "/targets", json={})
        responses = [request() for _ in range(budget + 1)]
    assert all(r.status_code == (404 if method == "get" else 422) for r in responses[:budget])
    assert responses[-1].status_code == 429 and responses[-1].json()["scope"] == scope


def test_universal_request_boundary_rejects_duplicate_and_oversized_json(assured):
    clients, _, _ = assured
    for raw, status in [
        (b'{"owner":"a","owner":"b"}', 422),
        (b'{"x":' + b"[" * 30 + b"0" + b"]" * 30 + b"}", 422),
        (b" " * 2097153, 413),
    ]:
        result = clients["bank_a"].post(P + "/targets", content=raw, headers={"Content-Type": "application/json"})
        assert result.status_code == status, result.text
        assert result.headers["Cache-Control"] == "no-store"


def test_failed_collection_is_not_an_empty_success_or_asset_absence(assured):
    clients, db, body = target_body(assured)
    _, _, tmp = assured
    body["manifest"]["inputs"] = [
        {"input_id": "not-found", "kind": "PUBLIC_CERTIFICATE", "path": str(tmp / "absent-cert.pem")}
    ]
    target = clients["bank_a"].post(P + "/targets", json=body).json()
    tid = target["subject_id"]
    auth = admin(clients).post(P + f"/targets/{tid}/authorize", json=decision(1)).json()
    job = clients["bank_a"].post(P + "/jobs", json={"target_id": tid, "expected_target_revision": 2}).json()
    jid = job["subject_id"]
    assert clients["bank_a"].post(P + f"/jobs/{jid}/handoff", json={"expected_revision": 1}).status_code == 200
    assert imported(clients, body, auth).status_code == 201
    result = clients["bank_a"].post(P + f"/jobs/{jid}/complete", json={"expected_revision": 2})
    assert result.status_code == 200 and result.json()["payload"]["state"] == "FAILED"
    value = clients["reader_a"].get(P + f"/jobs/{jid}/evidence").json()
    assert not value["observations"] and value["coverage"]["whole_host_percent"] is None
    assert value["errors"][0]["asset_absence_proven"] is False


def test_universal_surface_is_not_a_production_fallback(controlled):
    from test_execution_controls import configure

    configure(controlled)
    client = controlled["clients"]["bank_a"]
    assert client.get(P + "/collectors").status_code == 409
    assert client.get(P + "/targets").status_code == 409
    assert client.post(P + "/targets", json={}).status_code == 409
    assert client.put(P + "/targets/unknown", json={}).status_code == 409
