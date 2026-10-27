"""Real SQL/auth/API control contracts; launchers are test doubles, NOT escape qualification."""
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from api.main import create_app
from api.middleware.auth_middleware import AuthMiddleware
from api.middleware.tenant_scope import TenantScopeMiddleware
from db.connection.session import SessionLocal
from db.models.base import utcnow
from db.models.execution_control import ScanApproval, ExecutionAttempt, ExecutionBudget, ExecutionOutbox
from db.models.scan_job import ScanJob as JobRow
from db.models.user import User
from db.repositories import execution_control as controls
from db.repositories.execution_outbox import dispatch_one, dispatch_pending
from db.repositories.job_repository import JobRepository
from db.tenancy import tenant_scope
from worker.core.job_consumer import ScanJob
from worker.core.job_executor import JobExecutor
from worker.core.queued_authority import claim, QueueRefused
from test_software_supply_chain_api import banks as banks

PREFIX = "/api/v1/execution-controls"


@pytest.fixture()
def controlled(banks, monkeypatch):
    old_clients, db, tmp = banks
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_CONTROLS", "true")
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_REGION", "in-south")
    monkeypatch.setenv("CRYPTOSCAN_EVIDENCE_REGION", "in-south")
    monkeypatch.setenv("CRYPTOSCAN_EVIDENCE_DESTINATION", "regional-sql-a")
    from api.security import scan_admission
    monkeypatch.setattr(scan_admission, "_control_plane_state", lambda: ([], {}))
    monkeypatch.setattr(scan_admission, "_enforce_queue_depth", lambda: None)
    monkeypatch.setattr(scan_admission, "_ot_declared", lambda: False)
    monkeypatch.setattr("worker.core.job_executor.gate_job", lambda *_a, **_kw: (True, None))
    # Tests below isolate SQL authority, not a provisioned Docker engine.
    monkeypatch.setattr("worker.core.controlled_source.preflight", lambda: None)
    published = []
    monkeypatch.setattr("api.routers.trigger._run_inline", lambda p: published.append(p))
    app = create_app()
    app.add_middleware(TenantScopeMiddleware)
    app.add_middleware(AuthMiddleware)
    clients = {}
    for name, old in old_clients.items():
        client = TestClient(app)
        client.cookies.update(old.cookies)
        clients[name] = client
    source = tmp / "approved-source"
    source.mkdir()
    (source / "crypto.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    state = {"clients": clients, "db": db, "target": str(source), "tmp": tmp, "published": published}
    try:
        yield state
    finally:
        for client in clients.values():
            client.close()


def configure(state, owner="a", **overrides):
    admin = state["clients"]["platform_admin"]
    headers = {"X-Tenant-ID": owner} if owner else {}
    response = admin.put(PREFIX + "/provider-budget", json={"capacity": 4, "requests_per_second": 10})
    assert response.status_code == 200, response.text
    body = {"expected_revision": 0, "legal_entity": "Bank " + str(owner), "execution_region": "in-south",
            "evidence_region": "in-south", "evidence_destination": "regional-sql-a", "max_runtime_seconds": 120,
            "capacity": 2, "requests_per_second": 5, **overrides}
    response = admin.put(PREFIX + "/policy", headers=headers, json=body)
    assert response.status_code == 200, response.text
    return body


def approve(state, owner="a", **changes):
    db = state["db"]
    subject = db.execute(select(User).where(User.username == "bank_" + owner)).scalar_one()
    now = utcnow()
    body = {"target": state["target"], "subject_kind": "user", "subject_id": subject.id,
            "not_before": (now - timedelta(minutes=1)).isoformat(), "expires_at": (now + timedelta(minutes=10)).isoformat(),
            "max_requests": 10, "evidence_ref": "change/BANK-123", **changes}
    response = state["clients"]["platform_admin"].post(PREFIX + "/approvals", headers={"X-Tenant-ID": owner}, json=body)
    assert response.status_code == 201, response.text
    return response.json()


def queue(state, user="bank_a"):
    response = state["clients"][user].post("/api/v1/scans/trigger", json={"repo_url": state["target"], "scan_mode": "safe"})
    assert response.status_code == 202, response.text
    state["db"].expire_all()
    row = state["db"].execute(select(JobRow).where(JobRow.id == response.json()["job_id"])).scalar_one()
    return row, ScanJob(job_id=row.id, **{k: getattr(row, k) for k in
        ("tenant_id", "target_repo", "target_branch", "target_commit", "triggered_by", "job_type", "system_id")}, progress=deepcopy(row.progress))


def test_positive_grant_and_original_credential_are_durable_before_publish(controlled):
    s = controlled
    configure(s)
    approval = approve(s)
    row, payload = queue(s)
    authority = row.progress["execution_authority"]
    assert authority["v"] == 2 and authority["kind"] == "user"
    assert authority["credential_id"] and authority["request_id"] and authority["estate"] == "a"
    assert authority["path"] == "/api/v1/scans/trigger" and authority["method"] == "POST"
    assert row.progress["execution_control"]["approval_id"] == approval["id"]
    assert row.progress["execution_control"]["evidence_destination"] == "regional-sql-a"
    assert s["db"].query(ExecutionOutbox).one().state == "PENDING"
    assert s["published"][0]["progress"] == row.progress
    assert not any(token in json.dumps(row.progress) for token in s["clients"]["bank_a"].cookies.values())
    # Queue hint cannot select another approval, owner, identity or target.
    for changed in (replace(payload, tenant_id="b"), replace(payload, target_repo="/etc"),
                    replace(payload, progress={"scan_options": {"active": True}})):
        assert not JobExecutor().execute(changed)
    s["db"].expire_all()
    assert row.status == "QUEUED"


def test_absent_expired_ambiguous_wrong_subject_and_region_are_refused(controlled, monkeypatch):
    s = controlled
    client = s["clients"]["bank_a"]
    assert client.post("/api/v1/scans/trigger", json={"repo_url": s["target"]}).status_code == 409
    configure(s)
    a = approve(s)
    # Overlapping approvals are deliberately not selected arbitrarily.
    approve(s)
    assert client.post("/api/v1/scans/trigger", json={"repo_url": s["target"]}).status_code == 409
    admin = s["clients"]["platform_admin"]
    assert admin.post(PREFIX + f"/approvals/{a['id']}/revoke", headers={"X-Tenant-ID": "a"}).status_code == 200
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_REGION", "eu-west")
    assert client.post("/api/v1/scans/trigger", json={"repo_url": s["target"]}).status_code == 409
    assert s["db"].query(JobRow).count() == 0


@pytest.mark.parametrize("change", ["revoke", "policy", "session", "role", "membership", "destination", "expiry"])
def test_fresh_claim_refuses_changed_authority_or_approval(controlled, change, monkeypatch):
    s = controlled
    policy = configure(s)
    a = approve(s)
    row, payload = queue(s)
    db = s["db"]
    if change == "revoke":
        s["clients"]["platform_admin"].post(PREFIX + f"/approvals/{a['id']}/revoke", headers={"X-Tenant-ID": "a"})
    elif change == "policy":
        response = s["clients"]["platform_admin"].put(PREFIX + "/policy", headers={"X-Tenant-ID": "a"}, json={**policy, "expected_revision": 1, "stopped": True})
        assert response.status_code == 200
    elif change == "session":
        from db.models.user import UserSession
        db.execute(update(UserSession).where(UserSession.id == row.progress["execution_authority"]["credential_id"]).values(revoked_at=utcnow()))
        db.commit()
    elif change == "role":
        db.execute(update(User).where(User.username == "bank_a").values(roles="readonly"))
        db.commit()
    elif change == "membership":
        from db.models.tenant import TenantMembership
        db.execute(update(TenantMembership).where(TenantMembership.username == "bank_a").values(tenant_role="viewer"))
        db.commit()
    elif change == "destination":
        monkeypatch.setenv("CRYPTOSCAN_EVIDENCE_DESTINATION", "foreign-bucket")
    else:
        approval = db.get(ScanApproval, a["id"])
        contract = {**approval.contract, "expires_at": (utcnow() - timedelta(seconds=1)).isoformat()}
        approval.contract = contract
        db.commit()
    assert not JobExecutor().execute(payload)
    db.expire_all()
    assert row.status == "FAILED" and db.query(ExecutionAttempt).count() == 0
    assert all(b.active == 0 for b in db.query(ExecutionBudget))


def test_api_key_original_id_and_verifier_prevent_name_replacement_and_collisions(controlled):
    from db.repositories.api_key_repository import ApiKeyRepository
    from db.models.api_key import ApiKey
    s = controlled
    configure(s)
    with tenant_scope("a"):
        key, raw = ApiKeyRepository(s["db"]).create(name="bot", created_by="platform_admin", roles=["scanner"])
        s["db"].commit()
    a = approve(s, subject_kind="api_key", subject_id=key.id)
    client = s["clients"]["bank_a"]
    response = client.post("/api/v1/scans/trigger", headers={"X-API-Key": raw}, json={"repo_url": s["target"]})
    assert response.status_code == 202, response.text
    row = s["db"].get(JobRow, response.json()["job_id"])
    assert row.progress["execution_authority"]["id"] == key.id
    assert raw not in json.dumps(row.progress)
    descriptor = ScanJob(job_id=row.id, target_repo=row.target_repo, tenant_id="a", triggered_by=row.triggered_by, progress=deepcopy(row.progress))
    s["db"].execute(update(ApiKey).where(ApiKey.id == key.id).values(revoked_at=utcnow()))
    with tenant_scope("a"):
        replacement, _ = ApiKeyRepository(s["db"]).create(name="bot", created_by="platform_admin", roles=["scanner"])
    s["db"].commit()
    assert replacement.id != a["contract"]["subject_id"]
    assert not JobExecutor().execute(descriptor)


def test_progress_cannot_drop_or_overwrite_typed_authority(controlled):
    s = controlled
    configure(s)
    approve(s)
    row, _payload = queue(s)
    original = deepcopy(row.progress)
    JobRepository(s["db"]).update_status(row.id, "RUNNING", progress={"current_stage": "test", "execution_authority": {"kind": "user", "id": "forged"}})
    s["db"].commit()
    s["db"].refresh(row)
    for name in ("execution_authority", "execution_control"):
        assert row.progress[name] == original[name]


def test_attempt_claim_checkpoint_stop_unknown_and_operator_reconciliation(controlled):
    s = controlled
    policy = configure(s)
    approve(s)
    row, descriptor = queue(s)
    with tenant_scope("a"):
        active = claim(descriptor)
        with controls.execution_scope(active):
            controls.checkpoint("before-parser", request=True)
            response = s["clients"]["platform_admin"].put(PREFIX + "/policy", headers={"X-Tenant-ID": "a"}, json={**policy, "expected_revision": 1, "stopped": True})
            assert response.status_code == 200
            with pytest.raises(controls.ExecutionDenied):
                controls.checkpoint("must-not-run")
        controls.finish_attempt(active, False)
    s["db"].expire_all()
    attempt = s["db"].query(ExecutionAttempt).one()
    assert attempt.status == "UNKNOWN" and row.status == "UNKNOWN"
    assert all(b.active == 1 for b in s["db"].query(ExecutionBudget))
    assert s["clients"]["bank_a"].post(f"/api/v1/jobs/{row.id}/retry").status_code == 409
    # Exact-owner reads: NULL/platform and bank B do not inherit bank A history.
    configure(s, "b")
    configure(s, None)
    for name in ("bank_b", "platform_admin"):
        assert s["clients"][name].get(PREFIX + "/attempts").json()["attempts"] == []
    response = s["clients"]["bank_a"].get(PREFIX + "/attempts")
    assert "fence" not in response.text and "budget_ids" not in response.text
    body = {"resolution": "CONFIRMED_STOPPED", "evidence_ref": "incident/confirmed-container-gone", "confirm_external_work_stopped": True}
    admin = s["clients"]["platform_admin"]
    assert admin.post(PREFIX + f"/attempts/{attempt.id}/reconcile", headers={"X-Tenant-ID": "b"}, json=body).status_code == 404
    assert admin.post(PREFIX + f"/attempts/{attempt.id}/reconcile", headers={"X-Tenant-ID": "a"}, json=body).status_code == 200
    assert admin.post(PREFIX + f"/attempts/{attempt.id}/reconcile", headers={"X-Tenant-ID": "a"}, json=body).status_code == 409
    s["db"].expire_all()
    assert all(b.active == 0 for b in s["db"].query(ExecutionBudget))
    assert row.status == "FAILED"
    # A late old worker cannot checkpoint or settle a released lease.
    with tenant_scope("a"), controls.execution_scope(active), pytest.raises(controls.ExecutionDenied):
        controls.checkpoint("late")


def test_expiry_fences_without_restarting_or_releasing_capacity(controlled):
    s = controlled
    configure(s)
    approve(s)
    row, descriptor = queue(s)
    with tenant_scope("a"):
        active = claim(descriptor)
        with SessionLocal() as session:
            assert controls.recover_expired(session, now=utcnow() + timedelta(hours=1)) == 1
            session.commit()
        with controls.execution_scope(active), pytest.raises(controls.ExecutionDenied):
            controls.checkpoint("late")
    s["db"].expire_all()
    assert row.status == "UNKNOWN"
    assert all(b.active == 1 for b in s["db"].query(ExecutionBudget))
    assert not JobExecutor().execute(descriptor)


def test_per_estate_and_provider_reservations_are_shared_and_atomic(controlled):
    s = controlled
    configure(s, capacity=1)
    configure(s, "b", capacity=1)
    approve(s)
    approve(s, "b")
    a, da = queue(s)
    a2, da2 = queue(s)
    b, db = queue(s, "bank_b")
    with tenant_scope("a"):
        claim(da)
        with pytest.raises(QueueRefused):
            claim(da2)
    with tenant_scope("b"):
        claim(db)
    s["db"].expire_all()
    assert s["db"].get(ExecutionBudget, controls.key("estate-budget", "a")).active == 1
    assert s["db"].get(ExecutionBudget, controls.key("estate-budget", "b")).active == 1
    assert s["db"].get(ExecutionBudget, controls.key("provider-budget", "local-source/v1")).active == 2
    assert a2.status == "QUEUED"  # Losing capacity does not create an attempt.


def test_request_allowance_is_consumed_once_per_launch_not_per_worker(controlled):
    s = controlled
    configure(s)
    approve(s, max_requests=1)
    _row, descriptor = queue(s)
    with tenant_scope("a"):
        active = claim(descriptor)
        with controls.execution_scope(active):
            controls.checkpoint("first", request=True)
            with pytest.raises(controls.ExecutionDenied, match="allowance"):
                controls.checkpoint("retry", request=True)
    s["db"].expire_all()
    assert s["db"].query(ScanApproval).one().requests_used == 1


def test_outbox_reconciles_publish_failure_and_ambiguous_ack_without_duplicate_claim(controlled):
    s = controlled
    configure(s)
    approve(s)
    row, descriptor = queue(s)
    def fail(_payload):
        raise OSError("transport unavailable")
    with pytest.raises(OSError):
        dispatch_one(row.id, fail)
    s["db"].expire_all()
    outbox = s["db"].query(ExecutionOutbox).one()
    assert outbox.state == "PENDING"
    delivered = []
    assert dispatch_pending(delivered.append) == 1
    assert delivered[0]["progress"] == row.progress
    assert dispatch_pending(delivered.append) == 0
    # Simulate published-but-SQL-ack-lost: lease recovery duplicates delivery,
    # but the worker must still refuse the second QUEUED claim.
    s["db"].execute(update(ExecutionOutbox).where(ExecutionOutbox.id == outbox.id).values(state="PUBLISHING", lease_until=utcnow() - timedelta(seconds=1)))
    s["db"].commit()
    assert dispatch_pending(delivered.append) == 1 and len(delivered) == 2
    with tenant_scope("a"):
        claim(descriptor)
        with pytest.raises(QueueRefused):
            claim(descriptor)


@pytest.mark.parametrize("path,method", [
    ("/api/v1/network/scan", "post"), ("/api/v1/devsecops/sbom/scan", "post"),
    ("/api/v1/cbom/ingest", "post"), ("/api/v1/graph", "get"),
    ("/api/v1/network/ssh/scan", "post"), ("/api/v1/webhooks/github", "post"),
    ("/api/v1/scans/runtime-findings", "get"),
])
def test_unqualified_consumers_have_no_privileged_legacy_fallback(controlled, path, method):
    response = getattr(controlled["clients"]["bank_a"], method)(path)
    assert response.status_code == 409 and response.json()["profile"] == "local-source/v1"


def test_approval_ownership_permissions_supersession_and_register(controlled):
    s = controlled
    configure(s)
    a = approve(s)
    configure(s, "b")
    configure(s, None)
    for name in ("bank_b", "platform_admin"):
        assert s["clients"][name].get(PREFIX + "/approvals").json()["approvals"] == []
    admin = s["clients"]["platform_admin"]
    assert admin.post(PREFIX + f"/approvals/{a['id']}/revoke", headers={"X-Tenant-ID": "b"}).status_code == 404
    assert s["clients"]["bank_a"].put(PREFIX + "/policy", json={}).status_code in (403, 422)
    revised = approve(s, supersedes_id=a["id"])
    s["db"].expire_all()
    assert s["db"].get(ScanApproval, a["id"]).revoked_at is not None
    row, _descriptor = queue(s)
    assert row.progress["execution_control"]["approval_id"] == revised["id"]
    register = admin.get(PREFIX + "/ownership-register")
    assert register.status_code == 200
    data = register.json()
    assert data["null_history_declassification"] == "FORBIDDEN" and data["external_stores"]
    assert all(not table["reviewed"] for table in data["sql_tables"])
    assert admin.get(PREFIX + "/ownership-register", headers={"X-Tenant-ID": "a"}).status_code == 403


def test_success_requires_committed_receipt_releases_capacity_and_never_reexecutes(controlled):
    from db.models.scan import Scan
    s = controlled
    configure(s)
    approve(s)
    row, descriptor = queue(s)
    executor = JobExecutor()
    calls = []
    def collector(**kwargs):
        calls.append(kwargs["job_id"])
        controls.checkpoint("parser-launch", request=True)
        with SessionLocal() as session:
            scan = Scan(tenant_id="a", scan_start=utcnow(), scan_end=utcnow(), target_location=s["target"], status="COMPLETED")
            session.add(scan)
            session.flush()
            JobRepository(session).update_status(row.id, "COMPLETED", scan_id=scan.id, progress={"stage": "done"})
            session.commit()
            return scan.id
    executor.runner.run = collector
    assert executor.execute(descriptor)
    s["db"].expire_all()
    assert s["db"].query(ExecutionAttempt).one().status == "SUCCEEDED"
    assert row.status == "COMPLETED" and row.scan_id
    assert row.progress["execution_authority"]["v"] == 2
    assert all(b.active == 0 for b in s["db"].query(ExecutionBudget))
    assert not executor.execute(descriptor) and len(calls) == 1


def test_truthy_collector_without_durable_completion_is_unknown_not_success(controlled):
    s = controlled
    configure(s)
    approve(s)
    row, descriptor = queue(s)
    executor = JobExecutor()
    executor.runner.run = lambda **_kw: "invented-success"
    assert not executor.execute(descriptor)
    s["db"].expire_all()
    assert row.status == "UNKNOWN" and s["db"].query(ExecutionAttempt).one().status == "UNKNOWN"
    assert all(b.active == 1 for b in s["db"].query(ExecutionBudget))


def test_fair_turn_defers_hot_estate_without_failing_or_losing_queued_job(controlled):
    s = controlled
    configure(s, capacity=2)
    configure(s, "b", capacity=2)
    approve(s)
    approve(s, "b")
    _a1, da1 = queue(s)
    a2, da2 = queue(s)
    _b, db = queue(s, "bank_b")
    # Claim A once. Even with another free A slot, B must get a turn before A2.
    with tenant_scope("a"):
        claim(da1)
    assert not JobExecutor().execute(da2)
    s["db"].expire_all()
    assert a2.status == "QUEUED"
    outbox = s["db"].execute(select(ExecutionOutbox).where(ExecutionOutbox.job_id == a2.id)).scalar_one()
    assert outbox.state == "PENDING" and controls.aware(outbox.lease_until) > utcnow()
    with tenant_scope("b"):
        claim(db)
    with tenant_scope("a"):
        claim(da2)
    assert s["db"].query(ExecutionAttempt).count() == 3


def test_production_profile_cannot_be_disabled_by_flag(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_CONTROLS", "false")
    assert controls.required()
    monkeypatch.setenv("ENVIRONMENT", "prod")
    assert controls.required()


def test_private_history_is_not_served_from_unapproved_region(controlled, monkeypatch):
    s = controlled
    configure(s)
    approve(s)
    row, _descriptor = queue(s)
    assert s["clients"]["bank_a"].get(f"/api/v1/jobs/{row.id}").status_code == 200
    monkeypatch.setenv("CRYPTOSCAN_EVIDENCE_REGION", "eu-west")
    for path in (f"/api/v1/jobs/{row.id}", "/api/v1/scans", PREFIX + "/approvals", PREFIX + "/events"):
        response = s["clients"]["bank_a"].get(path)
        assert response.status_code == 409 and "regional-sql-a" not in response.text


def test_production_monitor_cannot_start_uncontrolled_watch_or_collectors(monkeypatch):
    from worker.monitor.engine import MonitorEngine
    monkeypatch.setenv("CRYPTOSCAN_EXECUTION_CONTROLS", "true")
    engine = MonitorEngine.__new__(MonitorEngine)
    with pytest.raises(controls.ExecutionDenied, match="Monitor"):
        engine.tick()
    with pytest.raises(controls.ExecutionDenied, match="Monitor"):
        engine.run_target(None)


def test_global_stop_is_shared_durable_and_does_not_release_inflight_reservations(controlled):
    s = controlled
    configure(s)
    configure(s, "b")
    approve(s)
    _row, descriptor = queue(s)
    with tenant_scope("a"):
        active = claim(descriptor)
        response = s["clients"]["platform_admin"].post(PREFIX + "/emergency-stop")
        assert response.status_code == 200 and response.json()["reservations_released"] is False
        with controls.execution_scope(active), pytest.raises(controls.ExecutionDenied, match="stopped"):
            controls.checkpoint("after-global-stop")
    s["db"].expire_all()
    provider = s["db"].get(ExecutionBudget, controls.key("provider-budget", "local-source/v1"))
    assert provider.capacity == 0 and provider.active == 1
    assert s["clients"]["bank_a"].get(PREFIX + "/attempts").status_code == 200  # Stop doesn't hide incident history.
    assert s["clients"]["bank_b"].post("/api/v1/scans/trigger", json={"repo_url": s["target"]}).status_code == 409


def test_websocket_is_not_an_unreviewed_profile_escape(controlled):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as caught:
        with controlled["clients"]["bank_a"].websocket_connect("/api/v1/ws"):
            pytest.fail("unreviewed realtime adapter accepted")
    assert caught.value.code == 1008


def test_username_replacement_cannot_inherit_an_existing_session(controlled):
    from db.models.user import UserSession
    from sqlalchemy import delete
    from api.dependencies import _session_store_allows
    s = controlled
    original = s["db"].execute(select(User).where(User.username == "bank_a")).scalar_one()
    token = s["clients"]["bank_a"].cookies.get("cryptoscan_session")
    credential = s["db"].execute(select(UserSession).where(UserSession.username == "bank_a")).scalar_one()
    assert credential.user_id == original.id
    s["db"].execute(delete(User).where(User.id == original.id))
    replacement = User(username="bank_a", password_hash="unused", roles="superadmin")
    s["db"].add(replacement)
    s["db"].commit()
    assert replacement.id != credential.user_id
    assert not _session_store_allows(token, "bank_a")
    with pytest.raises(controls.ExecutionDenied):
        controls.authenticated_principal(s["db"], username="bank_a", token=token)


def test_legacy_session_needs_new_authentication_not_username_backfill(controlled):
    from db.models.user import UserSession
    s = controlled
    s["db"].execute(update(UserSession).where(UserSession.username == "bank_a").values(user_id=None))
    s["db"].commit()
    response = s["clients"]["bank_a"].get(PREFIX + "/policy")
    assert response.status_code == 401
