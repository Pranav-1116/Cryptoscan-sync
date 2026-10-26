"""Real sessions/SQL with explicitly synthetic counters, plus one actual local collector case."""

from copy import deepcopy
from datetime import timedelta
import os
import sys
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled, configure
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from db.models.user import AuditLog
from db.repositories.user_repository import UserRepository, verify_audit_chain
from api.assurance import resource_monitoring as core
from shared_models.host_collection import digest
from shared_models.resource_monitoring import ResourceAuthorization, ResourceCapture
from shared.shared_models.tests.test_resource_monitoring import authorization, capture

P = "/api/v1/resource-monitoring"


def decision(revision):
    return {
        "expected_revision": revision,
        "evidence_ref": "change/resource-17",
        "reason": "Approved exact read-only interface and filesystem sampling scope",
    }


def prepared(assured):
    clients, db, _ = assured
    scope = authorization().scope
    created = clients["bank_a"].post(P + "/plans", json=scope.model_dump(mode="json"))
    assert created.status_code == 201, created.text
    identifier = created.json()["subject_id"]
    approved = admin(clients).post(P + f"/plans/{identifier}/approve", json=decision(1))
    assert approved.status_code == 200, approved.text
    bound = clients["reader_a"].get(P + f"/plans/{identifier}/authorization")
    assert bound.status_code == 200, bound.text
    return clients, db, ResourceAuthorization.model_validate(bound.json())


def submitted(assured, monkeypatch):
    clients, db, auth = prepared(assured)
    value = capture(auth, utcnow() + timedelta(milliseconds=1))  # synthetic counter fixture, not a native measurement
    monkeypatch.setattr(core, "utcnow", lambda: value.finished_at + timedelta(seconds=1))
    body = {"capture": value.model_dump(mode="json"), "expected_capture_sha256": digest(value)}
    result = clients["bank_a"].post(P + "/captures", json=body)
    assert result.status_code == 201, result.text
    return clients, db, auth, value, result.json(), body


def proposal_body(row):
    return {
        "capture_id": row["subject_id"],
        "interface": "lo",
        "egress_limit_mbps": 10,
        "reason": "Review an explicit draft egress limit without applying any host configuration",
    }


def test_scope_capture_report_control_draft_roundtrip(assured, monkeypatch):
    clients, db, auth, value, row, body = submitted(assured, monkeypatch)
    report = row["payload"]["report"]
    assert report["network"][0]["tx_mbps"] == 16 and report["storage"][0]["used_bytes"] == 600
    read = clients["reader_a"].get(P + "/captures/" + row["subject_id"])
    assert read.status_code == 200 and read.json()["payload"] == row["payload"]
    assert read.headers["Cache-Control"] == "no-store"
    assert clients["reader_a"].get(P + "/captures").json()["items"][0]["capture_id"] == row["subject_id"]
    assert clients["reader_a"].get(P + "/plans").json()["items"][0]["payload"]["state"] == "APPROVED"
    proposal = clients["bank_a"].post(P + "/traffic-proposals", json=proposal_body(row))
    assert proposal.status_code == 201, proposal.text
    data = proposal.json()["payload"]
    assert not data["applied"] and not data["enforcement_supported"] and data["sample_exceeds_proposed_limit"]
    assert clients["reader_a"].get(P + "/traffic-proposals/" + proposal.json()["subject_id"]).status_code == 200
    assert (
        clients["bank_a"].post(P + "/traffic-proposals/" + proposal.json()["subject_id"] + "/apply").status_code == 404
    )
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("who", ["bank_b", "platform_admin"])
def test_exact_estate_hides_plans_captures_proposals(assured, monkeypatch, who):
    clients, _, auth, _, row, _ = submitted(assured, monkeypatch)
    proposal = clients["bank_a"].post(P + "/traffic-proposals", json=proposal_body(row)).json()
    for path in [
        "/plans/" + auth.plan_id,
        "/plans/" + auth.plan_id + "/authorization",
        "/captures/" + row["subject_id"],
        "/traffic-proposals/" + proposal["subject_id"],
    ]:
        assert clients[who].get(P + path).status_code == 404
    assert clients[who].get(P + "/captures").json()["items"] == []
    assert clients[who].get(P + "/plans").json()["items"] == []


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_reader_inspection_without_mutation(assured, monkeypatch, role):
    clients, db, auth, _, row, body = submitted(assured, monkeypatch)
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    reader = clients["reader_a"]
    assert reader.get(P + "/captures/" + row["subject_id"]).status_code == 200
    assert reader.post(P + "/captures", json=body).status_code == 403
    assert reader.post(P + "/traffic-proposals", json=proposal_body(row)).status_code == 403
    assert clients["bank_a"].post(P + f"/plans/{auth.plan_id}/approve", json=decision(1)).status_code == 403


def test_revocation_blocks_intake_and_control_draft_but_retains_history(assured, monkeypatch):
    clients, _, auth, _, row, body = submitted(assured, monkeypatch)
    assert admin(clients).post(P + f"/plans/{auth.plan_id}/revoke", json=decision(2)).status_code == 200
    assert clients["bank_a"].post(P + "/captures", json=body).status_code == 409
    assert clients["bank_a"].post(P + "/traffic-proposals", json=proposal_body(row)).status_code == 409
    assert clients["reader_a"].get(P + "/captures/" + row["subject_id"]).status_code == 200


@pytest.mark.parametrize("case", ["hash", "nonce", "duplicate", "future", "expired", "predates"])
def test_invalid_intake_does_not_commit(assured, monkeypatch, case):
    clients, db, auth, value, row, body = submitted(assured, monkeypatch)
    bad = deepcopy(body)
    if case == "hash":
        bad["expected_capture_sha256"] = "0" * 64
    elif case == "nonce":
        bad["capture"]["authorization"]["nonce"] = "c" * 64
        bad["expected_capture_sha256"] = digest(bad["capture"])
    elif case == "future":
        monkeypatch.setattr(core, "utcnow", lambda: value.started_at)
    elif case == "expired":
        monkeypatch.setattr(core, "utcnow", lambda: auth.scope.expires_at + timedelta(seconds=1))
    elif case == "predates":
        bad["capture"]["started_at"] = (value.started_at - timedelta(seconds=10)).isoformat()
        bad["expected_capture_sha256"] = digest(bad["capture"])
    result = clients["bank_a"].post(P + "/captures", json=bad)
    assert result.status_code in {409, 422}, result.text
    assert db.query(AssuranceRevision).filter_by(kind=core.CAPTURE).count() == 1


@pytest.mark.parametrize("case", ["stale", "unknown_interface", "unmeasured"])
def test_control_draft_requires_fresh_measured_approved_interface(assured, monkeypatch, case):
    clients, db, auth, value, row, body = submitted(assured, monkeypatch)
    request = proposal_body(row)
    if case == "stale":
        monkeypatch.setattr(core, "utcnow", lambda: value.finished_at + timedelta(minutes=6))
    elif case == "unknown_interface":
        request["interface"] = "eth0"
    else:
        bad = deepcopy(body["capture"])
        bad["capture_id"] = "22222222-2222-2222-2222-222222222222"
        bad["network"] = [{"interface": "lo", "status": "UNAVAILABLE"}]
        imported = clients["bank_a"].post(
            P + "/captures",
            json={"capture": bad, "expected_capture_sha256": digest(ResourceCapture.model_validate(bad))},
        )
        assert imported.status_code == 201, imported.text
        request["capture_id"] = imported.json()["subject_id"]
    assert clients["bank_a"].post(P + "/traffic-proposals", json=request).status_code == 409
    assert db.query(AssuranceRevision).filter_by(kind=core.PROPOSAL).count() == 0


@pytest.mark.parametrize("target", ["capture", "proposal"])
def test_resealed_view_changes_fail_recomputation(assured, monkeypatch, target):
    clients, db, _, _, row, _ = submitted(assured, monkeypatch)
    kind, path = core.CAPTURE, "/captures/"
    if target == "proposal":
        row = clients["bank_a"].post(P + "/traffic-proposals", json=proposal_body(row)).json()
        kind, path = core.PROPOSAL, "/traffic-proposals/"
    original = db.query(AssuranceRevision).filter_by(kind=kind, subject_id=row["subject_id"]).one()
    changed = deepcopy(original.payload)
    if target == "capture":
        changed["report"]["network"][0]["tx_mbps"] = 1000
    else:
        changed["management_access_safety_verified"] = True
    from test_collection_views_api import reseal

    reseal(db, original, changed)
    assert clients["reader_a"].get(P + path + row["subject_id"]).status_code == 409


@pytest.mark.parametrize("action", ["capture.intake", "traffic.propose"])
def test_audit_failure_rolls_back_resource_mutation(assured, monkeypatch, action):
    clients, db, _, _, row, body = submitted(assured, monkeypatch)
    original = UserRepository.audit
    before = db.query(AuditLog).count()
    if action == "capture.intake":
        body = deepcopy(body)
        body["capture"]["capture_id"] = "22222222-2222-2222-2222-222222222222"
        body["expected_capture_sha256"] = digest(body["capture"])
        path = "/captures"
        kind = core.CAPTURE
        expected = 1
    else:
        body = proposal_body(row)
        path = "/traffic-proposals"
        kind = core.PROPOSAL
        expected = 0

    def fail(self, user, event, **kwargs):
        if event == "collection.resource." + action:
            raise RuntimeError("synthetic resource audit failure")
        return original(self, user, event, **kwargs)

    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="synthetic resource audit failure"):
        clients["bank_a"].post(P + path, json=body)
    assert db.query(AssuranceRevision).filter_by(kind=kind).count() == expected
    assert db.query(AuditLog).count() == before


def test_controlled_production_boundary_stays_closed(controlled):
    configure(controlled)
    assert controlled["clients"]["bank_a"].get(P + "/captures").status_code == 409


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0, reason="Actual ordinary-user Linux required")
def test_actual_readonly_linux_capture_to_authenticated_report(assured):
    from inventory.resource_monitoring import collect_resources

    clients, db, auth = prepared(assured)
    value = collect_resources(auth, auth.plan_record_sha256)
    response = clients["bank_a"].post(
        P + "/captures", json={"capture": value.model_dump(mode="json"), "expected_capture_sha256": digest(value)}
    )
    assert response.status_code == 201, response.text
    report = response.json()["payload"]["report"]
    assert report["network"][0]["status"] == "MEASURED" and report["storage"][0]["total_bytes"] > 0
    assert not report["runtime_control_applied"]
    output = os.getenv("CRYPTOSCAN_RESOURCE_WITNESS_DIR")
    if output:
        import json
        from pathlib import Path

        folder = Path(output)
        folder.mkdir(parents=True, exist_ok=True)
        history = clients["reader_a"].get(P + f"/plans/{auth.plan_id}")
        assert history.status_code == 200
        (folder / "resource-plan.json").write_text(json.dumps(history.json(), indent=2) + "\n")
        (folder / "resource-capture.json").write_text(json.dumps(value.model_dump(mode="json"), indent=2) + "\n")
        (folder / "resource-record.json").write_text(json.dumps(response.json(), indent=2) + "\n")
    assert verify_audit_chain(db)["status"] == "OK"
