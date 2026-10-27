"""Real human sessions/SQL; source and preflight measurements below are synthetic."""

from datetime import timedelta
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled
from test_resource_monitoring_api import submitted, proposal_body
from db.models.user import User
from db.repositories.user_repository import verify_audit_chain
from api.assurance import traffic_control as core, resource_monitoring as resources
from shared.shared_models.tests.test_linux_traffic_control import capture
from shared_models.linux_traffic_control import PreflightSpec
from shared_models.host_collection import digest

P = "/api/v1/traffic-control"


def prepared(assured, monkeypatch):
    clients, db, auth, _, row, _ = submitted(assured, monkeypatch)
    monkeypatch.setattr(core, "utcnow", resources.utcnow)
    proposal = clients["bank_a"].post("/api/v1/resource-monitoring/traffic-proposals", json=proposal_body(row)).json()
    result = clients["bank_a"].post(
        P + f"/proposals/{proposal['subject_id']}/preflight-requests",
        json={"expected_proposal_record_sha256": proposal["payload_sha256"], "management_ips": ["127.0.0.1"]},
    )
    assert result.status_code == 201, result.text
    request = result.json()
    spec = PreflightSpec.model_validate(request["payload"]["spec"])
    value = capture(spec)
    monkeypatch.setattr(core, "utcnow", lambda: value.finished_at + timedelta(seconds=1))
    intake = clients["bank_a"].post(
        P + f"/preflight-requests/{spec.request_id}/captures",
        json={"capture": value.model_dump(mode="json"), "expected_preflight_sha256": digest(value)},
    )
    assert intake.status_code == 201, intake.text
    return clients, db, auth, request, intake.json()


def test_preflight_review_export_is_namespace_only(assured, monkeypatch):
    clients, db, auth, request, row = prepared(assured, monkeypatch)
    reviewer = db.query(User).filter_by(username="platform_admin").one()
    body = {
        "preflight_id": row["subject_id"],
        "expected_preflight_record_sha256": row["payload_sha256"],
        "reviewer_user_id": reviewer.id,
        "duration_seconds": 1,
        "reason": "Validate rollback only in a disposable loopback namespace",
    }
    response = clients["bank_a"].post(P + "/validations", json=body)
    assert response.status_code == 201, response.text
    key = response.json()["subject_id"]
    assert clients["reader_a"].get(P + f"/validations/{key}/authorization").status_code == 409
    decision = {
        "expected_revision": 1,
        "evidence_ref": "change/isolated-test",
        "reason": "Reviewed only disposable namespace testing; real host changes prohibited",
    }
    assert clients["bank_a"].post(P + f"/validations/{key}/approve", json=decision).status_code == 403
    approved = admin(clients).post(P + f"/validations/{key}/approve", json=decision)
    assert approved.status_code == 200, approved.text
    assert admin(clients).post(P + f"/validations/{key}/approve", json=decision).status_code == 409
    packet = clients["reader_a"].get(P + f"/validations/{key}/authorization")
    assert packet.status_code == 200, packet.text
    assert packet.json()["target_interface"] == "lo" and not packet.json()["authorizes_real_host_change"]
    assert packet.headers["Cache-Control"] == "no-store"
    assert clients["bank_b"].get(P + f"/validations/{key}").status_code == 404
    assert clients["bank_a"].post(P + f"/validations/{key}/apply").status_code == 404
    assert verify_audit_chain(db)["status"] == "OK"


@pytest.mark.parametrize("path", ["preflight-requests", "preflights"])
def test_other_estate_cannot_read_preflight(assured, monkeypatch, path):
    clients, _, _, request, _ = prepared(assured, monkeypatch)
    assert clients["bank_b"].get(P + f"/{path}/{request['subject_id']}").status_code == 404


def test_readonly_cannot_propose_and_hash_mismatch_refuses(assured, monkeypatch):
    clients, db, _, _, row = prepared(assured, monkeypatch)
    reviewer = db.query(User).filter_by(username="platform_admin").one()
    body = {
        "preflight_id": row["subject_id"],
        "expected_preflight_record_sha256": "0" * 64,
        "reviewer_user_id": reviewer.id,
        "duration_seconds": 1,
        "reason": "Isolated fixture review with mismatched source commitment",
    }
    assert clients["reader_a"].post(P + "/validations", json=body).status_code == 403
    assert clients["bank_a"].post(P + "/validations", json=body).status_code == 409


def test_revoked_source_blocks_review_but_preserves_historical_read(assured, monkeypatch):
    clients, db, auth, request, row = prepared(assured, monkeypatch)
    reviewer = db.query(User).filter_by(username="platform_admin").one()
    body = {
        "preflight_id": row["subject_id"],
        "expected_preflight_record_sha256": row["payload_sha256"],
        "reviewer_user_id": reviewer.id,
        "duration_seconds": 1,
        "reason": "Only a fresh approved source may support isolated validation",
    }
    response = clients["bank_a"].post(P + "/validations", json=body)
    assert response.status_code == 201, response.text
    key = response.json()["subject_id"]
    decision = {
        "expected_revision": 2,
        "evidence_ref": "change/revoke-source",
        "reason": "Revoke the source sampling window before validation review",
    }
    revoked = admin(clients).post(f"/api/v1/resource-monitoring/plans/{auth.plan_id}/revoke", json=decision)
    assert revoked.status_code == 200, revoked.text
    decision["expected_revision"] = 1
    assert admin(clients).post(P + f"/validations/{key}/approve", json=decision).status_code == 409
    assert clients["reader_a"].get(P + f"/preflights/{request['subject_id']}").status_code == 200


def test_same_human_cannot_assign_self_as_reviewer(assured, monkeypatch):
    clients, db, _, _, row = prepared(assured, monkeypatch)
    reviewer = db.query(User).filter_by(username="platform_admin").one()
    body = {
        "preflight_id": row["subject_id"],
        "expected_preflight_record_sha256": row["payload_sha256"],
        "reviewer_user_id": reviewer.id,
        "duration_seconds": 1,
        "reason": "A self review must be rejected even for a platform administrator",
    }
    assert admin(clients).post(P + "/validations", json=body).status_code == 409


def test_kinds_fit_existing_database_contract():
    assert all(len(kind) <= 30 for kind in (core.REQUEST, core.PREFLIGHT, core.CHANGE))
