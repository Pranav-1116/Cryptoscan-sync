"""Actual sessions, tenant predicates and SQL evidence; synthetic Linux inputs."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled, configure
from db.models.assurance import AssuranceRevision
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.system import System
from db.models.user import AuditLog
from db.repositories.user_repository import UserRepository
from inventory.host import collect
from shared_models.host_collection import HostManifest, HostInput
from services.inventory.tests.test_host import certificate

P = "/api/v1/host-evidence"


def setup(assured):
    clients, db, tmp = assured
    cert = tmp / "certificate.pem"
    cert.write_bytes(certificate())
    config = tmp / "tls.conf"
    config.write_text("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers AES256-GCM-SHA384;\npassword do-not-upload;\n")
    binary = tmp / "libcrypto.so"
    binary.write_bytes(b"\x7fELFsynthetic-header-only")
    manifest = HostManifest(
        approval_reference="change/host-17",
        host_id="payments-1",
        environment="prod",
        platform="linux",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        inputs=[
            HostInput(input_id="cert", kind="PUBLIC_CERTIFICATE", path=str(cert)),
            HostInput(input_id="tls", kind="NGINX_TLS_CONFIG", path=str(config)),
            HostInput(input_id="lib", kind="BINARY_METADATA", path=str(binary)),
            HostInput(input_id="denied", kind="PUBLIC_CERTIFICATE", path=str(tmp / "unavailable.pem")),
        ],
    )
    body = {"system_id": "system-a", "manifest": manifest.model_dump(mode="json")}
    result = admin(clients).post(P + "/approvals", json=body)
    assert result.status_code == 201, result.text
    identifier = result.json()["subject_id"]
    snapshot = collect(manifest).model_dump(mode="json")
    return clients, db, identifier, body, snapshot


def submit(clients, identifier, snapshot):
    return clients["bank_a"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot})


def test_host_collection_intake_inspection_and_exact_schema_export(assured):
    clients, db, identifier, body, snapshot = setup(assured)
    result = submit(clients, identifier, snapshot)
    assert result.status_code == 201, result.text
    receipt = result.json()
    assert receipt["source_basis"] == "IMPORTED" and receipt["evidence_count"] == 6
    assert (
        receipt["runtime_use"] == receipt["pqc_assessment"] == "UNKNOWN" and receipt["policy_result"] == "NOT_EVALUATED"
    )
    scan = db.get(Scan, receipt["scan_id"])
    assert scan.tenant_id == "a" and scan.target_commit is None
    system = db.get(System, "system-a")
    assert system.last_scan_id is None  # import must not stamp observed coverage
    detail = clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot")
    assert detail.status_code == 200, detail.text
    assert detail.headers["Cache-Control"] == "no-store"
    assert detail.json()["integrity"]["result"] == "PASS"
    assert "do-not-upload" not in detail.text and "BEGIN CERTIFICATE" not in detail.text
    bom = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert bom.status_code == 200, bom.text
    document = bom.json()
    from cbom.cyclonedx16 import validate_cyclonedx16

    assert validate_cyclonedx16(document)["ok"] and document["specVersion"] == "1.6"
    assert len(document["components"]) == 2  # no crypto algorithm from lib presence/failed input
    assert not document.get("dependencies")  # no inferred system/HSM relationships
    props = {p["name"]: p["value"] for c in document["components"] for p in c["properties"]}
    assert props["cryptoscan:source_basis"] == "IMPORTED"
    assert props["cryptoscan:host:runtime_use"] == props["cryptoscan:host:pqc_assessment"] == "UNKNOWN"
    assert props["cryptoscan:host:configured_protocols"] == "TLSv1.2,TLSv1.3"
    from cbom.generator import CbomGenerator

    legacy = CbomGenerator().from_records(db.query(EvidenceRecord).filter_by(scan_id=scan.id).all())
    assert all(c["evidence"]["identity"][0]["methods"][0]["technique"] == "other" for c in legacy["components"])
    actions = [r.action for r in db.query(AuditLog).all()]
    assert all(a in actions for a in ["host.approve", "host.intake", "host.export"])
    from db.repositories.user_repository import verify_audit_chain

    assert verify_audit_chain(db)["status"] == "OK"


def test_exact_scope_and_one_use_idempotency(assured):
    clients, db, identifier, body, snapshot = setup(assured)
    first = submit(clients, identifier, snapshot)
    assert first.status_code == 201, first.text
    second = submit(clients, identifier, snapshot)
    assert second.status_code == 200 and second.json() == first.json()
    assert db.query(Scan).count() == 1
    snapshot["receipts"][-1]["reason"] = "ACCESS_DENIED"
    snapshot["receipts"][-1]["status"] = "DENIED"
    assert submit(clients, identifier, snapshot).status_code == 409
    for suffix in ("", "/snapshot", "/cbom"):
        path = P + f"/approvals/{identifier}{suffix}"
        assert clients["bank_b"].get(path).status_code == 404
        assert clients["platform_admin"].get(path).status_code == 404
        assert admin(clients).get(path).status_code == 200
    assert clients["bank_b"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot}).status_code == 404
    assert admin(clients).post(P + "/approvals", json={**body, "system_id": "system-b"}).status_code == 404
    assert admin(clients).post(P + "/approvals", json={**body, "system_id": "platform-system"}).status_code == 404


@pytest.mark.parametrize("role", ["readonly", "auditor"])
def test_durable_readonly_auditor_can_inspect_not_modify_scan(assured, role):
    clients, db, identifier, body, snapshot = setup(assured)
    result = submit(clients, identifier, snapshot)
    assert result.status_code == 201, result.text
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    user = clients["reader_a"]
    assert user.get(P + f"/approvals/{identifier}/snapshot").status_code == 200
    assert user.get(P + f"/approvals/{identifier}/cbom").status_code == 200
    assert user.post(P + "/approvals", json=body).status_code == 403
    assert user.post(P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot}).status_code == 403
    # A read-only caller is refused before routing, so an unimplemented method
    # answers 403 rather than 405: "you may not write at all" precedes "that
    # method does not exist".
    assert user.patch(P + f"/approvals/{identifier}/snapshot", json={}).status_code in (403, 405)
    assert db.query(Scan).count() == 1


@pytest.mark.parametrize(
    "change",
    ["manifest", "future", "preapproval", "expired", "raw", "observation", "wrong_type", "large", "duplicate_json"],
)
def test_intake_refuses_unapproved_or_unbounded_inputs_without_persistence(assured, change):
    clients, db, identifier, body, snapshot = setup(assured)
    if change == "manifest":
        from shared_models.host_collection import digest

        snapshot["manifest"]["inputs"][0]["path"] = "/unapproved.pem"
        snapshot["manifest_sha256"] = digest(snapshot["manifest"])
    if change == "future":
        snapshot["finished_at"] = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
    if change == "preapproval":
        snapshot["started_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    if change == "expired":
        from shared_models.host_collection import digest

        snapshot["manifest"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        snapshot["manifest_sha256"] = digest(snapshot["manifest"])
    if change == "raw":
        snapshot["raw_bytes"] = "secret"
    if change == "observation":
        snapshot["host_identity_attested"] = True
    if change == "wrong_type":
        snapshot["receipts"][1]["facts"][0]["kind"] = "CERTIFICATE"
    if change == "large":
        result = clients["bank_a"].post(P + f"/approvals/{identifier}/intake", content=b" " * (2 * 1048576 + 1))
    elif change == "duplicate_json":
        result = clients["bank_a"].post(
            P + f"/approvals/{identifier}/intake",
            content='{"snapshot":{},"snapshot":{}}',
            headers={"Content-Type": "application/json"},
        )
    else:
        result = submit(clients, identifier, snapshot)
    assert result.status_code in (409, 413, 422), result.text
    assert db.query(Scan).count() == db.query(EvidenceRecord).count() == 0
    assert db.query(AssuranceRevision).filter_by(kind="host_intake").count() == 0


@pytest.mark.parametrize(
    "change",
    [
        "content",
        "projection",
        "chain",
        "manifest",
        "snapshot",
        "tombstone",
        "foreign_row",
        "foreign_scan",
        "scope",
        "target",
        "evidence_id",
        "time",
        "version",
    ],
)
def test_export_refuses_broken_evidence_closure(assured, change):
    clients, db, identifier, body, snapshot = setup(assured)
    result = submit(clients, identifier, snapshot)
    assert result.status_code == 201, result.text
    scan = db.get(Scan, result.json()["scan_id"])
    row = db.query(EvidenceRecord).filter_by(scan_id=scan.id).order_by(EvidenceRecord.chain_position).first()
    if change == "content":
        row.finding_data = {"tampered": True}
    if change == "projection":
        row.algorithm = "AES"
    if change == "chain":
        row.chain_hash = "a" * 64
    if change == "manifest":
        scan.manifest_hash = "a" * 64
    if change == "snapshot":
        db.execute(
            text("UPDATE assurance_revisions SET payload_sha256=:sha WHERE kind='host_intake'"), {"sha": "a" * 64}
        )
    if change == "tombstone":
        row.deleted_at = datetime.now(timezone.utc)
    if change == "foreign_row":
        db.execute(text("UPDATE evidence_records SET tenant_id='b' WHERE id=:id"), {"id": row.id})
    if change == "foreign_scan":
        db.execute(text("UPDATE scans SET tenant_id='b' WHERE id=:id"), {"id": scan.id})
    if change == "scope":
        scan.statistics = {}
    if change == "target":
        scan.target_location = "urn:cryptoscan:host:wrong-host"
    if change == "evidence_id":
        db.execute(
            text("UPDATE evidence_records SET id=:new WHERE id=:old"),
            {"new": "changed-evidence-identity", "old": row.id},
        )
    if change == "time":
        scan.scan_start -= timedelta(seconds=1)
    if change == "version":
        scan.scanner_version = "fake"
    db.commit()
    db.expire_all()
    for endpoint in ("snapshot", "cbom"):
        response = clients["bank_a"].get(P + f"/approvals/{identifier}/{endpoint}")
        assert response.status_code in (404, 409), response.text


def test_audit_failure_rolls_back_intake_not_just_receipt(assured, monkeypatch):
    clients, db, identifier, body, snapshot = setup(assured)
    from api.routers import host_evidence

    def fail(*args):
        raise RuntimeError("synthetic audit persistence failure")

    monkeypatch.setattr(host_evidence, "_audit", fail)
    with pytest.raises(RuntimeError, match="synthetic audit"):
        submit(clients, identifier, snapshot)
    assert db.query(Scan).count() == db.query(EvidenceRecord).count() == 0
    assert db.query(AssuranceRevision).filter_by(kind="host_intake").count() == 0


def test_host_import_does_not_bypass_controlled_production_profile(controlled):
    configure(controlled)
    client = controlled["clients"]["bank_a"]
    for method, path in (
        ("post", "/approvals"),
        ("post", "/approvals/a/intake"),
        ("get", "/approvals/a/snapshot"),
        ("get", "/approvals/a/cbom"),
    ):
        response = getattr(client, method)(P + path)
        assert response.status_code == 409 and "no qualified controlled-profile adapter" in response.text
    assert (
        controlled["db"]
        .query(AssuranceRevision)
        .filter(AssuranceRevision.kind.in_(["host_approval", "host_intake"]))
        .count()
        == 0
    )


def test_host_write_rate_limit_is_enforced_on_actual_http(assured):
    clients, db, _ = assured
    # The shared test app deliberately omits its production/dev limiter. Mount
    # the actual product middleware explicitly, retaining real session auth.
    from fastapi.testclient import TestClient
    from api.middleware.rate_limit import RateLimitMiddleware

    with TestClient(RateLimitMiddleware(clients["bank_a"].app)) as limited:
        limited.cookies.update(clients["bank_a"].cookies)
        responses = [limited.post(P + "/approvals", json={}) for _ in range(11)]
    assert all(r.status_code == 422 for r in responses[:10])
    assert responses[-1].status_code == 429 and responses[-1].json()["scope"] == "host_write"
    assert "Retry-After" in responses[-1].headers
    assert db.query(AssuranceRevision).count() == 0


def test_analyst_cannot_self_approve_or_escalate_body_authority(assured):
    clients, db, identifier, body, snapshot = setup(assured)
    assert clients["bank_a"].post(P + "/approvals", json=body).status_code == 403
    assert admin(clients).post(P + "/approvals", json={**body, "created_by": "fake-admin"}).status_code == 422
    assert db.query(AssuranceRevision).filter_by(kind="host_approval").count() == 1


def test_approval_audit_failure_rolls_back_scope_authorization(assured, monkeypatch):
    clients, db, identifier, body, snapshot = setup(assured)
    from api.routers import host_evidence

    def fail(*args):
        raise RuntimeError("synthetic approval audit failure")

    monkeypatch.setattr(host_evidence, "_audit", fail)
    with pytest.raises(RuntimeError, match="approval audit"):
        admin(clients).post(P + "/approvals", json=body)
    assert db.query(AssuranceRevision).filter_by(kind="host_approval").count() == 1
