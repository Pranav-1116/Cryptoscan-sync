"""Synthetic verified container evidence custody, export and admission refusal."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_oci_content import content_layout, runtime_scope, kernel
from inventory.host import collect
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, tmp_path, monkeypatch, *, failed=False):
    clients, db, _ = assured
    root, scope = content_layout(tmp_path)
    rt = runtime_scope(scope).inputs[0]
    # Independent runtime image association is NOT claimed by this fixture.
    rt = rt.model_copy(
        update={"path": rt.path.replace("b" * 64, scope.inputs[0].path.split("/manifest/sha256/")[1].split("/")[0])}
    )
    scope = scope.model_copy(update={"inputs": [*scope.inputs, rt]})
    kernel(monkeypatch)
    if failed:
        (root / "index.json").unlink()
    response = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    identifier = response.json()["subject_id"]
    snapshot = collect(scope)
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    return clients, db, identifier, snapshot, root


def test_verified_package_export_and_readiness_are_stored_only(assured, tmp_path, monkeypatch):
    clients, db, identifier, snapshot, root = prepared(assured, tmp_path, monkeypatch)
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*args):
        raise AssertionError("No collection on read/export")

    monkeypatch.setattr("inventory.oci_content.collect_content", forbidden)
    monkeypatch.setattr("inventory.oci_runtime.collect_runtime", forbidden)
    for f in root.rglob("*"):
        if f.is_file():
            f.unlink()
    path = P + f"/approvals/{identifier}/container"
    response = clients["reader_a"].get(path + "/cyclonedx-1.6")
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    assert len(bom["components"]) == 2
    assert [(c["name"], c.get("version")) for c in bom["components"] if c["type"] == "library"] == [
        ("openssl", "3.0-fixture")
    ]
    assert "dependencies" not in bom and not any("supplier" in c or "hashes" in c for c in bom["components"])
    assert bom["compositions"] == [{"aggregate": "incomplete"}]
    assert "DO_NOT_EXPORT" not in response.text and response.headers["cache-control"] == "no-store"
    properties = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert properties["cryptoscan:profile"] == "VERIFIED_OCI_LAYERS_AND_SCOPED_PACKAGE_DATABASES"
    assert "OPERATOR_DECLARED_NOT_RUNTIME_VERIFIED" in properties["cryptoscan:runtime_process_evidence"]
    response = clients["reader_a"].get(path + "/admission-readiness")
    assert response.status_code == 200
    ready = response.json()
    assert (
        ready["verified_content_observations"]
        == ready["package_database_records"]
        == ready["runtime_process_observations"]
        == 1
    )
    assert ready["verdict"] == "BLOCKED_NOT_PRODUCTION_ADMITTED" and not ready["production_execution_qualified"]
    assert not ready["runtime_image_binding_verified"] and not ready["server_execution"]
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 1
    for user in ["bank_b", "platform_admin"]:
        for suffix in ["/cyclonedx-1.6", "/admission-readiness"]:
            assert clients[user].get(path + suffix).status_code == 404
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    for suffix in ["/cyclonedx-1.6", "/admission-readiness"]:
        assert clients["reader_a"].get(path + suffix).status_code == 409


def test_failed_layers_cannot_export_runtime_only_as_package_inventory(assured, tmp_path, monkeypatch):
    clients, db, identifier, _, _ = prepared(assured, tmp_path, monkeypatch, failed=True)
    count = db.query(AuditLog).count()
    path = P + f"/approvals/{identifier}/container"
    assert clients["reader_a"].get(path + "/cyclonedx-1.6").status_code == 409
    ready = clients["reader_a"].get(path + "/admission-readiness").json()
    assert ready["verified_content_observations"] == ready["package_database_records"] == 0
    assert ready["failed_inputs"] and not ready["production_execution_qualified"]
    assert "RUNTIME_DECLARED_IMAGE_WITHOUT_MATCHING_VERIFIED_CONTENT" in ready["blockers"]
    assert db.query(AuditLog).count() == count


def test_official_validator_failure_no_export_or_audit(assured, tmp_path, monkeypatch):
    clients, db, identifier, _, _ = prepared(assured, tmp_path, monkeypatch)
    count = db.query(AuditLog).count()
    monkeypatch.setattr("cbom.cyclonedx16.validate_cyclonedx16", lambda *a: {"ok": False})
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/container/cyclonedx-1.6").status_code == 503
    assert db.query(AuditLog).count() == count


@pytest.mark.parametrize("method", ["container", "offline_host"])
@pytest.mark.parametrize("kind", ["OCI_IMAGE_CONTENT", "OCI_RUNTIME_PROCESS"])
def test_registry_does_not_accept_candidate_as_production_admission(assured, tmp_path, method, kind):
    clients, _, body = target_body(assured)
    _, scope = content_layout(tmp_path)
    if kind == "OCI_RUNTIME_PROCESS":
        scope = runtime_scope(scope)
    body.update(
        collection_method=method,
        manifest=scope.model_dump(mode="json"),
        environment="test",
        target_key="blocked-" + method + "-" + kind,
    )
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
