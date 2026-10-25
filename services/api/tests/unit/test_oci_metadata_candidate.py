"""OCI candidate custody/export; synthetic artifacts, not production admission."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_oci_image import layout, target
from inventory.collection import OfflineOciMetadataCollector
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, tmp_path):
    clients, db, _ = assured
    root, scope = layout(tmp_path)
    response = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    snapshot = OfflineOciMetadataCollector().collect(target(scope))
    response2 = clients["bank_a"].post(
        P + f"/approvals/{response.json()['subject_id']}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response2.status_code == 201, response2.text
    return clients, db, response.json()["subject_id"], snapshot, root


def test_image_sbom_and_custody_reads_never_reinspect_files(assured, tmp_path, monkeypatch):
    clients, db, identifier, snapshot, root = prepared(assured, tmp_path)
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*a):
        raise AssertionError("Stored projections must not reread OCI source")

    monkeypatch.setattr("inventory.oci_image.collect_image", forbidden)
    for file in root.rglob("*"):
        if file.is_file():
            file.unlink()
    path = P + f"/approvals/{identifier}"
    value = clients["reader_a"].get(path + "/snapshot")
    assert value.status_code == 200 and value.json()["source_basis"] == "IMPORTED"
    fact = value.json()["snapshot"]["receipts"][0]["facts"][0]
    assert fact["layer_contents_verified"] is fact["package_inventory_verified"] is fact["deployment_verified"] is False
    crypto = clients["reader_a"].get(path + "/cbom")
    assert crypto.status_code == 200 and crypto.json()["components"] == []
    response = clients["reader_a"].get(path + "/oci-image/cyclonedx-1.6")
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    assert len(bom["components"]) == 1 and bom["components"][0]["type"] == "container"
    assert "dependencies" not in bom and "hashes" not in bom["components"][0] and "supplier" not in bom["components"][0]
    assert bom["compositions"] == [{"aggregate": "incomplete"}]
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["cryptoscan:profile"] == "OCI_MANIFEST_CONFIG_METADATA_ONLY_NOT_PACKAGE_SBOM"
    assert response.headers["cache-control"] == "no-store"
    assert "DO_NOT_EXPORT" not in response.text
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 2
    for user in ["bank_b", "platform_admin"]:
        assert clients[user].get(path + "/oci-image/cyclonedx-1.6").status_code == 404
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(path + "/oci-image/cyclonedx-1.6").status_code == 409


def test_official_schema_failure_refuses_export_and_audit(assured, tmp_path, monkeypatch):
    clients, db, identifier, _, _ = prepared(assured, tmp_path)
    before = db.query(AuditLog).count()
    monkeypatch.setattr("cbom.cyclonedx16.validate_cyclonedx16", lambda *a: {"ok": False})
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/oci-image/cyclonedx-1.6")
    assert response.status_code == 503 and db.query(AuditLog).count() == before


@pytest.mark.parametrize("mode", ["missing", "hash", "platform"])
def test_failed_metadata_not_exported_as_empty_success(assured, tmp_path, mode):
    clients, _, _ = assured
    root, scope = layout(tmp_path)
    response = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    identifier = response.json()["subject_id"]
    if mode == "missing":
        (root / "index.json").unlink()
    elif mode == "hash":
        for p in (root / "blobs/sha256").iterdir():
            p.write_bytes(b"{}")
    else:
        import json

        p = root / "index.json"
        index = json.loads(p.read_bytes())
        index["manifests"][0]["platform"]["os"] = "windows"
        p.write_text(json.dumps(index))
    snapshot = OfflineOciMetadataCollector().collect(target(scope))
    assert snapshot.receipts[0].status != "PARSED"
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/oci-image/cyclonedx-1.6").status_code == 409


@pytest.mark.parametrize("method", ["container", "offline_host"])
def test_universal_container_and_linux_bypass_stay_blocked(assured, tmp_path, method):
    clients, _, body = target_body(assured)
    _, scope = layout(tmp_path)
    body.update(
        collection_method=method,
        manifest=scope.model_dump(mode="json"),
        environment="test",
        target_key="candidate-" + method,
    )
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
