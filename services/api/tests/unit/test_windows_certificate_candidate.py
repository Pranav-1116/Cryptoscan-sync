"""Approved synthetic Windows receipt custody, not native API qualification."""

from types import SimpleNamespace
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_windows_certificates import der, manifest, FakeCrypt32, install
from inventory.host import collect
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, monkeypatch, *, mode="success"):
    import inventory.host as host

    clients, db, _ = assured
    data = der()
    scope = manifest(data)
    # Explicit portable seam. This does not claim the Linux host ran Windows.
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: mode == "elevated")
    fake = FakeCrypt32(data, first_error=5 if mode == "denied" else 0x80092004 if mode == "missing" else None)
    install(monkeypatch, fake)
    approved = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert approved.status_code == 201, approved.text
    snapshot = collect(scope)
    return clients, db, approved.json()["subject_id"], snapshot, fake


def test_scoped_windows_certificate_import_and_existing_standard_cbom(assured, monkeypatch):
    clients, db, identifier, snapshot, fake = prepared(assured, monkeypatch)
    assert snapshot.receipts[0].status == "PARSED" and fake.finds == 2
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def no_capture(*args):
        raise AssertionError("Read/export must not invoke a native collector")

    monkeypatch.setattr("inventory.windows_certificates._api", no_capture)
    detail = clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot")
    assert detail.status_code == 200, detail.text
    value = detail.json()
    assert value["snapshot"]["receipts"][0]["facts"][0]["local_basis"] == "OBSERVED"
    assert value["snapshot"]["windows_execution_qualified"] is False
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"] and len(bom["components"]) == 1
    properties = {p["name"]: p["value"] for c in bom["components"] for p in c["properties"]}
    assert properties["cryptoscan:source_basis"] == "IMPORTED"
    assert properties["cryptoscan:host:local_basis"] == "OBSERVED"
    assert properties["cryptoscan:host:runtime_use"] == "UNKNOWN"
    assert properties["cryptoscan:host:fingerprint_sha256"] == snapshot.receipts[0].facts[0].fingerprint_sha256
    assert "BEGIN CERTIFICATE" not in response.text
    for suffix in ("snapshot", "cbom"):
        path = P + f"/approvals/{identifier}/{suffix}"
        assert clients["bank_b"].get(path).status_code == 404
        assert clients["platform_admin"].get(path).status_code == 404
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 1  # Existing CBOM export audit, not recollection.
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/cbom").status_code == 409


@pytest.mark.parametrize("mode,status", [("denied", "DENIED"), ("missing", "UNAVAILABLE"), ("elevated", "DENIED")])
def test_failed_certificate_receipt_never_becomes_no_certificate_or_positive_cbom(assured, monkeypatch, mode, status):
    clients, _, identifier, snapshot, fake = prepared(assured, monkeypatch, mode=mode)
    receipt = snapshot.receipts[0]
    assert receipt.status == status and not receipt.facts and receipt.content_sha256 is None
    if mode == "elevated":
        assert not fake.calls
    result = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert result.status_code == 201, result.text
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert response.status_code == 200 and response.json()["components"] == []
    assert validate_cyclonedx16(response.json())["ok"]


def test_store_fingerprint_scope_mismatch_refuses_intake_before_persistence(assured, monkeypatch):
    clients, db, identifier, snapshot, _ = prepared(assured, monkeypatch)
    raw = snapshot.model_dump(mode="json")
    raw["receipts"][0]["facts"][0]["fingerprint_sha256"] = "0" * 64
    result = clients["bank_a"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": raw})
    assert result.status_code == 422 and db.query(Scan).count() == 0


def test_windows_registry_jobs_stay_blocked_and_no_remote_admission_is_added(assured):
    clients, _, body = target_body(assured)
    body["manifest"] = manifest(der()).model_dump(mode="json")
    body["environment"] = "test"
    body["target_key"] = "windows-certificate-candidate"
    registered = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert registered.status_code == 201, registered.text
    response = admin(clients).post(
        COLLECTION + f"/targets/{registered.json()['subject_id']}/authorize", json=decision(1)
    )
    assert response.status_code == 409 and "future capability" in response.text
