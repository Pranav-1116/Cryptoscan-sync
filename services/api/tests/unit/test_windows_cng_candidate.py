"""Portable registration seams in authenticated custody; never native qualification."""

from types import SimpleNamespace
import hashlib
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_windows_cng import manifest, FakeBcrypt, install
from shared_models.windows_cng import registration_bytes
from inventory.host import collect
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, monkeypatch, mode="success"):
    import inventory.host as host

    clients, db, _ = assured
    scope = manifest()
    monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(host, "elevated", lambda: mode == "elevated")
    fake = FakeBcrypt(
        first_status=0xC0000022 if mode == "denied" else 0xC0000225 if mode == "missing" else None,
        second_status=0xC0000023 if mode == "changed" else None,
    )
    install(monkeypatch, fake)
    response = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    return clients, db, response.json()["subject_id"], collect(scope), fake


def test_registration_custody_does_not_emit_algorithm_use_or_recollect(assured, monkeypatch):
    clients, db, identifier, snapshot, fake = prepared(assured, monkeypatch)
    assert snapshot.receipts[0].status == "PARSED" and fake.calls == ["size", "read"]
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*args):
        raise AssertionError("Stored read/export cannot invoke CNG")

    monkeypatch.setattr("inventory.windows_cng._api", forbidden)
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot")
    assert response.status_code == 200, response.text
    value = response.json()
    fact = value["snapshot"]["receipts"][0]["facts"][0]
    assert fact["registered_functions"] == ["3DES", "AES"] and fact["capabilities_observed"] is False
    assert fact["algorithm"] == fact["runtime_use"] == fact["operation_use"] == "UNKNOWN"
    assert value["source_basis"] == "IMPORTED" and value["snapshot"]["windows_execution_qualified"] is False
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert response.status_code == 200, response.text
    assert response.json()["components"] == [] and validate_cyclonedx16(response.json())["ok"]
    for suffix in ("snapshot", "cbom"):
        assert clients["bank_b"].get(P + f"/approvals/{identifier}/{suffix}").status_code == 404
        assert clients["platform_admin"].get(P + f"/approvals/{identifier}/{suffix}").status_code == 404
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 1
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot").status_code == 409


@pytest.mark.parametrize(
    "mode,status", [("denied", "DENIED"), ("missing", "UNAVAILABLE"), ("changed", "INVALID"), ("elevated", "DENIED")]
)
def test_failed_registration_is_unknown_not_no_crypto_or_supported_crypto(assured, monkeypatch, mode, status):
    clients, _, identifier, snapshot, fake = prepared(assured, monkeypatch, mode)
    assert snapshot.receipts[0].status == status and snapshot.receipts[0].facts == []
    if mode == "elevated":
        assert fake.calls == []
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert response.status_code == 200 and response.json()["components"] == []


@pytest.mark.parametrize("change", ["interface", "digest", "functions", "capability"])
def test_changed_registration_scope_truth_or_commitment_refuses_before_persistence(assured, monkeypatch, change):
    clients, db, identifier, snapshot, _ = prepared(assured, monkeypatch)
    raw = snapshot.model_dump(mode="json")
    fact = raw["receipts"][0]["facts"][0]
    if change == "interface":
        fact["registration_interface"] = "hash"
        fact["identity_key"] = "microsoft-primitive:user:hash"
        fact["interface_sha256"] = hashlib.sha256(
            registration_bytes("hash", 0, fact["registered_functions"])
        ).hexdigest()
        raw["receipts"][0]["content_sha256"] = fact["interface_sha256"]
    elif change == "digest":
        raw["receipts"][0]["content_sha256"] = "0" * 64
    elif change == "functions":
        fact["registered_functions"] = ["RSA"]
    else:
        fact["capabilities_observed"] = True
    response = clients["bank_a"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": raw})
    assert response.status_code == 422 and db.query(Scan).count() == 0


def test_registration_candidate_does_not_enable_windows_worker_admission(assured):
    clients, _, body = target_body(assured)
    body["manifest"] = manifest().model_dump(mode="json")
    body["environment"] = "test"
    body["target_key"] = "windows-cng-candidate"
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
