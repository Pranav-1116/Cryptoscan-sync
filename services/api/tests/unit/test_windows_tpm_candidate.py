"""Authenticated custody of portable TBS fixtures, not native/hardware qualification."""

from types import SimpleNamespace
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_windows_tpm import manifest, FakeTbs, install
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
    fake = FakeTbs(
        status=0x8028400F if mode == "missing" else 0x80284008 if mode == "service" else 0,
        structure=2 if mode == "layout" else 1,
    )
    install(monkeypatch, fake)
    response = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    return clients, db, response.json()["subject_id"], collect(scope), fake


def test_tpm_custody_no_crypto_component_or_recollection(assured, monkeypatch):
    clients, db, identifier, snapshot, fake = prepared(assured, monkeypatch)
    assert snapshot.receipts[0].status == "PARSED" and fake.calls == ["device-info"]
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*a):
        raise AssertionError("Stored inspection/export must not query TBS")

    monkeypatch.setattr("inventory.windows_tpm._api", forbidden)
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot")
    assert response.status_code == 200, response.text
    value = response.json()
    fact = value["snapshot"]["receipts"][0]["facts"][0]
    assert fact["tpm_specification"] == "2.0" and fact["capabilities_observed"] is False
    assert fact["algorithm"] == fact["runtime_use"] == fact["operation_use"] == "UNKNOWN"
    assert value["source_basis"] == "IMPORTED" and value["snapshot"]["windows_execution_qualified"] is False
    assert "firmware_version" not in fact and "reserved_interface" not in fact
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert (
        response.status_code == 200
        and response.json()["components"] == []
        and validate_cyclonedx16(response.json())["ok"]
    )
    for suffix in ("snapshot", "cbom"):
        assert clients["bank_b"].get(P + f"/approvals/{identifier}/{suffix}").status_code == 404
        assert clients["platform_admin"].get(P + f"/approvals/{identifier}/{suffix}").status_code == 404
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 1
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot").status_code == 409


@pytest.mark.parametrize(
    "mode,status",
    [("missing", "UNAVAILABLE"), ("service", "UNAVAILABLE"), ("layout", "UNSUPPORTED"), ("elevated", "DENIED")],
)
def test_tpm_failure_not_hardware_absence_or_no_crypto(assured, monkeypatch, mode, status):
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


@pytest.mark.parametrize(
    "field,value", [("tpm_specification", "1.2"), ("interface_sha256", "0" * 64), ("capabilities_observed", True)]
)
def test_tpm_changed_commitment_or_promoted_claim_refuses_before_persistence(assured, monkeypatch, field, value):
    clients, db, identifier, snapshot, _ = prepared(assured, monkeypatch)
    raw = snapshot.model_dump(mode="json")
    raw["receipts"][0]["facts"][0][field] = value
    response = clients["bank_a"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": raw})
    assert response.status_code == 422 and db.query(Scan).count() == 0


def test_tpm_candidate_does_not_enable_windows_admission(assured):
    clients, _, body = target_body(assured)
    body["manifest"] = manifest().model_dump(mode="json")
    body["environment"] = "test"
    body["target_key"] = "windows-tpm-candidate"
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
