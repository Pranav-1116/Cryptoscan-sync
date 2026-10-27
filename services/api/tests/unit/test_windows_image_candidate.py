"""Authenticated custody of portable Windows module fixtures, not native evidence."""

from types import SimpleNamespace
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_windows_images import manifest, FakeKernel, install, CREATED
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
    fake = FakeKernel(
        error_at="open" if mode in {"denied", "missing"} else None,
        error=5 if mode == "denied" else 87,
        changed=mode == "changed",
    )
    install(monkeypatch, fake)
    response = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    return clients, db, response.json()["subject_id"], collect(scope), fake


def test_scoped_image_custody_does_not_create_crypto_components_or_recollect(assured, monkeypatch):
    clients, db, identifier, snapshot, fake = prepared(assured, monkeypatch)
    assert snapshot.receipts[0].status == "PARSED" and fake.pass_no == 2
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*args):
        raise AssertionError("Read/export must not invoke native collector")

    monkeypatch.setattr("inventory.windows_images._api", forbidden)
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot")
    assert response.status_code == 200, response.text
    value = response.json()
    facts = value["snapshot"]["receipts"][0]["facts"]
    assert len(facts) == 3 and all(f["creation_filetime"] == CREATED for f in facts)
    assert all(f["algorithm"] == f["runtime_use"] == f["operation_use"] == "UNKNOWN" for f in facts)
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
def test_image_failure_is_not_absence_or_crypto_inventory(assured, monkeypatch, mode, status):
    clients, _, identifier, snapshot, fake = prepared(assured, monkeypatch, mode)
    assert snapshot.receipts[0].status == status and snapshot.receipts[0].facts == []
    if mode == "elevated":
        assert not fake.calls
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert response.status_code == 200 and response.json()["components"] == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", 72),
        ("creation_filetime", CREATED[:-1] + "2"),
        ("creation_filetime", int(CREATED)),
        ("interface_sha256", "0" * 64),
        ("runtime_use", "OBSERVED"),
    ],
)
def test_changed_scope_or_truth_refuses_intake_before_persistence(assured, monkeypatch, field, value):
    clients, db, identifier, snapshot, _ = prepared(assured, monkeypatch)
    raw = snapshot.model_dump(mode="json")
    raw["receipts"][0]["facts"][1][field] = value
    response = clients["bank_a"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": raw})
    assert response.status_code == 422 and db.query(Scan).count() == 0


def test_module_candidate_does_not_enable_windows_worker_admission(assured):
    clients, _, body = target_body(assured)
    body["manifest"] = manifest().model_dump(mode="json")
    body["environment"] = "test"
    body["target_key"] = "windows-module-candidate"
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
