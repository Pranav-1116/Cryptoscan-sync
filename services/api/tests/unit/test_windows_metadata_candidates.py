"""Portable Windows candidate custody, not native production acceptance."""

from types import SimpleNamespace
import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_windows_metadata import manifest, snapshot
from services.inventory.tests.test_windows_cng import manifest as cng_manifest, FakeBcrypt, install
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, monkeypatch, which, mode="success"):
    clients, db, _ = assured
    scope = manifest(which) if which in {"capi", "ipv4", "ipv6"} else cng_manifest(which)
    approval = admin(clients).post(
        P + "/approvals", json={"system_id": "system-a", "manifest": scope.model_dump(mode="json")}
    )
    assert approval.status_code == 201, approval.text
    if which in {"capi", "ipv4", "ipv6"}:
        value, fake = snapshot(monkeypatch, which, mode, scope)
    else:
        import inventory.host as host

        monkeypatch.setattr(host, "sys", SimpleNamespace(platform="win32"))
        monkeypatch.setattr(host, "elevated", lambda: False)
        fake = FakeBcrypt(functions=["RSA"])
        install(monkeypatch, fake)
        value = host.collect(scope)
    return clients, db, approval.json()["subject_id"], value


@pytest.mark.parametrize(
    "which", ["capi", "ipv4", "ipv6", "asymmetric-encryption", "secret-agreement", "signature", "rng", "key-derivation"]
)
def test_metadata_custody_not_crypto_and_no_recollection(assured, monkeypatch, which):
    clients, db, identifier, value = prepared(assured, monkeypatch, which)
    assert value.receipts[0].status == "PARSED", value.receipts[0]
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": value.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*a):
        raise AssertionError("Stored reads must not query Windows")

    for path in ["inventory.windows_capi._api", "inventory.windows_listeners._api", "inventory.windows_cng._api"]:
        monkeypatch.setattr(path, forbidden)
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot")
    assert response.status_code == 200, response.text
    raw = response.json()
    fact = raw["snapshot"]["receipts"][0]["facts"][0]
    assert raw["source_basis"] == "IMPORTED" and raw["snapshot"]["windows_execution_qualified"] is False
    assert (
        fact["algorithm"] == fact["runtime_use"] == fact["operation_use"] == "UNKNOWN"
        and fact["capabilities_observed"] is False
    )
    response = clients["reader_a"].get(P + f"/approvals/{identifier}/cbom")
    assert (
        response.status_code == 200
        and response.json()["components"] == []
        and validate_cyclonedx16(response.json())["ok"]
    )
    for suffix in ["snapshot", "cbom"]:
        for user in ["bank_b", "platform_admin"]:
            assert clients[user].get(P + f"/approvals/{identifier}/{suffix}").status_code == 404
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert before[:2] == after[:2] and after[2] == before[2] + 1
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/snapshot").status_code == 409


@pytest.mark.parametrize(
    "which,mode,status",
    [
        ("capi", "denied", "DENIED"),
        ("capi", "missing", "UNAVAILABLE"),
        ("capi", "changed", "INVALID"),
        ("ipv4", "connection", "INVALID"),
        ("ipv4", "growing", "INVALID"),
        ("ipv6", "unknown", "UNAVAILABLE"),
    ],
)
def test_metadata_gaps_retained_without_absence(assured, monkeypatch, which, mode, status):
    clients, _, identifier, value = prepared(assured, monkeypatch, which, mode)
    assert value.receipts[0].status == status and value.receipts[0].facts == []
    response = clients["bank_a"].post(
        P + f"/approvals/{identifier}/intake", json={"snapshot": value.model_dump(mode="json")}
    )
    assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    "which,field,value",
    [
        ("capi", "provider_name", "Another Provider"),
        ("capi", "provider_type", 1),
        ("ipv4", "listener_count", 0),
        ("ipv4", "tls_observed", True),
        ("ipv4", "process_identity_verified", True),
    ],
)
def test_metadata_tamper_refuses_before_persistence(assured, monkeypatch, which, field, value):
    clients, db, identifier, snapshot_value = prepared(assured, monkeypatch, which)
    raw = snapshot_value.model_dump(mode="json")
    raw["receipts"][0]["facts"][0][field] = value
    response = clients["bank_a"].post(P + f"/approvals/{identifier}/intake", json={"snapshot": raw})
    assert response.status_code == 422 and db.query(Scan).count() == 0


@pytest.mark.parametrize("which", ["capi", "ipv4", "ipv6"])
def test_candidates_do_not_open_universal_windows_or_container_admission(assured, which):
    clients, _, body = target_body(assured)
    body["manifest"] = manifest(which).model_dump(mode="json")
    body["environment"] = "test"
    body["target_key"] = "windows-next-" + which
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text


@pytest.mark.parametrize("method", ["container", "network", "cloud", "hsm", "hardware", "vendor"])
def test_next_phases_stay_unadmitted_without_their_own_contract(assured, method):
    clients, db, body = target_body(assured)
    body.update(
        {"target_key": "future-" + method, "collection_method": method, "manifest": None, "environment": "test"}
    )
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
    assert db.query(Scan).count() == 0
