"""Actual owned hybrid handshake custody/export; not physical HSM/bank acceptance."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_tls_hybrid import hybrid_server, hybrid_target
from inventory.collection import ApprovedTlsSessionCollector
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, wrong_pin=False):
    clients, db, _ = assured
    with hybrid_server() as state:
        t = hybrid_target(state)
        if wrong_pin:
            t.manifest.inputs[0] = t.manifest.inputs[0].model_copy(
                update={"path": t.manifest.inputs[0].path[:-64] + "a" * 64}
            )
        response = admin(clients).post(
            P + "/approvals", json={"system_id": "system-a", "manifest": t.manifest.model_dump(mode="json")}
        )
        assert response.status_code == 201, response.text
        identifier = response.json()["subject_id"]
        snapshot = ApprovedTlsSessionCollector(include_hybrid=True).collect(t)
        response = clients["bank_a"].post(
            P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
        )
        assert response.status_code == 201, response.text
    return clients, db, identifier, snapshot


def test_actual_hybrid_stored_export_not_new_probing_or_hsm_use(assured, monkeypatch):
    clients, db, identifier, s = prepared(assured)
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*a, **kw):
        raise AssertionError("No probes on stored reads")

    monkeypatch.setattr("inventory.tls_session.probe_session", forbidden)
    path = P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6"
    response = clients["reader_a"].get(path)
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    component = next(c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol")
    props = {p["name"]: p["value"] for p in component["properties"]}
    assert (
        props["cryptoscan:hybrid_session_completed"] == "true"
        and props["cryptoscan:key_exchange_group"] == "X25519MLKEM768"
    )
    assert props["cryptoscan:pqc_readiness_verified"] == "false" and props["cryptoscan:runtime_use"] == "UNKNOWN"
    assert props["cryptoscan:provider_identity_basis"] == "SELF_REPORTED_LIBRARY_VERSION_NOT_MEASURED_EXECUTION"
    assert tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog)) == (before[0], before[1], before[2] + 1)
    for name in ["bank_b", "platform_admin"]:
        assert clients[name].get(path).status_code == 404
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(path).status_code == 409


@pytest.mark.parametrize("method", ["network", "offline_host"])
def test_hybrid_cannot_bypass_server_admission(assured, method):
    clients, _, body = target_body(assured)
    t = hybrid_target({"port": 443, "pin": "a" * 64})
    body.update(
        collection_method=method,
        address=t.address,
        environment="test",
        manifest=t.manifest.model_dump(mode="json"),
        allowed_operations=t.allowed_operations if method == "network" else ["READ_APPROVED_METADATA"],
        target_key="blocked-hybrid-" + method,
    )
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    assert (
        admin(clients)
        .post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
        .status_code
        == 409
    )


def test_failed_peer_pin_never_exports_hybrid_success(assured):
    clients, db, identifier, s = prepared(assured, wrong_pin=True)
    assert s.receipts[0].reason == "TLS_PEER_PIN_MISMATCH" and not s.receipts[0].facts
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6").status_code == 409


def test_schema_failure_blocks_hybrid_success_audit(assured, monkeypatch):
    clients, db, identifier, _ = prepared(assured)
    before = db.query(AuditLog).count()
    monkeypatch.setattr("cbom.cyclonedx16.validate_cyclonedx16", lambda *a: {"ok": False})
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6").status_code == 503
    assert db.query(AuditLog).count() == before
