"""Stored custody and group export, no customer endpoints or PQC qualification."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_tls_session import server
from services.inventory.tests.test_tls_key_share import key_target
from inventory.collection import ApprovedTlsSessionCollector
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, tmp_path):
    clients, db, _ = assured
    with server(tmp_path) as state:
        t = key_target(state)
        response = admin(clients).post(
            P + "/approvals", json={"system_id": "system-a", "manifest": t.manifest.model_dump(mode="json")}
        )
        assert response.status_code == 201, response.text
        identifier = response.json()["subject_id"]
        snapshot = ApprovedTlsSessionCollector(include_key_share=True).collect(t)
        response = clients["bank_a"].post(
            P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
        )
        assert response.status_code == 201, response.text
    return clients, db, identifier, snapshot


def test_stored_group_evidence_keeps_pqc_readiness_and_app_use_unknown(assured, tmp_path, monkeypatch):
    clients, db, identifier, snapshot = prepared(assured, tmp_path)
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*a, **k):
        raise AssertionError("No probes during stored export")

    monkeypatch.setattr("inventory.tls_session.probe_session", forbidden)
    path = P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6"
    response = clients["reader_a"].get(path)
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    protocol = next(c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "protocol")
    props = {p["name"]: p["value"] for p in protocol["properties"]}
    f = snapshot.receipts[0].facts[0]
    assert props["cryptoscan:key_exchange_group"] == f.key_exchange_group
    assert props["cryptoscan:selected_group_id"] == str(f.selected_group_id)
    # The owned loopback server may negotiate a registered classical OR
    # hybrid group depending on the installed OpenSSL. Preserve the observed
    # ServerHello classification; neither choice proves PQC implementation.
    assert props["cryptoscan:group_classification"] == f.group_classification
    assert props["cryptoscan:pqc_implementation_verified"] == props["cryptoscan:pqc_readiness_verified"] == "false"
    assert props["cryptoscan:pqc_assessment"] == props["cryptoscan:runtime_use"] == "UNKNOWN"
    assert props["cryptoscan:server_hello_sha256"] == f.server_hello_sha256
    assert props["cryptoscan:application_identity_verified"] == "false"
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 1
    for name in ["bank_b", "platform_admin"]:
        assert clients[name].get(path).status_code == 404
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(path).status_code == 409


@pytest.mark.parametrize("method", ["network", "offline_host"])
def test_key_share_profile_cannot_bypass_server_admission(assured, method):
    clients, _, body = target_body(assured)
    t = key_target({"port": 443, "pin": "a" * 64})
    body.update(
        collection_method=method,
        address=t.address,
        environment="test",
        manifest=t.manifest.model_dump(mode="json"),
        allowed_operations=t.allowed_operations if method == "network" else ["READ_APPROVED_METADATA"],
        target_key="blocked-key-" + method,
    )
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409


def test_key_share_export_official_schema_refusal_no_success_audit(assured, tmp_path, monkeypatch):
    clients, db, identifier, _ = prepared(assured, tmp_path)
    before = db.query(AuditLog).count()
    monkeypatch.setattr("cbom.cyclonedx16.validate_cyclonedx16", lambda *a: {"ok": False})
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6").status_code == 503
    assert db.query(AuditLog).count() == before
