"""Owned loopback TLS custody and stored export; no external probes or admission."""

import pytest
from test_assurance_workflows import assured as assured, admin
from test_software_supply_chain_api import banks as banks
from services.inventory.tests.test_tls_session import server, target
from inventory.collection import ApprovedTlsSessionCollector
from db.models.scan import Scan
from db.models.evidence_record import EvidenceRecord
from db.models.user import AuditLog
from cbom.cyclonedx16 import validate_cyclonedx16
from shared_models.host_collection import digest
from test_collection_foundation import target_body, decision, P as COLLECTION

P = "/api/v1/host-evidence"


def prepared(assured, tmp_path, *, failed=False):
    clients, db, _ = assured
    with server(tmp_path) as state:
        t = target(state)
        if failed:
            t.manifest.inputs[0] = t.manifest.inputs[0].model_copy(
                update={"path": t.manifest.inputs[0].path[:-64] + "f" * 64}
            )
        response = admin(clients).post(
            P + "/approvals", json={"system_id": "system-a", "manifest": t.manifest.model_dump(mode="json")}
        )
        assert response.status_code == 201, response.text
        identifier = response.json()["subject_id"]
        snapshot = ApprovedTlsSessionCollector().collect(t)
        response = clients["bank_a"].post(
            P + f"/approvals/{identifier}/intake", json={"snapshot": snapshot.model_dump(mode="json")}
        )
        assert response.status_code == 201, response.text
    return clients, db, identifier, snapshot


def test_stored_tls_export_no_probing_and_no_identity_promotion(assured, tmp_path, monkeypatch):
    clients, db, identifier, snapshot = prepared(assured, tmp_path)
    before = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))

    def forbidden(*args, **kwargs):
        raise AssertionError("Stored reads must never probe")

    monkeypatch.setattr("inventory.tls_session.probe_session", forbidden)
    path = P + f"/approvals/{identifier}"
    assert clients["reader_a"].get(path + "/snapshot").status_code == 200
    response = clients["reader_a"].get(path + "/tls-session/cyclonedx-1.6")
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    assert len(bom["services"]) == 1 and len(bom["components"]) == 2
    assert {c["cryptoProperties"]["assetType"] for c in bom["components"]} == {"certificate", "protocol"}
    assert "dependencies" not in bom and bom["compositions"] == [{"aggregate": "incomplete"}]
    assert response.headers["cache-control"] == "no-store"
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert props["cryptoscan:profile"] == "PINNED_SINGLE_TLS_SESSION_NOT_CAPABILITY_SCAN"
    assert props["cryptoscan:snapshot_sha256"] == digest(snapshot)
    for c in bom["components"]:
        p = {v["name"]: v["value"] for v in c["properties"]}
        assert p["cryptoscan:hostname_validated"] == p["cryptoscan:certificate_chain_validated"] == "false"
    after = tuple(db.query(m).count() for m in (Scan, EvidenceRecord, AuditLog))
    assert after[:2] == before[:2] and after[2] == before[2] + 1
    for user in ["bank_b", "platform_admin"]:
        assert clients[user].get(path + "/tls-session/cyclonedx-1.6").status_code == 404
    db.query(EvidenceRecord).first().finding_data = {"changed": True}
    db.commit()
    assert clients["reader_a"].get(path + "/tls-session/cyclonedx-1.6").status_code == 409


def test_failed_session_is_not_empty_successful_nbom(assured, tmp_path):
    clients, db, identifier, s = prepared(assured, tmp_path, failed=True)
    assert s.receipts[0].reason == "TLS_PEER_PIN_MISMATCH"
    before = db.query(AuditLog).count()
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6").status_code == 409
    assert db.query(AuditLog).count() == before


def test_official_schema_failure_blocks_export_audit(assured, tmp_path, monkeypatch):
    clients, db, identifier, _ = prepared(assured, tmp_path)
    before = db.query(AuditLog).count()
    monkeypatch.setattr("cbom.cyclonedx16.validate_cyclonedx16", lambda *a: {"ok": False})
    assert clients["reader_a"].get(P + f"/approvals/{identifier}/tls-session/cyclonedx-1.6").status_code == 503
    assert db.query(AuditLog).count() == before


@pytest.mark.parametrize("method", ["network", "offline_host"])
def test_api_cannot_admit_or_tunnel_active_session(assured, method):
    clients, _, body = target_body(assured)
    t = target({"port": 443, "pin": "a" * 64})
    body.update(
        collection_method=method,
        address=t.address,
        environment="test",
        manifest=t.manifest.model_dump(mode="json"),
        allowed_operations=t.allowed_operations if method == "network" else ["READ_APPROVED_METADATA"],
        target_key="blocked-" + method,
    )
    response = clients["bank_a"].post(COLLECTION + "/targets", json=body)
    assert response.status_code == 201, response.text
    response = admin(clients).post(COLLECTION + f"/targets/{response.json()['subject_id']}/authorize", json=decision(1))
    assert response.status_code == 409 and "future capability" in response.text
