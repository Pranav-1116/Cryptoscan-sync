"""Six distinct BOM negative contracts; synthetic identities, not runtime attestation."""
from copy import deepcopy
from datetime import timedelta
import pytest
from db.models.base import utcnow
from db.models.assurance import CollectionPhaseReceipt
from db.models.scan_job import ScanJob
from test_relationship_trace_integrity import trace_case as trace_case, review, TRACE
from test_assurance_workflows import (assured as assured, banks as banks, ssh as ssh, P, admin, approval,
    done, manifest, new_scan, source_job, signer_and_key, supplier_body, export_document)
from test_software_supply_chain_api import register


@pytest.mark.parametrize("fault", ["bytes", "manifest_digest", "owner", "missing"])
def test_sbom_current_trace_rechecks_original_document_not_only_derived_rows(trace_case, fault):
    c = trace_case
    review(c)
    assert done(c["client"].get(TRACE), 200)["paths"]
    from api.routers.devsecops import _sbom_storage, _find_manifest
    storage = _sbom_storage()
    binding = c["binding"]
    m = _find_manifest(storage, binding["sbom_artifact_id"], tenant_id="a")
    if fault == "bytes": storage.put(m["storage_key"], b'{"changed":"original document"}')
    elif fault == "manifest_digest": storage.put_manifest(m["storage_key"], {**m, "sha256": "0" * 64})
    elif fault == "owner": storage.put_manifest(m["storage_key"], {**m, "tenant_id": "b"})
    else:
        storage.delete(m["storage_key"])
    before = deepcopy(c["proposed"])
    response = c["client"].get(TRACE)
    assert response.status_code in (404, 409), response.text
    assert c["proposed"] == before
    assert admin(c["clients"]).get(P + f"/records/bom_relationship/{before['subject_id']}").status_code == 200


def test_cbom_withdrawal_preserves_observation_but_removes_current_trace(trace_case):
    c = trace_case; review(c)
    original = c["evidence"].finding_data.copy()
    done(admin(c["clients"]).post(f"/api/v1/findings/{c['evidence'].id}/soft-delete", json={"reason": "Synthetic withdrawal"}), 200)
    result = done(c["client"].get(TRACE), 200)
    assert result["paths"] == [] and result["complete"] is False
    assert c["evidence"].finding_data == original


@pytest.mark.parametrize("when", ["before_recording", "current_read"])
@pytest.mark.parametrize("fault", ["failed", "payload", "digest", "endpoint", "future", "job"])
def test_nbom_current_coverage_rechecks_exact_phase_and_job(ssh, assured, fault, when):
    _, db, state = ssh
    clients = assured[0]
    state["keys"] = [{"algorithm": "ssh-ed25519", "public_key": "synthetic-public"}]
    done(clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10"]}), 200)
    job = db.query(ScanJob).one()
    target = {**manifest()["targets"][0], "kind": "ENDPOINT", "source_class": "network", "method": "SSH_HOST_KEYS", "target_ref": "10.21.0.10:22"}
    rid = done(clients["bank_a"].post(P + "/registers", json=manifest(targets=[target])))["subject_id"]
    body = {"expected_revision": 0, "outcome": "RECEIPT", "job_id": job.id,
            "evidence_ref": "synthetic/phase", "reason": "Exact SSH observation"}
    if when == "current_read":
        done(clients["bank_a"].put(P + f"/registers/{rid}/observations/repo-pay", json=body), 200)
    phase = db.query(CollectionPhaseReceipt).one()
    if fault == "failed": phase.observation_succeeded = False
    elif fault == "payload": phase.observation = {"status": "OK", "keys": []}
    elif fault == "digest": phase.observation_sha256 = "0" * 64
    elif fault == "endpoint": phase.endpoint = "10.21.0.11:22"
    elif fault == "future": phase.updated_at = utcnow() + timedelta(hours=1)
    else: job.status = "UNKNOWN"
    db.commit()
    response = (clients["bank_a"].get(P + f"/registers/{rid}/coverage") if when == "current_read"
                else clients["bank_a"].put(P + f"/registers/{rid}/observations/repo-pay", json=body))
    if when == "before_recording" and response.status_code == 200:
        assert response.json()["payload"]["state"] != "OBSERVED"
    else:
        assert response.status_code == 409, response.text


def test_techbom_declared_deployment_and_review_are_not_runtime_proof(trace_case):
    c = trace_case; review(c)
    result = done(c["client"].get(TRACE), 200)
    assert result["paths"] and result["runtime_verified"] is result["complete"] is False
    assert all(p["deployed_verified"] is p["invocation_verified"] is False for p in result["paths"])
    assert c["clients"]["bank_b"].get(TRACE).status_code == 404


def test_hbom_model_or_declared_fips_mode_does_not_fill_missing_firmware():
    from cbom.hbom import generate_hbom
    document = generate_hbom([{"asset_id": "synthetic-hsm", "model": "model-name-not-attestation", "hsm": {"fips_mode": True}}], environment="synthetic")
    row = document["components"][0]
    assert row["firmware"]["details"] is None and row["evidence"]["last_verified"] is None
    assert row.get("certification_verified") is not True
    assert document["dependencies"] == []


def test_vbom_valid_signature_is_not_truth_and_revocation_blocks_current_bytes(assured):
    clients, db, _ = assured
    signer, key, signer_body = signer_and_key(clients)
    # Even a signed assertion of hardware support is still a supplier declaration.
    doc = export_document(pages=[{"number": 1, "facts": [{"kind": "hardware", "product": "synthetic", "product_version": "1", "hardware_backed": True}]}])
    row = done(clients["bank_a"].post(P + "/supplier-evidence", json=supplier_body(register(clients["bank_a"]), signer, key, document=doc)))
    identifier = row["subject_id"]
    reviewed = done(admin(clients).post(P + f"/supplier-evidence/{identifier}/approve", json=approval()), 200)
    assert reviewed["payload"]["origin_verified"] is True
    assert reviewed["payload"]["independent_truth_verified"] is False
    signer_body.update(expected_revision=1, revoked=True)
    done(admin(clients).put(P + f"/signers/{signer['subject_id']}", json=signer_body), 200)
    assert admin(clients).get(P + f"/evidence-blobs/{identifier}/content").status_code == 409
    history = done(clients["bank_a"].get(P + f"/records/supplier_evidence/{identifier}"), 200)
    assert history["revisions"][-1]["payload"] == reviewed["payload"]
    assert history["revisions"][-1]["payload_sha256"] == reviewed["payload_sha256"]


def test_empty_source_findings_without_receipts_do_not_establish_coverage(assured):
    clients, db, _ = assured
    scan = new_scan(db, algorithms=()); scan.statistics = {}; db.commit()
    job = source_job(db, scan)
    rid = done(clients["bank_a"].post(P + "/registers", json=manifest()))["subject_id"]
    response = clients["bank_a"].put(P + f"/registers/{rid}/observations/repo-pay", json={"expected_revision": 0,
        "outcome": "RECEIPT", "job_id": job.id, "evidence_ref": "synthetic/missing", "reason": "Empty is not proof"})
    assert response.status_code == 409
