"""Real auth/SQL negative contracts; fixtures are synthetic, not bank qualification."""
import base64
import hashlib
from copy import deepcopy
from datetime import timedelta
import uuid

import pytest
from db.models.base import utcnow
from db.models.assurance import AssuranceRevision, AssuranceBlob
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.scan_job import ScanJob
from db.models.user import User
from db.repositories.execution_control import aware
from api.assurance import store
from test_software_supply_chain_api import banks as banks, register, attach, deploy
from test_ssh_receipt_contract import ssh as ssh

P = "/api/v1/assurance"


@pytest.fixture()
def assured(banks):
    from fastapi.testclient import TestClient
    from api.main import create_app
    from api.middleware.auth_middleware import AuthMiddleware
    from api.middleware.tenant_scope import TenantScopeMiddleware
    clients, db, tmp = banks
    app = create_app()
    app.add_middleware(TenantScopeMiddleware)
    app.add_middleware(AuthMiddleware)
    authenticated = {}
    for name, previous in clients.items():
        client = TestClient(app)
        client.cookies.update(previous.cookies)
        authenticated[name] = client
    try:
        yield authenticated, db, tmp
    finally:
        for client in authenticated.values():
            client.close()


def done(response, status=201):
    assert response.status_code == status, response.text
    return response.json()


def admin(clients, owner="a"):
    # The platform administrator must explicitly select a tenant, never inherit
    # a tenant's records from an unscoped administrative SQL view.
    client = clients["platform_admin"]
    return Selected(client, owner)


class Selected:
    def __init__(self, client, owner):
        self.client, self.owner = client, owner
    def request(self, method, path, **kw):
        kw["headers"] = {**kw.get("headers", {}), **({"X-Tenant-ID": self.owner} if self.owner else {})}
        return self.client.request(method, path, **kw)
    def post(self, path, **kw): return self.request("POST", path, **kw)
    def put(self, path, **kw): return self.request("PUT", path, **kw)
    def get(self, path, **kw): return self.request("GET", path, **kw)


def blob(client, data=b"approved redacted test fixture"):
    return done(client.post(P + "/evidence-blobs?evidence_ref=customer/redacted-fixture", content=data,
                            headers={"Content-Type": "application/octet-stream"}))


def manifest(**changes):
    return {"expected_revision": 0, "scope_description": "Pilot applications only, not the whole bank",
        "register_owner": "Bank A inventory owner", "completeness": "PARTIAL", "completeness_evidence_ref": "inventory/review-17",
        "targets": [{"target_id": "repo-pay", "system_id": "system-a", "owner_ref": "payments-owner",
            "kind": "SOURCE", "source_class": "wrappers_config", "target_ref": "/approved/pay",
            "method": "LOCAL_SOURCE", "permission_ref": "change/17", "freshness_seconds": 3600}], **changes}


def new_scan(db, owner="a", path="/approved/pay", algorithms=("MD5",), version="1.0", start=None, file_name="crypto.py"):
    now = start or utcnow() - timedelta(seconds=30)
    scan = Scan(tenant_id=owner, target_location=path, target_type="LOCAL_DIRECTORY", scan_start=now,
        scan_end=now + timedelta(milliseconds=1), status="COMPLETED", scanner_version=version, manifest_hash="a" * 64, statistics={"file_observation_receipts": [
            {"file": "crypto.py", "sha256": hashlib.sha256(b"redacted first-pass source checksum").hexdigest(), "parser_completed": True},
            {"file": "held.py", "sha256": hashlib.sha256(b"redacted held-out source checksum").hexdigest(), "parser_completed": True}]})
    db.add(scan)
    db.flush()
    for index, algorithm in enumerate(algorithms):
        db.add(EvidenceRecord(tenant_id=owner, scan_id=scan.id, content_hash=hashlib.sha256(algorithm.encode()).hexdigest(),
            chain_hash="a" * 64, chain_position=index, algorithm=algorithm, file_path=file_name, line_number=index + 1,
            purpose="CHECKSUM", finding_data={"algorithm": algorithm}))
    db.commit()
    return scan


def source_job(db, scan):
    job = ScanJob(tenant_id=scan.tenant_id, target_repo=scan.target_location, target_branch="local", job_type="MANUAL",
                  triggered_by="bank_a", status="COMPLETED", scan_id=scan.id,
                  started_at=scan.scan_start, completed_at=scan.scan_end)
    db.add(job)
    db.commit()
    return job


def approval(revision=1):
    return {"expected_revision": revision, "evidence_ref": "review/domain-owner-17", "reason": "Reviewed exact source, identity and scope"}


def test_register_has_independent_denominator_and_is_exact_estate(assured):
    clients, db, _ = assured
    a = clients["bank_a"]
    row = done(a.post(P + "/registers", json=manifest()))
    identifier = row["subject_id"]
    report = done(a.get(P + f"/registers/{identifier}/coverage"), 200)
    assert report["registered_targets"] == report["counts"]["NOT_ATTEMPTED"] == 1
    assert report["whole_bank_verified"] is False and report["register_completeness"] == "PARTIAL"
    assert clients["bank_b"].get(P + f"/registers/{identifier}/coverage").status_code == 404
    assert clients["platform_admin"].get(P + f"/registers/{identifier}/coverage").status_code == 404
    assert admin(clients).get(P + f"/registers/{identifier}/coverage").status_code == 200
    assert a.post(P + "/registers", json=manifest(targets=[{**manifest()["targets"][0], "system_id": "system-b"}])).status_code == 404
    assert clients["reader_a"].post(P + "/registers", json=manifest()).status_code == 403
    assert a.get(P + "/records?kind=estate_register").json()["records"][0]["payload_sha256"] == row["payload_sha256"]


def test_revision_browser_cannot_bypass_kind_specific_authority(assured):
    """?kind= must not be a cheaper read path than the kind's own routes.

    Trust and qualification revisions are written under assurance.trust/
    assurance.review and read under crypto.read. The generic revision browser
    used to answer any authenticated tenant user, so an analyst or a readonly
    member could list them by naming the kind.
    """
    clients, db, _ = assured
    a = clients["bank_a"]
    done(a.post(P + "/registers", json=manifest()))
    # metadata-only kinds stay readable for a tenant member
    assert a.get(P + "/records?kind=estate_register").status_code == 200
    assert clients["reader_a"].get(P + "/records?kind=estate_register").status_code == 200
    # trust artefacts: neither an analyst (security_analyst) nor a readonly
    # member holds assurance.trust / assurance.review
    for kind in ("supplier_signer", "adapter_qualification"):
        assert a.get(P + f"/records?kind={kind}").status_code == 403, kind
        assert clients["reader_a"].get(P + f"/records?kind={kind}").status_code == 403, kind
        unknown = "00000000-0000-0000-0000-000000000000"
        assert a.get(P + f"/records/{kind}/{unknown}").status_code == 403, kind
    # host_qualification is gated on crypto.read, which every role holds; the
    # gate here is on the *principal* (a current typed human), so a tenant
    # member reads its metadata and a machine session cannot.
    assert a.get(P + "/records?kind=host_qualification").status_code == 200


def test_register_revision_preserves_history_rejects_stale_writes_and_changed_targets(assured):
    clients, db, _ = assured
    a = clients["bank_a"]
    first = done(a.post(P + "/registers", json=manifest()))
    rid = first["subject_id"]
    state = {"expected_revision": 0, "outcome": "BLOCKED", "evidence_ref": "permissions/denied", "reason": "No read permission"}
    done(a.put(P + f"/registers/{rid}/observations/repo-pay", json=state), 200)
    assert a.get(P + f"/registers/{rid}/coverage").json()["counts"]["BLOCKED"] == 1
    changed = manifest(expected_revision=1)
    changed["targets"][0]["target_ref"] = "/approved/pay-release-18"
    second = done(a.put(P + f"/registers/{rid}", json=changed), 200)
    assert second["previous_sha256"] == first["payload_sha256"]
    assert a.put(P + f"/registers/{rid}", json=changed).status_code == 409
    assert a.get(P + f"/registers/{rid}/coverage").json()["counts"]["NOT_ATTEMPTED"] == 1
    history = done(a.get(P + f"/records/estate_register/{rid}"), 200)["revisions"]
    assert [r["revision"] for r in history] == [1, 2]
    assert history[0]["payload"] == first["payload"]


def test_receipt_freshness_comes_from_sql_not_submission_time_and_expires(assured):
    clients, db, _ = assured
    a = clients["bank_a"]
    rid = done(a.post(P + "/registers", json=manifest()))["subject_id"]
    scan = new_scan(db, start=utcnow() - timedelta(hours=2))
    job = source_job(db, scan)
    state = {"expected_revision": 0, "outcome": "RECEIPT", "job_id": job.id, "evidence_ref": "job/17", "reason": "Exact source receipt"}
    done(a.put(P + f"/registers/{rid}/observations/repo-pay", json=state), 200)
    report = a.get(P + f"/registers/{rid}/coverage").json()
    assert report["counts"]["STALE"] == 1
    assert report["targets"][0]["last_successful_at"] == aware(scan.scan_end).isoformat()
    state["expected_revision"] = 1
    done(a.put(P + f"/registers/{rid}/observations/repo-pay", json=state), 200)
    assert a.get(P + f"/registers/{rid}/coverage").json()["counts"]["STALE"] == 1
    foreign = source_job(db, new_scan(db, owner="b"))
    state.update(job_id=foreign.id, expected_revision=2)
    assert a.put(P + f"/registers/{rid}/observations/repo-pay", json=state).status_code == 404


@pytest.mark.parametrize("change", ["duplicate", "deployment_from_source", "future", "foreign_system"])
def test_register_rejects_invalid_scope(assured, change):
    clients, _, _ = assured
    body = manifest()
    if change == "duplicate": body["targets"] *= 2
    if change == "deployment_from_source": body["targets"][0]["kind"] = "DEPLOYMENT"
    if change == "future": body["targets"][0]["freshness_seconds"] = 0
    if change == "foreign_system": body["targets"][0]["system_id"] = "system-b"
    assert clients["bank_a"].post(P + "/registers", json=body).status_code in (404, 422)


def test_partial_ssh_scope_retains_success_refusal_and_never_attempted(ssh):
    clients, db, state = ssh
    state["fault"] = "stop"
    state["keys"] = [{"algorithm": "ssh-ed25519", "public_key": "synthetic-public-key-only"}]
    r = clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10", "10.21.0.11"], "include_kex": True})
    assert r.status_code == 409
    db.expire_all()
    job = db.query(ScanJob).one()
    report = done(clients["bank_a"].get(P + "/collections/" + job.id), 200)
    assert [p["state"] for p in report["phases"]] == ["COMPLETED", "REFUSED", "NOT_ATTEMPTED", "NOT_ATTEMPTED"]
    assert report["phases"][0]["observation"]["status"] == "OK"
    assert report["phases"][0]["observation_succeeded"] is True
    assert report["recording_completed"] is False and report["collection_complete"] is False
    assert report["observation_succeeded"] is False and report["posture_acceptable"] is None
    assert clients["bank_b"].get(P + "/collections/" + job.id).status_code == 404


def test_interrupted_ssh_has_unknown_observation_and_remaining_scope(ssh):
    clients, db, state = ssh
    state["fault"] = "collector"
    assert clients["bank_a"].post("/api/v1/network/ssh-scan", json={"hosts": ["10.21.0.10", "10.21.0.11"]}).status_code == 503
    db.expire_all()
    report = clients["bank_a"].get(P + "/collections/" + db.query(ScanJob).one().id).json()
    assert [p["state"] for p in report["phases"]] == ["UNKNOWN", "NOT_ATTEMPTED"]
    assert report["collection_complete"] is False


def test_context_changes_recommendation_not_original_observation(assured):
    clients, db, _ = assured
    scan = new_scan(db)
    original = db.query(EvidenceRecord).filter_by(scan_id=scan.id).one()
    checksum = {"expected_revision": 0, "purpose": "CHECKSUM", "security_use": False,
                "evidence_ref": "owner/checksum", "rationale": "Non-adversarial cache checksum", "environment": "TEST", "execution": "PACKAGED"}
    reviewer = admin(clients)
    first = done(reviewer.post(P + f"/findings/{original.id}/assessments", json=checksum))
    assert first["payload"]["importance"] == "NONSECURITY_CHECKSUM_REVIEW"
    security = {**checksum, "expected_revision": 1, "purpose": "SECURITY_HASH", "security_use": True, "environment": "PRODUCTION"}
    second = done(reviewer.post(P + f"/findings/{original.id}/assessments", json=security))
    assert first["payload"]["observation"] == second["payload"]["observation"]
    assert first["payload"]["recommendation"] != second["payload"]["recommendation"]
    assert reviewer.post(P + f"/findings/{original.id}/assessments", json=security).status_code == 409
    db.refresh(original)
    assert original.purpose == "CHECKSUM" and original.algorithm == "MD5" and original.policy_evaluation is None
    assert clients["bank_b"].get(P + f"/records/finding_assessment/{original.id}").status_code == 404
    assert clients["bank_a"].post(P + f"/findings/{original.id}/assessments", json=security).status_code == 403


def test_certification_label_without_exact_module_version_mode_is_not_validation(assured):
    clients, db, _ = assured
    scan = new_scan(db)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=scan.id).one()
    body = {"expected_revision": 0, "purpose": "SYMMETRIC", "security_use": True, "evidence_ref": "cert/label", "rationale": "Vendor label only", "certification_label": "FIPS"}
    result = done(admin(clients).post(P + f"/findings/{evidence.id}/assessments", json=body))
    assert result["payload"]["certification"] == "INSUFFICIENT_EXACT_MODULE_VERSION_MODE"
    assert result["payload"]["posture_acceptable"] is None


def test_quarantine_blob_is_bounded_opaque_and_exact_estate(assured):
    clients, db, _ = assured
    a = clients["bank_a"]
    raw = b'<untrusted-do-not-parse SYSTEM="file:///etc/passwd">'
    stored = blob(a, raw)
    assert a.get(P + f"/evidence-blobs/{stored['blob_id']}/content").status_code == 403
    response = admin(clients).get(P + f"/evidence-blobs/{stored['blob_id']}/content")
    assert response.content == raw and response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"] == "application/octet-stream"
    assert clients["bank_b"].get(P + f"/evidence-blobs/{stored['blob_id']}/content").status_code == 404
    assert clients["platform_admin"].get(P + f"/evidence-blobs/{stored['blob_id']}/content").status_code == 404
    assert a.post(P + "/evidence-blobs?evidence_ref=test", content=b'x' * 1048577,
                  headers={"Content-Type": "application/octet-stream"}).status_code == 413
    assert a.post(P + "/registers", content=b' ' * (2 * 1048576 + 1), headers={"Content-Type": "application/json"}).status_code == 413
    assert db.query(AssuranceBlob).count() == 1


def _domain_owner_id(_client):
    from db.connection.session import SessionLocal
    with SessionLocal() as db:
        return db.query(User).filter_by(username="platform_admin").one().id


def sample_body(client, scan):
    first = blob(client, b"redacted first-pass source checksum")
    held = blob(client, b"redacted held-out source checksum")
    return {"scope_description": "Approved wrapper sample, not a bank-wide accuracy estimate",
        "selection_method": "Owner stratified wrapper/config sample", "domain_owner": "payments-owner",
        "domain_owner_user_id": str(_domain_owner_id(client)), "approval_ref": "change/sample-17", "blind_spots": ["No proprietary/native/mobile runtime sample supplied"],
        "scan_ids": [scan.id], "units": [
            {"file": "crypto.py", "algorithm": "MD5", "source_class": "wrappers_config", "split": "FIRST_PASS", "fixture_blob_id": first["blob_id"]},
            {"file": "crypto.py", "algorithm": "SHA256", "source_class": "wrappers_config", "split": "FIRST_PASS", "fixture_blob_id": first["blob_id"]},
            {"file": "held.py", "algorithm": "SHA1", "source_class": "wrappers_config", "split": "HOLDOUT", "fixture_blob_id": held["blob_id"]}]}


def test_approved_sample_freezes_first_pass_and_preserves_review_then_repeat(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    scan = new_scan(db)
    proposed = done(a.post(P + "/samples", json=sample_body(a, scan)))
    sid = proposed["subject_id"]
    assert a.get(P + f"/samples/{sid}/workbook").status_code == 409
    done(reviewer.post(P + f"/samples/{sid}/approve", json=approval()), 200)
    wb = done(a.get(P + f"/samples/{sid}/workbook"), 200)
    labels = [{"unit_id": u["unit_id"], "truth": "ABSENT" if u["algorithm"] == "MD5" else "PRESENT",
               "explanation": "Customer inspected exact wrapper/config bytes"} for u in wb["units"]]
    review_body = {"phase": "FIRST_PASS", "domain_owner": "payments-owner", "evidence_ref": "owner/review-17", "units": labels}
    first = done(reviewer.post(P + f"/samples/{sid}/reviews", json=review_body))
    assert first["payload"]["metrics"]["FP"] == first["payload"]["metrics"]["FN"] == 1
    assert first["payload"]["global_accuracy_claim"] is False
    assert "native_provider" in first["payload"]["uncovered_source_classes"]
    assert reviewer.post(P + f"/samples/{sid}/reviews", json=review_body).status_code == 409
    seeds = done(reviewer.post(P + f"/samples/{sid}/regressions"))
    assert len(seeds["case_ids"]) == 2 and seeds["executed_regression_tests"] is False
    assert reviewer.post(P + f"/samples/{sid}/regressions").json()["case_ids"] == seeds["case_ids"]
    assert a.post(P + f"/samples/{sid}/repeat", json={"scan_ids": [scan.id], "evidence_ref": "repeat/17"}).status_code == 409
    repeat_scan = new_scan(db, algorithms=("SHA1",), version="1.1", start=utcnow(), file_name="held.py")
    done(a.post(P + f"/samples/{sid}/repeat", json={"scan_ids": [repeat_scan.id], "evidence_ref": "repeat/18"}))
    held = done(a.get(P + f"/samples/{sid}/workbook?phase=HOLDOUT"), 200)
    assert len(held["units"]) == 1 and held["units"][0]["predicted"] is True
    final = done(reviewer.post(P + f"/samples/{sid}/reviews", json={"phase": "HOLDOUT", "domain_owner": "payments-owner",
        "evidence_ref": "owner/held-18", "units": [{"unit_id": held["units"][0]["unit_id"], "truth": "PRESENT", "explanation": "Held out from regression tuning"}]}))
    assert final["payload"]["metrics"]["TP"] == 1
    saved_first = a.get(P + f"/records/accuracy_review/{first['subject_id']}").json()["revisions"]
    assert len(saved_first) == 1 and saved_first[0]["payload"] == first["payload"]
    assert clients["bank_b"].get(P + f"/samples/{sid}/workbook").status_code == 404


def test_held_out_bytes_cannot_be_first_pass_or_known_regressions(assured):
    clients, db, _ = assured
    a = clients["bank_a"]
    scan = new_scan(db)
    body = sample_body(a, scan)
    body["units"][-1]["fixture_blob_id"] = body["units"][0]["fixture_blob_id"]
    assert a.post(P + "/samples", json=body).status_code == 409
    # A regression seed is not an executable file or a passing scanner test.
    seed = store.append(db, "a", "regression_case", str(uuid.uuid4()), 0,
        {"fixture_sha256": store.blob(db, "a", body["units"][-1]["fixture_blob_id"]).sha256}, "test-actor")
    body["units"][0]["fixture_blob_id"] = body["units"][1]["fixture_blob_id"] = blob(a, b"different first pass fixture")["blob_id"]
    assert a.post(P + "/samples", json=body).status_code == 409
    assert seed.payload["fixture_sha256"]


def test_empty_accuracy_denominators_are_unknown_not_perfect(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    scan = new_scan(db, algorithms=())
    sid = done(a.post(P + "/samples", json=sample_body(a, scan)))["subject_id"]
    done(reviewer.post(P + f"/samples/{sid}/approve", json=approval()), 200)
    wb = a.get(P + f"/samples/{sid}/workbook").json()
    review = done(reviewer.post(P + f"/samples/{sid}/reviews", json={"phase": "FIRST_PASS", "domain_owner": "payments-owner",
        "evidence_ref": "owner/negatives", "units": [{"unit_id": u["unit_id"], "truth": "ABSENT", "explanation": "Confirmed negative"} for u in wb["units"]]}))
    assert review["payload"]["metrics"]["precision"] is None
    assert review["payload"]["metrics"]["recall"] is None
    assert review["payload"]["metrics"]["TN"] == 2


def signer_and_key(clients):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    private = Ed25519PrivateKey.generate()
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    body = {"expected_revision": 0, "label": "Approved synthetic supplier test public key", "public_key_base64": public,
            "expires_at": (utcnow() + timedelta(days=3)).isoformat(), "evidence_ref": "supplier/key-review"}
    row = done(admin(clients).post(P + "/signers", json=body))
    return row, private, body


def export_document(**changes):
    return {"schema_version": "vendor-export/v1", "vendor": "Synthetic Fixture Supplier", "product": "Fixture Device",
            "version": "1.0", "profile": "offline-pilot", "customer_id": "a", "build_digest": "sha256:" + "a" * 64,
            "expected_pages": 1, "expected_items": 1,
            "pages": [{"number": 1, "facts": [{"kind": "crypto", "algorithm": "SHA256", "purpose": "CHECKSUM", "security_use": False, "location": "export/config/17"}]}], **changes}


def supplier_body(artifact, signer, private, document=None, manifest_changes=None, invalid_signature=False, raw=None):
    from shared_models.assurance import SupplierManifest
    payload = raw if raw is not None else store.encoded(document or export_document())
    now = utcnow()
    manifest = SupplierManifest.model_validate({"estate_scope": "tenant:a", "customer_id": "a", "build_digest": artifact["digest"],
        "payload_sha256": hashlib.sha256(payload).hexdigest(), "vendor": "Synthetic Fixture Supplier", "product": "Fixture Device",
        "version": "1.0", "profile": "offline-pilot", "format": "vendor-export/v1-json",
        "collected_at": (now - timedelta(hours=1)).isoformat(), "expires_at": (now + timedelta(days=1)).isoformat(), **(manifest_changes or {})}).model_dump(mode="json")
    signature = base64.b64encode(private.sign(store.encoded(manifest))).decode()
    return {"artifact_id": artifact["id"], "signer_id": signer["subject_id"], "manifest": manifest,
            "signature_base64": "bad" if invalid_signature else signature, "payload_base64": base64.b64encode(payload).decode()}


@pytest.mark.parametrize("problem", ["WRONG_CUSTOMER", "WRONG_BUILD", "STALE", "UNTRUSTED_SIGNER", "DIGEST_MISMATCH", "MALFORMED"])
def test_supplier_wrong_customer_build_stale_signer_or_malformed_stays_quarantined(assured, problem):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    artifact = register(a)
    signer, private, _ = signer_and_key(clients)
    changes = {"customer_id": "b"} if problem == "WRONG_CUSTOMER" else {"build_digest": "sha256:" + "b" * 64} if problem == "WRONG_BUILD" else {"expires_at": (utcnow() - timedelta(minutes=1)).isoformat()} if problem == "STALE" else {"payload_sha256": "f" * 64} if problem == "DIGEST_MISMATCH" else {}
    body = supplier_body(artifact, signer, private, manifest_changes=changes,
                         invalid_signature=problem == "UNTRUSTED_SIGNER", raw=b"<untrusted XML>" if problem == "MALFORMED" else None)
    first = done(a.post(P + "/supplier-evidence", json=body))
    assert first["payload"]["state"] == "QUARANTINED"
    result = done(reviewer.post(P + f"/supplier-evidence/{first['subject_id']}/approve", json=approval()), 200)
    assert result["payload"]["state"] == "QUARANTINED" and problem in result["payload"]["problems"]
    assert result["payload"]["independent_truth_verified"] is False
    assert reviewer.get(P + f"/evidence-blobs/{first['subject_id']}/content").status_code == 409
    assert db.query(AssuranceBlob).count() == 1
    assert clients["bank_b"].get(P + f"/evidence-blobs/{first['subject_id']}/content").status_code == 404


def test_supplier_signature_and_review_do_not_qualify_live_vendor_and_revocation_is_current(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    artifact = register(a)
    signer, private, signer_body = signer_and_key(clients)
    body = supplier_body(artifact, signer, private)
    row = done(a.post(P + "/supplier-evidence", json=body))
    result = done(reviewer.post(P + f"/supplier-evidence/{row['subject_id']}/approve", json=approval()), 200)
    assert result["payload"]["state"] == "APPROVED_OFFLINE_JSON"
    assert result["payload"]["origin_verified"] is True and result["payload"]["independent_truth_verified"] is False
    signer_body.update(expected_revision=1, revoked=True)
    done(reviewer.put(P + f"/signers/{signer['subject_id']}", json=signer_body), 200)
    from api.assurance.adapters import check
    assert check(db, "a", result["payload"]) == ["UNTRUSTED_SIGNER"]
    signer_body.update(expected_revision=2, public_key_base64=base64.b64encode(b"x" * 32).decode())
    assert reviewer.put(P + f"/signers/{signer['subject_id']}", json=signer_body).status_code == 409


def test_adapter_supported_only_for_actual_exercised_offline_profile(assured, monkeypatch):
    from shared_models.qualified_export import collect_export
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    artifact = register(a)
    signer, private, _ = signer_and_key(clients)
    spec = {"expected_revision": 0, "vendor": "Synthetic Fixture Supplier", "product": "Fixture Device", "version": "1.0",
        "profile": "offline-pilot", "format": "vendor-export/v1-json", "required_permissions": ["operator-approved export"],
        "collected_fields": ["crypto"], "pagination": "COMPLETE_OR_EXPLICIT_PARTIAL", "requests_per_second": 1,
        "retries": 0, "retry_backoff_seconds": 1, "exclusions": ["No live API permissions/rate behavior qualified"], "evidence_ref": "profile/customer-pilot"}
    profile = done(a.post(P + "/adapters", json=spec))
    aid = profile["subject_id"]
    assert a.get(P + f"/adapters/{aid}").json()["support_status"] == "NOT_QUALIFIED"
    cases = []
    for outcome in ("COMPLETE", "PARTIAL", "WRONG_CUSTOMER", "WRONG_BUILD", "STALE", "UNTRUSTED_SIGNER", "MALFORMED"):
        document = export_document(expected_pages=2, expected_items=2) if outcome == "PARTIAL" else export_document()
        changes = {"customer_id": "b"} if outcome == "WRONG_CUSTOMER" else {"build_digest": "sha256:" + "b" * 64} if outcome == "WRONG_BUILD" else {"expires_at": (utcnow() - timedelta(minutes=1)).isoformat()} if outcome == "STALE" else {}
        body = supplier_body(artifact, signer, private, document=document, manifest_changes=changes,
                             invalid_signature=outcome == "UNTRUSTED_SIGNER", raw=b"not-json" if outcome == "MALFORMED" else None)
        evidence = done(a.post(P + "/supplier-evidence", json=body))
        expected = None
        if outcome in {"COMPLETE", "PARTIAL"}:
            done(reviewer.post(P + f"/supplier-evidence/{evidence['subject_id']}/approve", json=approval()), 200)
            expected = store.digest(collect_export(base64.b64decode(body["payload_base64"]), body["manifest"]))
        cases.append({"supplier_evidence_id": evidence["subject_id"], "expected_outcome": outcome, "expected_output_sha256": expected})
    receipt = done(reviewer.post(P + f"/adapters/{aid}/qualifications", json={"cases": cases, "evidence_ref": "qualification/offline-golden-pilot"}))
    assert receipt["payload"]["passed"] is True and receipt["payload"]["live_vendor_supported"] is False
    status = a.get(P + f"/adapters/{aid}").json()
    assert status["offline_profile_exercised"] is True and status["live_vendor_supported"] is False
    facts = done(a.get(P + f"/adapters/{aid}/supplier-evidence/{cases[0]['supplier_evidence_id']}/observations"), 200)
    assert facts["facts"][0]["purpose"] == "CHECKSUM" and facts["independent_truth_verified"] is False
    assert facts["automatic_identity_joins"] is False
    with monkeypatch.context() as changed_engine:
        changed_engine.setattr("api.assurance.adapters.engine_fingerprint", lambda: "f" * 64)
        assert a.get(P + f"/adapters/{aid}").json()["offline_profile_exercised"] is False
    bad = deepcopy(cases)
    bad[0]["expected_output_sha256"] = "f" * 64
    failed = done(reviewer.post(P + f"/adapters/{aid}/qualifications", json={"cases": bad, "evidence_ref": "qualification/negative-digest"}))
    assert failed["payload"]["passed"] is False
    assert a.get(P + f"/adapters/{aid}").json()["support_status"] == "NOT_QUALIFIED"
    spec.update(expected_revision=1, version="2.0")
    done(a.put(P + f"/adapters/{aid}", json=spec), 200)
    assert a.get(P + f"/adapters/{aid}").json()["offline_profile_exercised"] is False


def redis_profile_body(**changes):
    return {"expected_revision": 0, "deployment_id": "synthetic-lab-not-a-bank-deployment", "topology_sha256": "a" * 64,
        "roles": ["queue"], "max_recovery_seconds": 10, "max_acknowledged_event_loss": 0,
        "minimum_recovery_operations_per_second": 5, "minimum_measurement_seconds": 5,
        "evidence_ref": "approved/redis-objectives", **changes}


def measurement_body(**changes):
    now = utcnow()
    return {"deployment_id": "synthetic-lab-not-a-bank-deployment", "topology_sha256": "a" * 64,
        "scenario": "process_kill", "role": "queue", "fault_at": (now - timedelta(seconds=30)).isoformat(),
        "recovered_at": (now - timedelta(seconds=25)).isoformat(), "measured_until": (now - timedelta(seconds=5)).isoformat(),
        "acknowledged": [{"event_id": "old-ack-17", "acknowledged_at": (now - timedelta(seconds=31)).isoformat()}],
        "recovered_event_ids": ["old-ack-17"], "recovery_operations": 200, "evidence_ref": "fault/process-kill-17",
        "fault_witness": "Approved operator retained kill/restart logs", **changes}


def measurement(client, profile_id, body):
    from shared_models.assurance import RedisMeasurement
    # Match the same canonical timestamp representation the typed receiver uses.
    normalized = RedisMeasurement.model_validate({**body, "evidence_blob_id": str(uuid.uuid4())}).model_dump(mode="json", exclude={"evidence_blob_id"})
    saved = blob(client, store.encoded({"measurement": normalized, "operator_log": "Synthetic fixture, not an actual fault run"}))
    return client.post(P + f"/redis-objectives/{profile_id}/measurements", json={**normalized, "evidence_blob_id": saved["blob_id"]})


def test_redis_event_loss_is_not_hidden_by_a_complete_new_snapshot(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    profile = done(reviewer.post(P + "/redis-objectives", json=redis_profile_body()))
    pid = profile["subject_id"]
    lost = measurement_body(recovered_event_ids=["new-complete-snapshot"])
    receipt = done(measurement(a, pid, lost))
    assert receipt["payload"]["acknowledged_event_loss"] == 1
    assert receipt["payload"]["meets_reported_objectives"] is False
    assert receipt["payload"]["snapshot_after_failover_is_prior_ack_survival_proof"] is False
    done(reviewer.post(P + f"/redis-measurements/{receipt['subject_id']}/review", json=approval()), 200)
    report = reviewer.get(P + f"/redis-objectives/{pid}/qualification").json()
    assert report["deployment_evidence_meets_objectives"] is False
    assert report["whole_infrastructure_qualified"] is False
    cell = next(c for c in report["matrix"] if c["scenario"] == "process_kill")
    assert cell["state"] == "REVIEWED" and cell["accepted"] is False
    assert "realtime" in report["unqualified_roles"]
    # Better later evidence is retained, but cannot qualify without review.
    better = done(measurement(a, pid, measurement_body()))
    assert better["payload"]["meets_reported_objectives"] is True
    pending = reviewer.get(P + f"/redis-objectives/{pid}/qualification").json()
    assert next(c for c in pending["matrix"] if c["scenario"] == "process_kill")["accepted"] is False
    assert clients["bank_b"].get(P + f"/redis-objectives/{pid}/qualification").status_code == 404


@pytest.mark.parametrize("change", ["snapshot_only", "duplicate", "wrong_topology", "wrong_deployment", "future", "journal_disagreement"])
def test_redis_qualification_refuses_unproven_measurements(assured, change):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    pid = done(reviewer.post(P + "/redis-objectives", json=redis_profile_body()))["subject_id"]
    body = measurement_body()
    if change == "snapshot_only": body["acknowledged"][0]["acknowledged_at"] = body["recovered_at"]
    if change == "duplicate": body["acknowledged"] *= 2
    if change == "wrong_topology": body["topology_sha256"] = "b" * 64
    if change == "wrong_deployment": body["deployment_id"] = "different-bank"
    if change == "future": body["measured_until"] = (utcnow() + timedelta(hours=1)).isoformat()
    if change == "journal_disagreement":
        saved = blob(a, b'{"measurement":{"unverified":"PASS"}}')
        response = a.post(P + f"/redis-objectives/{pid}/measurements", json={**body, "evidence_blob_id": saved["blob_id"]})
    elif change in {"snapshot_only", "duplicate"}:
        response = a.post(P + f"/redis-objectives/{pid}/measurements", json={**body, "evidence_blob_id": str(uuid.uuid4())})
    else:
        response = measurement(a, pid, body)
    assert response.status_code in (409, 422)
    assert db.query(AssuranceRevision).filter_by(kind="redis_measurement").count() == 0


def test_history_and_blobs_are_append_only_through_orm(assured):
    clients, db, _ = assured
    row = done(clients["bank_a"].post(P + "/registers", json=manifest()))
    stored = db.get(AssuranceRevision, row["id"])
    stored.payload = {"forged": "whole bank complete"}
    with pytest.raises(ValueError, match="append-only"):
        db.commit()
    db.rollback()
    db.refresh(stored)
    assert stored.payload == row["payload"]
    b = blob(clients["bank_a"])
    db.delete(db.get(AssuranceBlob, b["blob_id"]))
    with pytest.raises(ValueError, match="append-only"):
        db.commit()
    db.rollback()


def test_evidence_trace_uses_exact_release_package_and_reviewed_edge_not_names(assured):
    from test_software_supply_chain_api import scan as scan_sbom
    clients, db, tmp = assured
    a, reviewer = clients["bank_a"], admin(clients)
    sbom, package_identity = scan_sbom(a, tmp)
    artifact = register(a)
    binding = attach(a, artifact, sbom)
    done(deploy(a, artifact, system_id="system-a"))
    observation = new_scan(db)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=observation.id).one()
    trace = done(a.get(P + "/applications/system-a/trace"), 200)
    assert trace["paths"] == [] and trace["unresolved"]
    relation = {"expected_revision": 0, "relation": "PACKAGE_CRYPTO", "subject_type": "sbom_binding", "subject_id": binding["id"],
        "object_type": "evidence", "object_id": evidence.id, "package_identity": package_identity,
        "observed_at": (utcnow() - timedelta(minutes=1)).isoformat(), "expires_at": (utcnow() + timedelta(hours=1)).isoformat(),
        "evidence_ids": [evidence.id], "evidence_ref": "owner/package-file-mapping-17", "basis": "OPERATOR_REVIEWED", "rationale": "Explicit source/package review, not an inferred runtime link"}
    wrong = {**relation, "package_identity": "pkg:pypi/requests@0.0.0"}
    assert a.post(P + "/relationships", json=wrong).status_code == 409
    proposed = done(a.post(P + "/relationships", json=relation))
    assert a.get(P + "/applications/system-a/trace").json()["paths"] == []
    done(reviewer.post(P + f"/relationships/{proposed['subject_id']}/approve", json=approval()), 200)
    trace = a.get(P + "/applications/system-a/trace").json()
    path = next(p for p in trace["paths"] if p["crypto_evidence_id"] == evidence.id)
    assert path["application_id"] == "system-a" and path["artifact_digest"] == artifact["digest"]
    assert path["package_identity"] == package_identity and path["sbom_sha256"] == binding["sbom_sha256"]
    assert path["invocation_verified"] is False and path["deployed_verified"] is False
    assert clients["bank_b"].get(P + "/applications/system-a/trace").status_code == 404
    assert clients["platform_admin"].get(P + "/applications/system-a/trace").status_code == 404


def test_json_boundary_rejects_duplicate_keys_and_excessive_nesting(assured):
    clients, _, _ = assured
    a = clients["bank_a"]
    for raw in (b'{"expected_revision":0,"expected_revision":1}', b'[' * 25 + b'0' + b']' * 25, b'{"x":NaN}'):
        assert a.post(P + "/registers", content=raw, headers={"Content-Type": "application/json"}).status_code == 422


def test_regression_result_requires_matching_scanner_file_hash_and_current_run(assured):
    clients, db, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    original = new_scan(db)
    sid = done(a.post(P + "/samples", json=sample_body(a, original)))["subject_id"]
    done(reviewer.post(P + f"/samples/{sid}/approve", json=approval()), 200)
    wb = a.get(P + f"/samples/{sid}/workbook").json()
    done(reviewer.post(P + f"/samples/{sid}/reviews", json={"phase": "FIRST_PASS", "domain_owner": "payments-owner",
        "evidence_ref": "owner/corrected-negatives", "units": [{"unit_id": u["unit_id"], "truth": "ABSENT", "explanation": "Confirmed non-occurrence"} for u in wb["units"]]}))
    seeds = done(reviewer.post(P + f"/samples/{sid}/regressions"))
    case_id = seeds["case_ids"][0]
    assert a.post(P + f"/regressions/{case_id}/results", json={"scan_id": original.id, "evidence_ref": "old/receipt"}).status_code == 409
    corrected = new_scan(db, algorithms=(), start=utcnow(), version="1.1")
    receipt = done(a.post(P + f"/regressions/{case_id}/results", json={"scan_id": corrected.id, "evidence_ref": "regression/fresh-worker-run"}))
    assert receipt["payload"]["passed"] is True and receipt["payload"]["actual_present"] is False
    # A newer scan with changed input cannot masquerade as the same regression.
    wrong = new_scan(db, algorithms=(), start=utcnow(), version="1.2")
    wrong.statistics = {"file_observation_receipts": [{"file": "crypto.py", "sha256": "f" * 64, "parser_completed": True}]}
    db.commit()
    assert a.post(P + f"/regressions/{case_id}/results", json={"scan_id": wrong.id, "evidence_ref": "wrong/fixture"}).status_code == 409


def test_accuracy_requires_domain_owner_identity_and_actual_byte_binding(assured):
    clients, db, _ = assured
    a = clients["bank_a"]
    scan = new_scan(db)
    body = sample_body(a, scan)
    body["domain_owner_user_id"] = db.query(User).filter_by(username="bank_b").one().id
    assert a.post(P + "/samples", json=body).status_code == 404
    body["domain_owner_user_id"] = _domain_owner_id(a)
    body["units"][0]["fixture_blob_id"] = blob(a, b"different bytes not parsed by this scan")["blob_id"]
    assert a.post(P + "/samples", json=body).status_code == 409
    scan.statistics = {}
    db.commit()
    assert a.post(P + "/samples", json=sample_body(a, scan)).status_code == 409


def test_signed_supplier_scope_cannot_alias_platform_null_or_a_named_tenant(assured):
    clients, _, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    artifact = register(a)
    signer, private, _ = signer_and_key(clients)
    body = supplier_body(artifact, signer, private, manifest_changes={"estate_scope": "platform"})
    row = done(a.post(P + "/supplier-evidence", json=body))
    assert "WRONG_CUSTOMER" in row["payload"]["problems"]
    result = done(reviewer.post(P + f"/supplier-evidence/{row['subject_id']}/approve", json=approval()), 200)
    assert result["payload"]["state"] == "QUARANTINED"
    assert reviewer.get(P + f"/evidence-blobs/{row['subject_id']}/content").status_code == 409


def test_tied_redis_measurements_cannot_choose_an_old_pass_over_conflicting_failure(assured):
    clients, _, _ = assured
    a, reviewer = clients["bank_a"], admin(clients)
    pid = done(reviewer.post(P + "/redis-objectives", json=redis_profile_body()))["subject_id"]
    good = measurement_body()
    first = done(measurement(a, pid, good))
    done(reviewer.post(P + f"/redis-measurements/{first['subject_id']}/review", json=approval()), 200)
    failed = done(measurement(a, pid, {**good, "recovered_event_ids": []}))
    done(reviewer.post(P + f"/redis-measurements/{failed['subject_id']}/review", json=approval()), 200)
    report = reviewer.get(P + f"/redis-objectives/{pid}/qualification").json()
    cell = next(c for c in report["matrix"] if c["scenario"] == "process_kill")
    assert cell["accepted"] is False and cell["state"] == "AMBIGUOUS_LATEST_MEASUREMENT_ORDER"
