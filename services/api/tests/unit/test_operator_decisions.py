"""Real selected-estate auth/SQL and retained condition verification, synthetic fixtures."""
from datetime import timedelta
import pytest
from db.models.base import utcnow
from db.models.scan_job import ScanJob
from db.models.network_scan_run import NetworkScanRun
from db.models.remediation_task import RemediationTask
from api.routers.remediation import _finding_snapshot
from api.assurance import store
from test_assurance_workflows import assured as assured, banks as banks, admin, done, new_scan, manifest, P


def tls(db, owner="a", fp="a" * 64, endpoint="bank.example:443", start=None, status="COMPLETED", sni="bank.example"):
    start = start or utcnow() - timedelta(seconds=20)
    job = ScanJob(tenant_id=owner, job_type="NETWORK_SCAN", target_repo=endpoint, triggered_by="bank_a",
                  status=status, started_at=start, completed_at=start + timedelta(milliseconds=1))
    db.add(job); db.flush()
    run = NetworkScanRun(tenant_id=owner, target_kind="hosts", result={"live": True,
        "collection": {"schema": "cryptoscan.network-collection/1", "job_id": job.id, "kind": "hosts"},
        "probes": [{"endpoint": endpoint, "status": "OK", "certificates": [{"fingerprint_sha256": fp}],
                    "metadata": {"certificate_hostname": sni, "starttls": None}}]})
    db.add(run); db.commit()
    return run


def proposal(client, run, **kw):
    return client.post(P + "/remediation-changes", json={"kind": "TLS_CERTIFICATE", "owner_ref": "cert-ops",
        "change_ref": "change/123", "verification_criteria": "Exact intended endpoint must present replacement fingerprint",
        "expires_at": (utcnow() + timedelta(hours=1)).isoformat(), "before_run_id": run.id,
        "endpoint": "bank.example:443", "expected_fingerprint_sha256": "b" * 64, **kw})


def approved(clients, run):
    proposed = done(proposal(clients["bank_a"], run))
    identifier = proposed["subject_id"]
    body = {"expected_revision": 1, "evidence_ref": "review/123", "reason": "Exact condition reviewed"}
    assert clients["bank_a"].post(P + f"/remediation-changes/{identifier}/approve", json=body).status_code == 403
    done(admin(clients).post(P + f"/remediation-changes/{identifier}/approve", json=body))
    return identifier


def reported(clients, identifier):
    now = utcnow()
    done(clients["bank_a"].post(P + f"/remediation-changes/{identifier}/report-complete", json={
        "expected_revision": 2, "completed_at": now.isoformat(), "evidence_ref": "action/report"}))
    return now


def check(clients, identifier, run):
    history = admin(clients).get(P + f"/records/condition_proof/{store.subject(identifier, 'condition_proof')}")
    revision = history.json()["revisions"][-1]["revision"] if history.status_code == 200 else 0
    return done(admin(clients).post(P + f"/remediation-changes/{identifier}/verify", json={
        "expected_revision": 3, "rescan_id": run.id, "expected_proof_revision": revision}))


def test_tls_report_is_not_proof_and_exact_identity_is_retained(assured):
    clients, db, _ = assured
    before = tls(db)
    identifier = approved(clients, before)
    reported(clients, identifier)
    # A completed ticket and the original successful run cannot prove a change.
    assert check(clients, identifier, before)["payload"]["result"] == "INCONCLUSIVE"
    wrong = tls(db, fp="c" * 64, start=utcnow() - timedelta(milliseconds=5))
    assert check(clients, identifier, wrong)["payload"]["result"] == "FAILED"
    after = tls(db, fp="b" * 64, start=utcnow() - timedelta(milliseconds=5))
    proof = check(clients, identifier, after)
    assert proof["payload"]["result"] == "VERIFIED"
    assert proof["payload"]["before"]["fingerprint_sha256"] == "a" * 64
    assert proof["payload"]["after"]["fingerprint_sha256"] == "b" * 64
    history = done(admin(clients).get(P + f"/records/remediation_change/{identifier}"), 200)
    assert history["revisions"][-1]["payload"]["state"] == "REPORTED_COMPLETE"
    assert clients["bank_b"].get(P + f"/records/condition_proof/{proof['subject_id']}").status_code == 404


@pytest.mark.parametrize("case", ["foreign", "endpoint", "failed", "sni", "empty", "expired", "policy", "future", "ambiguous", "no_sni"])
def test_invalid_observation_never_closes_condition(assured, case):
    clients, db, _ = assured
    identifier = approved(clients, tls(db))
    reported(clients, identifier)
    after = tls(db, owner="b" if case == "foreign" else "a", fp="b" * 64,
                endpoint="other.example:443" if case == "endpoint" else "bank.example:443",
                status="FAILED" if case == "failed" else "COMPLETED", sni="other.example" if case == "sni" else "bank.example",
                start=utcnow() + timedelta(minutes=1) if case == "future" else utcnow() - timedelta(milliseconds=5))
    if case == "ambiguous":
        after.result = {**after.result, "probes": after.result["probes"] * 2}; db.commit()
    if case == "no_sni":
        after.result = {**after.result, "probes": [{**after.result["probes"][0], "metadata": {}}]}; db.commit()
    if case == "empty":
        after.result = {**after.result, "probes": []}; db.commit()
    if case in {"expired", "policy"}:
        from api.assurance import store
        old = store.latest(db, "a", "remediation_change", identifier)
        payload = {**old.payload, **({"expires_at": (utcnow() - timedelta(seconds=1)).isoformat()} if case == "expired" else {"policy_binding": {"revision": 999}})}
        # A new immutable fixture revision, never an in-place integrity bypass.
        store.append(db, "a", "remediation_change", identifier, 3, payload, "fixture")
        response = done(admin(clients).post(P + f"/remediation-changes/{identifier}/verify", json={"expected_revision": 4, "rescan_id": after.id}))
    else:
        response = check(clients, identifier, after)
    assert response["payload"]["result"] == "INCONCLUSIVE"


def test_self_approval_revision_conflict_and_reader_refusal(assured):
    clients, db, _ = assured
    p = done(proposal(admin(clients), tls(db)))
    identifier = p["subject_id"]
    body = {"expected_revision": 1, "evidence_ref": "review", "reason": "review"}
    assert admin(clients).post(P + f"/remediation-changes/{identifier}/approve", json=body).status_code == 409
    assert proposal(clients["reader_a"], tls(db)).status_code == 403
    assert clients["bank_b"].post(P + f"/remediation-changes/{identifier}/report-complete", json={"expected_revision": 1, "completed_at": utcnow().isoformat(), "evidence_ref": "x"}).status_code == 404


def source_job(db, scan, start=None):
    scan.scan_start = start or scan.scan_start
    scan.scan_end = scan.scan_start + timedelta(milliseconds=1)
    job = ScanJob(tenant_id="a", job_type="MANUAL", target_repo=scan.target_location, scan_id=scan.id,
        triggered_by="bank_a", status="COMPLETED", started_at=scan.scan_start,
        completed_at=scan.scan_end)
    db.add(job); db.commit()
    return job


def test_source_exact_site_and_changed_content_proof(assured, monkeypatch):
    clients, db, _ = assured
    from db.models.evidence_record import EvidenceRecord
    before = new_scan(db)
    source_job(db, before)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=before.id).one()
    evidence.compliance_status = "FAIL"; db.commit()
    task = RemediationTask(tenant_id="a", evidence_id=evidence.id, scan_id=before.id, rule_id="replace-md5",
        original_finding=_finding_snapshot(evidence), target_location=before.target_location, owner="payments", status="PROPOSED", created_by="bank_a")
    db.add(task); db.commit()
    p = done(clients["bank_a"].post(P + "/remediation-changes", json={"kind": "SOURCE_SITE", "owner_ref": "payments",
        "change_ref": "change/124", "verification_criteria": "Replace checksum algorithm at exact original site", "task_id": task.id,
        "expected_algorithm": "SHA-256", "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}))
    identifier = p["subject_id"]
    done(admin(clients).post(P + f"/remediation-changes/{identifier}/approve", json={"expected_revision": 1, "evidence_ref": "review", "reason": "condition reviewed"}))
    reported(clients, identifier)
    after = new_scan(db, algorithms=("SHA-256",), start=utcnow() - timedelta(milliseconds=5))
    source_job(db, after)
    row = db.query(EvidenceRecord).filter_by(scan_id=after.id).one(); row.compliance_status = "PASS"
    db.commit()
    assert check(clients, identifier, after)["payload"]["result"] == "INCONCLUSIVE"  # unchanged source checksum
    after.statistics = {**after.statistics, "file_observation_receipts": [{"file": "crypto.py", "sha256": "f" * 64, "parser_completed": True}]}
    db.commit()
    proof = check(clients, identifier, after)
    assert proof["payload"]["result"] == "VERIFIED"
    db.refresh(task); assert task.status == "VERIFIED"
    inbox = done(admin(clients).get(P + "/operator-decisions"), 200)
    assert inbox["sections"]["tasks"]["items"][0]["current_condition_verified"]
    with monkeypatch.context() as clock:
        clock.setattr("api.assurance.operator.utcnow", lambda: utcnow() + timedelta(hours=2))
        stale = done(admin(clients).get(P + "/operator-decisions"), 200)
        assert stale["sections"]["tasks"]["items"][0]["needs_attention"]
        assert stale["sections"]["proofs"]["items"][0]["freshness_state"] == "STALE_OR_UNAVAILABLE"
    row.line_number = 99; db.commit()
    assert check(clients, identifier, after)["payload"]["result"] == "INCONCLUSIVE"
    db.refresh(task); assert task.status == "COMPLETED"
    replacement = done(clients["bank_a"].post(P + "/remediation-changes", json={"kind": "SOURCE_SITE", "owner_ref": "payments",
        "change_ref": "change/next", "verification_criteria": "Reviewed new change", "task_id": task.id,
        "expected_algorithm": "SHA-256", "expires_at": (utcnow() + timedelta(hours=1)).isoformat()}))
    done(admin(clients).post(P + f"/remediation-changes/{replacement['subject_id']}/approve", json={"expected_revision": 1, "evidence_ref": "next/review", "reason": "supersedes old condition"}))
    assert check(clients, identifier, after)["payload"]["result"] == "INCONCLUSIVE"
    db.refresh(task); assert task.status == "ACCEPTED"  # old change cannot overwrite new task state


def test_inbox_independent_coverage_unknown_jobs_scope_and_pagination(assured):
    clients, db, _ = assured
    done(clients["bank_a"].post(P + "/registers", json=manifest()))
    for owner, status in [("a", "UNKNOWN"), ("a", "FAILED"), ("b", "UNKNOWN")]:
        db.add(ScanJob(tenant_id=owner, target_repo="/owned/" + owner, triggered_by="owner", status=status))
    db.commit()
    body = done(admin(clients).get(P + "/operator-decisions?limit=1"), 200)
    assert body["estate_id"] == "a" and body["page_is_whole_estate"] is False
    assert body["sections"]["jobs"]["has_more"]
    assert all(j["target"] == "/owned/a" for j in body["sections"]["jobs"]["items"])
    report = body["sections"]["coverage"]["items"][0]
    assert report["counts"]["NOT_ATTEMPTED"] == 1 and not report["whole_bank_verified"]
    platform = done(admin(clients, None).get(P + "/operator-decisions"), 200)
    assert not platform["sections"]["jobs"]["items"]
    assert clients["bank_b"].get(P + "/operator-decisions?limit=0").status_code == 422


def test_proof_compare_and_swap_prevents_stale_retry(assured):
    clients, db, _ = assured
    identifier = approved(clients, tls(db))
    reported(clients, identifier)
    after = tls(db, fp="b" * 64, start=utcnow() - timedelta(milliseconds=1))
    first = check(clients, identifier, after)
    stale = admin(clients).post(P + f"/remediation-changes/{identifier}/verify", json={"expected_revision": 3, "rescan_id": after.id, "expected_proof_revision": 0})
    assert stale.status_code == 409
    history = done(admin(clients).get(P + f"/records/condition_proof/{first['subject_id']}"), 200)
    assert len(history["revisions"]) == 1


def test_assigned_task_requires_owned_evidence_and_human_role(assured):
    clients, db, _ = assured
    from db.models.evidence_record import EvidenceRecord
    scan = new_scan(db)
    evidence = db.query(EvidenceRecord).filter_by(scan_id=scan.id).one()
    body = {"evidence_id": evidence.id, "owner_ref": "payments"}
    assert clients["bank_b"].post(P + "/remediation-tasks", json=body).status_code == 404
    assert clients["reader_a"].post(P + "/remediation-tasks", json=body).status_code == 403
    created = done(clients["bank_a"].post(P + "/remediation-tasks", json=body))
    assert created["owner"] == "payments" and created["status"] == "PROPOSED"


def test_revocation_preserves_old_proof_but_invalidates_current_resolution(assured):
    clients, db, _ = assured
    identifier = approved(clients, tls(db))
    reported(clients, identifier)
    proof = check(clients, identifier, tls(db, fp="b" * 64, start=utcnow() - timedelta(milliseconds=1)))
    assert proof["payload"]["result"] == "VERIFIED"
    done(admin(clients).post(P + f"/remediation-changes/{identifier}/revoke", json={"expected_revision": 3,
        "evidence_ref": "incident/revoke", "reason": "Approval withdrawn"}))
    inbox = done(admin(clients).get(P + "/operator-decisions"), 200)
    assert inbox["sections"]["changes"]["items"][0]["approval_current"] is False
    assert inbox["sections"]["proofs"]["items"][0]["freshness_state"] == "STALE_OR_UNAVAILABLE"
    assert inbox["sections"]["proofs"]["items"][0]["result"] == "VERIFIED"  # retained historical result, not current approval
    assert admin(clients).post(P + f"/remediation-changes/{identifier}/verify", json={"expected_revision": 4,
        "rescan_id": "nonexistent", "expected_proof_revision": 1}).status_code == 409
