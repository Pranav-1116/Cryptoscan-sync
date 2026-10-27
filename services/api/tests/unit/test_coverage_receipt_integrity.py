"""Regression: source coverage needs real parser proof and coherent SQL times.

Synthetic authenticated SQLite fixtures; not customer/site qualification.
"""
from copy import deepcopy
from datetime import timedelta

import pytest
from db.models.assurance import AssuranceRevision
from db.models.base import utcnow
from api.assurance import store
from test_assurance_workflows import (
    P, admin, assured as assured, banks as banks, done, manifest, new_scan, source_job,
)


def registered(clients):
    return done(clients["bank_a"].post(P + "/registers", json=manifest()))["subject_id"]


def submit(clients, rid, job, revision=0):
    return clients["bank_a"].put(P + f"/registers/{rid}/observations/repo-pay", json={
        "expected_revision": revision, "outcome": "RECEIPT", "job_id": job.id,
        "evidence_ref": "synthetic/source-receipt", "reason": "Review exact parsed source evidence",
    })


def report(clients, rid):
    return clients["bank_a"].get(P + f"/registers/{rid}/coverage")


@pytest.mark.parametrize("receipts", [
    [{}],
    [None],
    ["not-a-receipt"],
    {"file": "crypto.py", "sha256": "a" * 64, "parser_completed": True},
    [{"file": "crypto.py", "sha256": "a" * 64, "parser_completed": False}],
    [{"file": "crypto.py", "sha256": "a" * 64, "parser_completed": "true"}],
    [{"file": "crypto.py", "sha256": "a" * 64}],
    [{"file": "crypto.py", "sha256": "not-a-sha256", "parser_completed": True}],
    [{"file": "crypto.py", "sha256": "g" * 64, "parser_completed": True}],
    [{"file": "", "sha256": "a" * 64, "parser_completed": True}],
    [{"file": "../crypto.py", "sha256": "a" * 64, "parser_completed": True}],
    [{"file": "/other/crypto.py", "sha256": "a" * 64, "parser_completed": True}],
    [{"file": "crypto.py", "sha256": "a" * 64, "parser_completed": True}] * 2,
    [{"file": "crypto.py", "sha256": "a" * 64, "parser_completed": True},
     {"file": "crypto.py", "sha256": "b" * 64, "parser_completed": True}],
], ids=["empty-object", "null-entry", "string-entry", "not-a-list", "parser-failed",
        "string-success", "missing-success", "short-checksum", "nonhex-checksum", "empty-file",
        "parent-path", "absolute-path", "duplicate-file", "conflicting-file"])
def test_invalid_source_receipts_cannot_be_recorded_as_observed(assured, receipts):
    clients, db, _ = assured
    rid = registered(clients)
    scan = new_scan(db)
    scan.statistics = {"file_observation_receipts": receipts}
    db.commit()
    job = source_job(db, scan)
    response = submit(clients, rid, job)
    assert response.status_code == 409, response.text
    assert db.query(AssuranceRevision).filter_by(kind="coverage_observation").count() == 0
    result = done(report(clients, rid), 200)
    assert result["counts"]["NOT_ATTEMPTED"] == 1
    assert result["counts"]["OBSERVED"] == 0


@pytest.mark.parametrize("case", [
    "missing-job-start", "missing-job-end", "job-end-before-scan",
    "job-start-after-scan", "scan-end-before-start", "future-job-end",
])
def test_invalid_source_job_scan_intervals_cannot_establish_freshness(assured, case):
    clients, db, _ = assured
    rid = registered(clients)
    scan = new_scan(db)
    job = source_job(db, scan)
    if case == "missing-job-start":
        job.started_at = None
    elif case == "missing-job-end":
        job.completed_at = None
    elif case == "job-end-before-scan":
        job.completed_at = scan.scan_start - timedelta(seconds=1)
    elif case == "job-start-after-scan":
        job.started_at = scan.scan_end + timedelta(seconds=1)
    elif case == "scan-end-before-start":
        scan.scan_end = scan.scan_start - timedelta(seconds=1)
    elif case == "future-job-end":
        job.completed_at = utcnow() + timedelta(hours=1)
    db.commit()
    response = submit(clients, rid, job)
    assert response.status_code == 409, response.text
    assert db.query(AssuranceRevision).filter_by(kind="coverage_observation").count() == 0


def test_partial_primary_file_receipts_do_not_claim_complete_source_or_bank(assured):
    clients, db, _ = assured
    rid = registered(clients)
    scan = new_scan(db)
    scan.statistics = {**scan.statistics, "file_receipts_complete": False,
                       "file_receipts_scope": "PRIMARY_DISCOVERED_SOURCE_FILES_ONLY"}
    job = source_job(db, scan)
    done(submit(clients, rid, job), 200)
    result = done(report(clients, rid), 200)
    assert result["counts"]["OBSERVED"] == 1
    assert result["registered_targets"] == 1
    assert result["whole_bank_verified"] is False
    assert result["targets"][0]["receipt"]["collection_complete"] is None
    assert result["register_completeness"] == "PARTIAL"
    assert clients["bank_b"].get(P + f"/registers/{rid}/coverage").status_code == 404
    assert clients["platform_admin"].get(P + f"/registers/{rid}/coverage").status_code == 404
    assert admin(clients).get(P + f"/registers/{rid}/coverage").status_code == 200


@pytest.mark.parametrize("case", ["parser-proof-removed", "job-failed", "scan-failed", "target-changed", "job-missing-end"])
def test_current_read_rechecks_source_evidence_without_rewriting_history(assured, case):
    clients, db, _ = assured
    rid = registered(clients)
    scan = new_scan(db)
    job = source_job(db, scan)
    saved = done(submit(clients, rid, job), 200)
    before = deepcopy(saved["payload"])
    if case == "parser-proof-removed":
        scan.statistics = {"file_observation_receipts": [{}]}
    elif case == "job-failed":
        job.status = "FAILED"
    elif case == "scan-failed":
        scan.status = "FAILED"
    elif case == "target-changed":
        scan.target_location = "/approved/other"
    elif case == "job-missing-end":
        job.completed_at = None
    db.commit()
    response = report(clients, rid)
    assert response.status_code == 409, response.text
    # The operator summary uses the same coverage path; no old green counts.
    summary = clients["bank_a"].get(P + "/operator-decisions")
    assert summary.status_code == 409, summary.text
    retained = store.latest(db, "a", "coverage_observation", store.subject(rid, "repo-pay"))
    assert retained.payload == before
    assert retained.revision == 1 and retained.payload_sha256 == saved["payload_sha256"]


@pytest.mark.parametrize("statistics", [None, [], "legacy-invalid-statistics", True,
    {"file_observation_receipts": []},
    {"file_observation_receipts": [{"file": f"file-{i}.py", "sha256": "a" * 64,
                                   "parser_completed": True} for i in range(1001)]},
])
def test_missing_malformed_or_unbounded_source_statistics_refuse_cleanly(assured, statistics):
    clients, db, _ = assured
    rid = registered(clients)
    scan = new_scan(db)
    scan.statistics = statistics
    db.commit()
    response = submit(clients, rid, source_job(db, scan))
    assert response.status_code == 409, response.text
    assert db.query(AssuranceRevision).filter_by(kind="coverage_observation").count() == 0


def test_source_current_proof_queries_are_batched_not_per_target(assured):
    from sqlalchemy import event

    clients, db, _ = assured
    targets = [{**manifest()["targets"][0], "target_id": f"repo-{i}",
                "target_ref": f"/approved/repo-{i}"} for i in range(10)]
    rid = done(clients["bank_a"].post(P + "/registers", json=manifest(targets=targets)))["subject_id"]
    for target in targets:
        job = source_job(db, new_scan(db, path=target["target_ref"]))
        done(clients["bank_a"].put(P + f"/registers/{rid}/observations/{target['target_id']}", json={
            "expected_revision": 0, "outcome": "RECEIPT", "job_id": job.id,
            "evidence_ref": "synthetic/batched-source", "reason": "Bounded proof lookup",
        }), 200)
    queries = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        normalized = " ".join(statement.lower().split())
        if normalized.startswith("select") and ("from scan_jobs " in normalized or "from scans " in normalized):
            queries.append(normalized)

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        result = done(report(clients, rid), 200)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert result["counts"]["OBSERVED"] == result["registered_targets"] == 10
    assert len(queries) == 2, queries
