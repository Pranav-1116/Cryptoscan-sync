"""Fault isolation — the HSM-collector scenario, pinned as a contract.

A bank's HSM collector fails during a scheduled collection. A robust
CryptoScan must: (1) mark the run failed or partially completed,
(2) preserve evidence already collected, (3) record the failure reason,
(4) retry only where the failure is recoverable and retrying is safe,
(5) avoid duplicating previously stored observations, (6) keep unrelated
collectors running, (7) report incomplete coverage instead of pretending
the scan succeeded. Each test below is one of those seven points.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from db.connection.session import Base

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def queue(db):
    from binary_intelligence.durable_queue import DurableScanJobQueue

    q = DurableScanJobQueue()
    return q


def _submit(queue, db, job_id: str):
    from binary_intelligence.orchestrator import ScanJob

    accepted, reason = queue.submit(ScanJob(
        job_id=job_id, tenant_id="t1", data=b"\x7fELF fake",
        original_filename=f"{job_id}.bin", source_type="upload",
        uploaded_by="aud"), db=db)
    assert accepted, reason
    return job_id


# (1) mark the collector run as failed or partially completed — never hidden
def test_1_a_failed_run_is_marked_never_left_in_flight(db, queue):
    _submit(queue, db, "job-1")
    claimed = queue.claim(db, worker_id="w1", tenant_id="t1")
    assert claimed is not None and claimed.status == "CLAIMED"
    status = queue.fail(db, "job-1", error="HSM collector: connection reset")
    assert status in ("QUEUED", "DEAD")   # marked as failed-with-outcome
    visible = queue.as_dict(db)
    assert visible["pending"] == (1 if status == "QUEUED" else 0)


# (2) preserve evidence already collected
def test_2_evidence_already_collected_survives_the_failure(db, queue):
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan

    db.add(Scan(id="scan-1", status="COMPLETED", target_location="hsm://slot-1",
                target_type="HOST_SNAPSHOT_IMPORT", operator="t", scan_start=NOW))
    db.add(EvidenceRecord(id="ev-1", scan_id="scan-1", content_hash="a" * 64,
                          chain_hash="b" * 64, chain_position=0,
                          algorithm="RSA", file_path="hsm://slot-1", line_number=0,
                          finding_data={"algorithm": "RSA", "key_size": 2048}))
    db.commit()
    # the run's failure afterwards must not take earlier evidence with it
    scan = db.get(Scan, "scan-1")
    scan.status = "FAILED"
    scan.error_message = "collector died mid-run"
    db.commit()
    rows = db.scalars(select(EvidenceRecord).where(
        EvidenceRecord.scan_id == "scan-1")).all()
    assert [r.id for r in rows] == ["ev-1"], "failure must never delete collected evidence"


# (3) record the failure reason
def test_3_the_failure_reason_is_recorded(db, queue):
    _submit(queue, db, "job-3")
    queue.claim(db, worker_id="w1", tenant_id="t1")
    queue.fail(db, "job-3", error="HSM collector: pkcs11 session refused")
    from db.models.binary_scan_job import BinaryScanJob

    row = db.scalar(select(BinaryScanJob).where(BinaryScanJob.job_id == "job-3"))
    assert "pkcs11 session refused" in (row.error or ""), "the reason must survive"


# (4) retry only where the failure is recoverable and retrying is safe
def test_4_only_named_transient_failures_are_retried():
    from worker.core.retry_policy import (
        DEAD_LETTER,
        NEVER,
        RETRY,
        decide,
    )

    transient = decide(exc=ConnectionResetError("hsm dropped"))
    assert transient.action == RETRY
    assert "transient" in transient.reason.lower()

    permanent = decide(exc=ValueError("malformed pkcs11 payload"))
    assert permanent.action == DEAD_LETTER, "a retry would fail identically"

    unknown = decide(exc=RuntimeError("???"))
    assert unknown.action == DEAD_LETTER, "unknown failures are terminal by default"

    controlled = decide(exc=TimeoutError("slow"), controlled=True)
    assert controlled.action == NEVER, (
        "a job under controlled execution is never auto-retried — the "
        "failed attempt may have spent part of an approved action")


# (5) avoid duplicating previously stored observations
def test_5_a_stale_verdict_loses_quietly_no_duplicates(db, queue):
    _submit(queue, db, "job-5")
    queue.claim(db, worker_id="w1", tenant_id="t1")
    assert queue.complete(db, "job-5", summary={"findings": 3}, tenant_id="t1") is True
    # a duplicate completion (late retry, double delivery) must be refused
    assert queue.complete(db, "job-5", summary={"findings": 3}, tenant_id="t1") is False
    from db.models.binary_scan_job import BinaryScanJob

    rows = db.scalars(select(BinaryScanJob).where(
        BinaryScanJob.job_id == "job-5")).all()
    assert len(rows) == 1 and rows[0].status == "SUCCEEDED"
    assert rows[0].result == {"findings": 3}, "the first verdict stands"


# (6) keep unrelated collectors running
def test_6_one_dead_collector_does_not_stop_the_others(db, queue):
    _submit(queue, db, "job-hsm")
    _submit(queue, db, "job-net")
    first = queue.claim(db, worker_id="w1", tenant_id="t1")
    # one collector fails terminally (a retry cannot fix it)...
    assert queue.fail(db, first.job_id, error="terminal: pkcs11 permission denied",
                      error_kind="TERMINAL") == "DEAD"
    # ...the other collector keeps running to completion
    second = queue.claim(db, worker_id="w2", tenant_id="t1")
    assert second is not None, "one collector's death must not stop the queue"
    assert second.job_id != first.job_id
    assert queue.complete(db, second.job_id, summary={"ok": True}, tenant_id="t1")
    from db.models.binary_scan_job import BinaryScanJob

    statuses = {r.job_id: r.status for r in db.scalars(
        select(BinaryScanJob)).all()}
    assert set(statuses.values()) == {"DEAD", "SUCCEEDED"}, statuses


# (7) report incomplete coverage instead of pretending the scan succeeded
def test_7_incomplete_coverage_is_reported_not_hidden():
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]
    discovery = (root / "services" / "api" / "api" / "estate_discovery.py").read_text()
    # the pipeline's verdict is PARTIAL the moment any requested plane is
    # FAILED, PARTIAL or NOT_ATTEMPTED — never a green COMPLETE
    assert '"verdict": "PARTIAL_COVERAGE" if unanswered else "COMPLETE"' in discovery
    for key in ("failed_planes", "partial_planes", "coverage_gaps", "not_attempted_planes"):
        assert f'"{key}"' in discovery
    # and the schedule surface cannot clear it: an error or incomplete
    # coverage keeps the estate DEGRADED even when the daemon is healthy
    graph = (root / "services" / "api" / "api" / "routers" / "estate_graph.py").read_text()
    assert '"ERROR", "PARTIAL_COVERAGE"' in graph
    assert "a live daemon cannot clear that result" in graph
