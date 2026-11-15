"""Durable binary scan job queue — the restart-safe artifact handoff.

These tests are the restart/replica proof the readiness gate names: jobs
survive a queue-object replacement (restart), two queue instances over one
database (replicas) produce exactly one claim winner, expired leases are
requeued with counted attempts, exhausted retries are dead-lettered, and a
foreign tenant's job is indistinguishable from a missing one.
"""

from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2].parent /
                       "binary_intelligence"))
from tests.fixtures import elf_crypto_sample  # noqa: E402
from fastapi import FastAPI
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient


@pytest.fixture()
def db(tmp_path):
    from db.models.base import Base
    from db.models.binary_artifact_blob import BinaryArtifactBlob
    from db.models.binary_scan_job import BinaryScanJob

    engine = create_engine(f"sqlite:///{tmp_path / 'jobs.db'}")
    Base.metadata.create_all(engine, tables=[BinaryScanJob.__table__,
                                            BinaryArtifactBlob.__table__])
    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _queue(**overrides):
    from binary_intelligence.durable_queue import DurableScanJobQueue
    from binary_intelligence.orchestrator import WorkerLimits

    limits = overrides.pop("limits", WorkerLimits(max_queue_depth=8,
                                                  max_seconds_per_job=60))
    return DurableScanJobQueue(limits=limits, **overrides)


def _job(job_id="bjob-1", tenant="tenant_001", data=b"\x7fELFfake"):
    from binary_intelligence.orchestrator import ScanJob

    return ScanJob(job_id=job_id, tenant_id=tenant, data=data,
                   original_filename="payments-engine", source_type="upload",
                   uploaded_by="tester")


def _row(db, job_id):
    from db.models.binary_scan_job import BinaryScanJob

    return db.scalar(select(BinaryScanJob)
                     .where(BinaryScanJob.job_id == job_id))


class TestHandoff:

    def test_submit_persists_the_artifact_handoff(self, db, monkeypatch):
        import base64

        from sqlalchemy import select

        from db import encryption
        from db.models.binary_artifact_blob import BinaryArtifactBlob

        monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS",
                           "test:" + base64.b64encode(bytes(range(32))).decode())
        encryption.reset_ring()
        queue = _queue()
        accepted, reason = queue.submit(_job(data=b"artifact-bytes"), db=db)
        assert accepted and reason == "queued"
        row = _row(db, "bjob-1")
        assert row is not None and row.status == "QUEUED"
        assert row.artifact_sha256 == hashlib.sha256(b"artifact-bytes").hexdigest()
        assert row.tenant_id == "tenant_001"
        # The handoff is the blob store: bytes live ONCE per (tenant, sha256),
        # encrypted; the job row references the content and stores no copy.
        blob = db.scalar(select(BinaryArtifactBlob).where(
            BinaryArtifactBlob.tenant_id == "tenant_001",
            BinaryArtifactBlob.sha256 == row.artifact_sha256))
        assert blob is not None and blob.bytes_size == len(b"artifact-bytes")
        assert bytes(blob.ciphertext) != b"artifact-bytes", (
            "with keys configured the blob is ciphertext at rest")
        monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS")
        encryption.reset_ring()

    def test_identical_content_is_stored_once_and_referenced_twice(self, db):
        from sqlalchemy import func, select

        from db.models.binary_artifact_blob import BinaryArtifactBlob

        queue = _queue()
        for job_id in ("bjob-1", "bjob-2"):
            accepted, _ = queue.submit(
                _job(job_id=job_id, data=b"same-bytes"), db=db)
            assert accepted
        blob = db.scalar(select(BinaryArtifactBlob).where(
            BinaryArtifactBlob.tenant_id == "tenant_001"))
        assert blob.ref_count == 2, "resubmission references, never copies"
        assert db.scalar(select(func.count()).select_from(
            BinaryArtifactBlob)) == 1
        # Both jobs still execute against the shared content.
        summary = queue.process_job("bjob-2", tenant_id="tenant_001", db=db)
        assert summary is not None and summary["status"] == "completed"

    def test_dedup_is_never_a_cross_tenant_side_channel(self, db):
        from sqlalchemy import func, select

        from db.models.binary_artifact_blob import BinaryArtifactBlob

        queue = _queue()
        queue.submit(_job(job_id="bjob-1", tenant="tenant_001",
                          data=b"same-bytes"), db=db)
        queue.submit(_job(job_id="bjob-2", tenant="tenant_002",
                          data=b"same-bytes"), db=db)
        assert db.scalar(select(func.count()).select_from(
            BinaryArtifactBlob)) == 2, (
            "two tenants uploading the same file store two blobs: "
            "'which other bank has this file?' must be unanswerable")

    def test_a_job_survives_restart(self, db):
        queue_a = _queue()
        queue_a.submit(_job(data=elf_crypto_sample()), db=db)
        # A restart is a fresh queue object over the same database.
        queue_b = _queue()
        assert queue_b.as_dict(db)["pending"] == 1
        summary = queue_b.process_job("bjob-1", tenant_id="tenant_001", db=db)
        assert summary is not None and summary["status"] == "completed"
        row = _row(db, "bjob-1")
        assert row.status == "SUCCEEDED"
        assert row.result["status"] == "completed"
        # Durable totals are derived from the table, not process memory.
        body = queue_b.as_dict(db)
        assert body["accepted_total"] == 1
        assert body["processed_total"] == 1

    def test_backpressure_refuses_and_counts(self, db):
        from binary_intelligence.orchestrator import WorkerLimits

        queue = _queue(limits=WorkerLimits(max_queue_depth=2,
                                          max_seconds_per_job=60))
        for i in range(2):
            accepted, _ = queue.submit(_job(job_id=f"bjob-{i}"), db=db)
            assert accepted
        accepted, reason = queue.submit(_job(job_id="bjob-2"), db=db)
        assert not accepted and "backpressure" in reason
        assert queue.refused_count == 1
        assert _row(db, "bjob-2") is None  # never silently stored half-way

    def test_oversized_artifacts_are_refused(self, db):
        from binary_intelligence.orchestrator import WorkerLimits

        queue = _queue(limits=WorkerLimits(max_artifact_bytes=4,
                                          max_seconds_per_job=60))
        accepted, reason = queue.submit(_job(data=b"12345"), db=db)
        assert not accepted and "above the worker" in reason


class TestClaims:

    def test_two_replicas_claim_exactly_once(self, db):
        replica_a, replica_b = _queue(), _queue()
        replica_a.submit(_job(), db=db)
        first = replica_a.claim(db, "worker-a", tenant_id="tenant_001")
        second = replica_b.claim(db, "worker-b", tenant_id="tenant_001")
        assert first is not None and first.claimed_by == "worker-a"
        assert second is None  # one winner, exactly once

    def test_foreign_jobs_are_indistinguishable_from_missing(self, db):
        queue = _queue()
        queue.submit(_job(tenant="tenant_001"), db=db)
        assert queue.process_job("bjob-1", tenant_id="tenant_002", db=db) is None
        assert queue.claim(db, "worker", tenant_id="tenant_002") is None
        row = _row(db, "bjob-1")
        assert row.status == "QUEUED"  # never consumed, never executed

    def test_expired_leases_requeue_with_an_attempt(self, db):
        queue = _queue(lease_seconds=-1.0)
        queue.submit(_job(), db=db)
        claimed = queue.claim(db, "dying-worker", tenant_id="tenant_001")
        assert claimed is not None
        recovered = queue.recover_expired_leases(db)
        assert recovered == 1
        row = _row(db, "bjob-1")
        assert row.status == "QUEUED"
        assert row.attempts == 1
        assert row.claimed_by is None and row.lease_expires_at is None

    def test_a_stale_verdict_cannot_overwrite_the_result(self, db):
        queue = _queue()
        queue.submit(_job(), db=db)
        queue.claim(db, "worker-a", tenant_id="tenant_001")
        queue.fail(db, "bjob-1", "boom", tenant_id="tenant_001")
        # The worker was requeued; a late completion from the old claim is a
        # compare-and-set miss and must not fabricate a success.
        assert queue.complete(db, "bjob-1", {"status": "completed"},
                              tenant_id="tenant_001") is False
        row = _row(db, "bjob-1")
        assert row.status == "QUEUED" and row.error == "boom"


class TestRetriesAndDeadLetters:

    def test_retries_exhaust_to_dead_letters(self, db):
        queue = _queue(max_attempts=2)
        queue.submit(_job(), db=db)
        for expected_attempts in (1, 2):
            claimed = queue.claim(db, "worker", tenant_id="tenant_001")
            assert claimed is not None
            status = queue.fail(db, "bjob-1", f"attempt {expected_attempts}",
                                tenant_id="tenant_001")
            if expected_attempts < 2:
                assert status == "QUEUED"
            else:
                assert status == "DEAD"
        row = _row(db, "bjob-1")
        assert row.status == "DEAD" and row.attempts == 2
        assert "attempt 2" in row.error
        assert queue.claim(db, "worker", tenant_id="tenant_001") is None
        assert queue.as_dict(db)["failed_total"] == 1

    def test_the_dead_letter_is_visible_never_silent(self, db):
        queue = _queue(max_attempts=1)
        queue.submit(_job(), db=db)
        queue.claim(db, "worker", tenant_id="tenant_001")
        queue.fail(db, "bjob-1", "fatal", tenant_id="tenant_001")
        row = _row(db, "bjob-1")
        assert row.status == "DEAD"
        # A dead row still holds its identity for operators to inspect.
        assert row.tenant_id == "tenant_001"
        assert row.original_filename == "payments-engine"


class TestIntrospection:

    def test_as_dict_declares_durability_honestly(self, db):
        queue = _queue()
        queue.submit(_job(), db=db)
        body = queue.as_dict(db)
        assert body["durable"] is True
        assert body["backend"] == "database_leased_jobs"
        assert body["pending"] == 1
        assert "never silently dropped" in body["note"]
        assert "lease" in body["note"]
        assert "dead-lettered" in body["note"]

    def test_submit_without_a_session_refuses_instead_of_lying(self):
        queue = _queue()
        with pytest.raises(ValueError, match="database session"):
            queue.submit(_job())


@pytest.fixture()
def api():
    from db.models.base import Base
    from db.models.binary_scan_job import BinaryScanJob
    from db.models.binary_artifact_blob import BinaryArtifactBlob
    from db.models.binary_scan import BinaryScanObservation, BinaryScanRecord
    from db.models.binary_intelligence import (
        BinaryAnalysisCoverage, BinaryArtifact, BinaryCryptoFinding,
        BinaryEvidence, BinaryScanRun, BinaryTwinEdge,
    )
    from db.models.performance import PerformanceMetric
    from db.models.cryptolog import CryptoLogEvent

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        BinaryArtifact.__table__, BinaryScanRun.__table__,
        BinaryCryptoFinding.__table__, BinaryEvidence.__table__,
        BinaryAnalysisCoverage.__table__, BinaryTwinEdge.__table__,
        BinaryScanJob.__table__, BinaryArtifactBlob.__table__,
        BinaryScanRecord.__table__,
        BinaryScanObservation.__table__,
        PerformanceMetric.__table__, CryptoLogEvent.__table__])
    session = sessionmaker(bind=engine)()

    from api import dependencies
    from api.routers import binary_intelligence
    from api.errors import install_error_contract

    app = FastAPI()
    app.include_router(binary_intelligence.router, prefix="/api/v1")
    install_error_contract(app)
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    app.dependency_overrides[dependencies.require_intelligence_writer] = lambda: "writer"
    original = binary_intelligence.WORKER_QUEUE
    binary_intelligence.configure_durable_queue()
    try:
        with TestClient(app) as client:
            yield client, session, binary_intelligence
    finally:
        binary_intelligence.WORKER_QUEUE = original


class TestRouterIntegration:

    def test_production_endpoints_accept_the_durable_backend(self, api, monkeypatch):
        client, _session, binary = api
        from types import SimpleNamespace

        monkeypatch.setattr(binary, "get_settings",
                            lambda: SimpleNamespace(is_production=True))
        sample = elf_crypto_sample()
        accepted = client.post("/api/v1/binary/scan/async", json={
            "tenant_id": "tenant_001",
            "artifact_base64": base64.b64encode(sample).decode(),
            "original_filename": "payments-engine",
            "source_type": "upload", "scan_profile": "standard"})
        assert accepted.status_code == 202, accepted.text
        body = accepted.json()
        assert body["queue"]["durable"] is True
        assert body["queue"]["backend"] == "database_leased_jobs"

        done = client.post(f"/api/v1/binary/scan/jobs/{body['job_id']}/process")
        assert done.status_code == 201, done.text
        # Exactly once: a second attempt finds nothing to claim.
        again = client.post(f"/api/v1/binary/scan/jobs/{body['job_id']}/process")
        assert again.status_code == 404

    def test_the_declared_backend_survives_status_introspection(self, api):
        client, _session, binary = api
        status = client.get("/api/v1/binary/worker/status")
        assert status.status_code == 200
        queue = status.json()["queue"]
        assert queue["durable"] is True
        assert queue["accepted_total"] == 0


class TestTraceContinuity:

    def test_the_submitting_trace_rides_the_job_row(self, db):
        from binary_intelligence.orchestrator import ScanJob
        from worker.pipeline.pipeline_runner import trace_id_from_job

        queue = _queue()
        accepted, _ = queue.submit(ScanJob(
            job_id="bjob-tr", tenant_id="tenant_001", data=b"trace-bytes",
            original_filename="f", source_type="upload", uploaded_by="tester",
            trace_id="4bf92f3577b34da6a3ce929d0e0e4736"), db=db)
        assert accepted
        row = _row(db, "bjob-tr")
        # The job outlives its HTTP request: the identity rides the row and
        # survives a queue replacement (restart) — the worker reads it back.
        assert row.trace_id == "4bf92f3577b34da6a3ce929d0e0e4736"
        assert trace_id_from_job(row) == "4bf92f3577b34da6a3ce929d0e0e4736"

    def test_the_trace_reader_covers_both_job_families(self):
        from types import SimpleNamespace

        from worker.pipeline.pipeline_runner import trace_id_from_job

        assert trace_id_from_job(SimpleNamespace(
            progress={"trace_id": "from-progress"},
            raw={"trace_id": "from-raw"}, trace_id="from-column")) == "from-progress"
        assert trace_id_from_job(SimpleNamespace(
            progress=None, raw={"trace_id": "from-raw"},
            trace_id="from-column")) == "from-raw"
        assert trace_id_from_job(SimpleNamespace(
            progress=None, raw=None, trace_id="from-column")) == "from-column"
        assert trace_id_from_job(SimpleNamespace(
            progress=None, raw=None, trace_id=None)) is None


class TestBackpressureContract:

    def test_a_full_queue_answers_429_with_retry_after_and_depth_headers(self, api):
        client, _session, binary = api
        binary.WORKER_QUEUE.limits.max_queue_depth = 1
        payload = {
            "tenant_id": "tenant_001",
            "artifact_base64": base64.b64encode(b"first").decode(),
            "original_filename": "a", "source_type": "upload",
            "scan_profile": "standard"}
        first = client.post("/api/v1/binary/scan/async", json=payload)
        assert first.status_code == 202
        assert first.headers["X-Queue-Depth"] == "1"
        assert first.headers["X-Queue-Limit"] == "1"

        payload["artifact_base64"] = base64.b64encode(b"second").decode()
        refused = client.post("/api/v1/binary/scan/async", json=payload)
        assert refused.status_code == 429
        assert refused.headers["Retry-After"] == "30", (
            "a backpressure refusal tells the caller when to come back")
        assert refused.headers["X-Queue-Depth"] == "1"
        assert refused.headers["X-Queue-Limit"] == "1"
        assert "backpressure" in refused.json()["detail"]

    def test_an_oversized_artifact_answers_413_not_a_queue_refusal(self, api):
        client, _session, binary = api
        binary.WORKER_QUEUE.limits.max_artifact_bytes = 4
        refused = client.post("/api/v1/binary/scan/async", json={
            "tenant_id": "tenant_001",
            "artifact_base64": base64.b64encode(b"too-large").decode(),
            "original_filename": "a", "source_type": "upload",
            "scan_profile": "standard"})
        assert refused.status_code == 413
        assert refused.headers["X-Queue-Depth"] == "0"
        assert "above the worker limit" in refused.json()["detail"]

    def test_the_submission_stamps_the_request_trace_onto_the_job_row(self, api):
        client, session, _binary = api
        accepted = client.post("/api/v1/binary/scan/async",
                               headers={"X-Request-ID": "trace-abc-123"},
                               json={
                                   "tenant_id": "tenant_001",
                                   "artifact_base64": base64.b64encode(b"traced").decode(),
                                   "original_filename": "a", "source_type": "upload",
                                   "scan_profile": "standard"})
        assert accepted.status_code == 202
        job_id = accepted.json()["job_id"]
        from db.models.binary_scan_job import BinaryScanJob

        row = session.scalar(select(BinaryScanJob)
                             .where(BinaryScanJob.job_id == job_id))
        assert row.trace_id == "trace-abc-123", (
            "the scan keeps the submitting request's identity after the "
            "HTTP request is gone")


class TestInvestigationSurface:

    def _dead(self, db, job_id="bjob-dead", tenant="tenant_001"):
        queue = _queue(max_attempts=1)
        queue.submit(_job(job_id=job_id, tenant=tenant), db=db)
        queue.claim(db, "worker", tenant_id=tenant)
        queue.fail(db, job_id, "fatal boom", tenant_id=tenant)
        return queue

    def test_the_dead_letter_is_listable_and_inspectable(self, db):
        queue = self._dead(db)
        dead = queue.list_jobs(db, status="DEAD")
        assert [j["job_id"] for j in dead] == ["bjob-dead"]
        record = queue.get_job(db, "bjob-dead")
        assert record["status"] == "DEAD" and record["attempts"] == 1
        assert record["error"] == "fatal boom"
        assert queue.list_jobs(db, status="QUEUED") == []

    def test_investigation_reads_are_tenant_scoped(self, db):
        queue = self._dead(db)
        assert queue.get_job(db, "bjob-dead", tenant_id="tenant_001") is not None
        assert queue.get_job(db, "bjob-dead", tenant_id="tenant_002") is None
        assert queue.list_jobs(db, tenant_id="tenant_002") == []
        assert len(queue.list_jobs(db, tenant_id="tenant_001")) == 1

    def test_replay_requeues_only_dead_letters(self, db):
        queue = self._dead(db)
        ok, reason = queue.replay_dead(db, "bjob-dead", tenant_id="tenant_001")
        assert ok and reason == "requeued"
        record = queue.get_job(db, "bjob-dead")
        assert record["status"] == "QUEUED" and record["attempts"] == 0
        assert record["error"] is None
        claimed = queue.claim(db, "worker", tenant_id="tenant_001")
        assert claimed is not None
        assert queue.complete(db, "bjob-dead", {"scan_id": "s1"},
                              tenant_id="tenant_001")
        ok, reason = queue.replay_dead(db, "bjob-dead", tenant_id="tenant_001")
        assert not ok and "not a dead letter" in reason

    def test_replay_of_missing_or_foreign_jobs_is_refused(self, db):
        queue = self._dead(db)
        assert queue.replay_dead(db, "bjob-nope") == (False, "job not found")
        assert queue.replay_dead(db, "bjob-dead",
                                 tenant_id="tenant_002") == (False, "job not found")

    def test_listing_is_bounded(self, db):
        queue = _queue()
        for i in range(5):
            queue.submit(_job(job_id=f"bjob-{i}"), db=db)
        assert len(queue.list_jobs(db, limit=2)) == 2
        assert len(queue.list_jobs(db, limit=1000)) == 5


class TestInvestigationAPI:

    def _make_dead(self, client, session, binary):
        binary.WORKER_QUEUE.max_attempts = 1
        accepted = client.post("/api/v1/binary/scan/async", json={
            "tenant_id": "tenant_001",
            "artifact_base64": base64.b64encode(b"dead-bytes").decode(),
            "original_filename": "a", "source_type": "upload",
            "scan_profile": "standard"})
        assert accepted.status_code == 202, accepted.text
        job_id = accepted.json()["job_id"]
        assert binary.WORKER_QUEUE.claim(session, "worker",
                                         tenant_id="tenant_001") is not None
        binary.WORKER_QUEUE.fail(session, job_id, "fatal boom",
                                 tenant_id="tenant_001")
        return job_id

    def test_dead_jobs_are_listed_and_inspectable_over_http(self, api):
        client, session, binary = api
        job_id = self._make_dead(client, session, binary)
        listing = client.get("/api/v1/binary/scan/jobs",
                             params={"status": "DEAD"})
        assert listing.status_code == 200
        body = listing.json()
        assert body["count"] == 1 and body["jobs"][0]["job_id"] == job_id
        assert body["jobs"][0]["error"] == "fatal boom"
        detail = client.get(f"/api/v1/binary/scan/jobs/{job_id}")
        assert detail.status_code == 200
        assert detail.json()["status"] == "DEAD"

    def test_replay_requeues_the_dead_letter_over_http(self, api):
        client, session, binary = api
        job_id = self._make_dead(client, session, binary)
        replay = client.post(f"/api/v1/binary/scan/jobs/{job_id}/replay")
        assert replay.status_code == 200, replay.text
        assert replay.json() == {"job_id": job_id, "requeued": True,
                                "reason": "requeued"}
        detail = client.get(f"/api/v1/binary/scan/jobs/{job_id}")
        assert detail.json()["status"] == "QUEUED"
        # A live job is never replayed underneath its worker.
        again = client.post(f"/api/v1/binary/scan/jobs/{job_id}/replay")
        assert again.status_code == 409
        assert "not a dead letter" in again.json()["detail"]

    def test_unknown_jobs_are_indistinguishable_from_missing(self, api):
        client, _session, _binary = api
        assert client.get("/api/v1/binary/scan/jobs/bjob-nope").status_code == 404
        assert client.post(
            "/api/v1/binary/scan/jobs/bjob-nope/replay").status_code == 404
