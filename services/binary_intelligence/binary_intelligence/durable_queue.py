"""Durable, database-backed binary scan job queue.

This is the production async backend the API's async endpoints have been
waiting for: a job row carries the bounded artifact bytes, so an acknowledged
submission survives an API restart and any replica's worker can claim it.

Reliability model
-----------------
* **Handoff** — ``submit`` writes the artifact bytes into ``binary_scan_jobs``
  inside the caller's transaction.  A ``202`` is only ever answered for a row
  the database now holds.
* **Claims** — ``claim`` (and ``process_job``/``process_one``) take the job
  under an optimistic ``version`` compare-and-set: two replicas claiming the
  same job produce exactly one winner.  A claim is a *lease*
  (``claimed_by`` + ``lease_expires_at``), not a transfer of ownership.
* **Lease recovery** — ``recover_expired_leases`` requeues jobs whose worker
  died mid-scan (lease past, still CLAIMED), incrementing ``attempts``; after
  ``max_attempts`` the job becomes a terminal ``DEAD`` row — the dead letter.
  Nothing stays QUEUED/CLAIMED forever.
* **Completion** — ``complete``/``fail`` are compare-and-set on the version
  they read, so a stale worker finishing a job the reaper already requeued
  cannot silently overwrite the verdict (the ``scan_jobs.version`` discipline).
* **Backpressure** — bounded by ``max_queue_depth`` across QUEUED+CLAIMED:
  the offer is refused and COUNTED, never silently dropped.

Honest boundaries
-----------------
* Artifact bytes live in this database row (bounded by the worker's declared
  ``max_artifact_bytes``); encryption at rest is the database's job (TDE,
  pgcrypto, or an encrypted volume) — this module never claims otherwise.
* ``refused_total`` is a process-local counter: a refusal writes no row by
  design.  Durable totals (accepted/processed/failed) are derived from the
  table when a session is available and survive restart.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Dict, Optional, Tuple

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from binary_intelligence.orchestrator import ScanJob, WorkerLimits
from binary_intelligence.pipeline import ScanResult, run_scan
from db.encryption import encryption_status, protect, unprotect
from db.models.base import utcnow
from db.models.binary_artifact_blob import BinaryArtifactBlob
from db.models.binary_scan_job import BinaryScanJob

DEFAULT_LEASE_SECONDS = 300.0


@dataclass
class DurableScanJobQueue:
    """The durable twin of ``ScanJobQueue``: same call sites, durable state."""

    limits: WorkerLimits = field(default_factory=WorkerLimits)
    lease_seconds: float = DEFAULT_LEASE_SECONDS
    #: Total tries per job (the first run included). Exhaustion dead-letters.
    max_attempts: int = 3
    _refused: int = 0
    _accepted: int = 0
    _processed: int = 0
    _failed: int = 0

    # -- interface parity with ScanJobQueue ------------------------------
    @property
    def pending(self) -> int:
        # Without a session the durable depth is unknowable; report None via
        # as_dict and keep this property for the process-local call sites.
        return -1

    @property
    def refused_count(self) -> int:
        return self._refused

    @property
    def accepted_count(self) -> int:
        return self._accepted

    @property
    def processed_count(self) -> int:
        return self._processed

    @property
    def failed_count(self) -> int:
        return self._failed

    def submit(self, job: ScanJob, db: Optional[Session] = None) -> Tuple[bool, str]:
        """Offer one job. False + reason under backpressure. The row is the
        handoff: accepted means the database now holds the artifact."""
        if db is None:
            raise ValueError(
                "the durable queue needs a database session — accepting a job "
                "it cannot hand off is exactly the dishonesty this backend exists "
                "to remove")
        if len(job.data) > self.limits.max_artifact_bytes:
            self._refused += 1
            return False, (
                f"artifact is {len(job.data)} bytes, above the worker "
                f"limit {self.limits.max_artifact_bytes} — refused (§14)")
        depth = self._depth(db)
        if depth >= self.limits.max_queue_depth:
            self._refused += 1
            return False, (
                f"queue is full at {self.limits.max_queue_depth} — "
                "backpressure refuses and counts, it never silently "
                "drops a job")
        now = utcnow()
        # Deduplication: the bytes live ONCE per (tenant, sha256) in the
        # content-addressed blob store — envelope-encrypted, tenant-bound
        # ciphertext. The job row references the content by its plaintext
        # hash and stores no copy; resubmitting an artifact grows
        # ref_count, never storage. Two tenants uploading the same file
        # store two blobs: dedup never becomes a cross-tenant side channel.
        sha256 = hashlib.sha256(job.data).hexdigest()
        self._refer_blob(db, tenant_id=job.tenant_id, sha256=sha256,
                         data=job.data, now=now)
        db.add(BinaryScanJob(
            tenant_id=job.tenant_id, job_id=job.job_id,
            status="QUEUED", artifact_bytes=b"",
            artifact_sha256=sha256,
            original_filename=job.original_filename,
            source_type=job.source_type,
            source_location=job.source_location,
            uploaded_by=job.uploaded_by, profile=job.profile,
            trace_id=job.trace_id,
            version=0, attempts=0,
            max_attempts=int(self.max_attempts),
            created_at=now, updated_at=now))
        db.commit()
        self._accepted += 1
        return True, "queued"

    def process_job(self, job_id: str,
                    on_result: Optional[Callable[[ScanResult], Any]] = None,
                    tenant_id: Optional[str] = None,
                    db: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        """Claim and run one named job. A foreign id is indistinguishable
        from a missing one and is never consumed or run. None is reserved for
        an explicitly unscoped platform worker/operator."""
        if db is None:
            raise ValueError("the durable queue needs a database session")
        row = self._visible(db, job_id, tenant_id)
        if row is None or not self._claim(db, row):
            return None
        return self._execute(db, row, on_result=on_result)

    def process_one(self, on_result: Optional[Callable[[ScanResult], Any]] = None,
                    db: Optional[Session] = None) -> Optional[Dict[str, Any]]:
        """Claim and run the oldest runnable job. None when nothing is
        runnable — an empty durable queue is not an error."""
        if db is None:
            raise ValueError("the durable queue needs a database session")
        candidates = db.scalars(
            select(BinaryScanJob)
            .where(BinaryScanJob.status == "QUEUED")
            .order_by(BinaryScanJob.created_at, BinaryScanJob.id)
            .limit(8)).all()
        for row in candidates:
            if self._claim(db, row):
                return self._execute(db, row, on_result=on_result)
        return None

    # -- cross-replica worker path --------------------------------------
    def claim(self, db: Session, worker_id: str,
              tenant_id: Optional[str] = None) -> Optional[BinaryScanJob]:
        """Lease one QUEUED job for a named worker. Two replicas calling
        claim concurrently produce exactly one winner (version CAS)."""
        candidates = db.scalars(
            select(BinaryScanJob)
            .where(BinaryScanJob.status == "QUEUED")
            .order_by(BinaryScanJob.created_at, BinaryScanJob.id)
            .limit(8)).all()
        for row in candidates:
            if tenant_id is not None and row.tenant_id != tenant_id:
                continue
            if self._claim(db, row, worker_id=worker_id):
                return self._visible(db, row.job_id, tenant_id)
        return None

    def complete(self, db: Session, job_id: str, summary: Dict[str, Any],
                 tenant_id: Optional[str] = None) -> bool:
        """Record success. Compare-and-set: a stale verdict loses quietly."""
        return self._finish(db, job_id, tenant_id,
                            status="SUCCEEDED", result=summary, error=None)

    def fail(self, db: Session, job_id: str, error: str,
             tenant_id: Optional[str] = None) -> Optional[str]:
        """Record one failure. Returns the resulting status: QUEUED when a
        retry remains, DEAD when ``max_attempts`` is exhausted — the dead
        letter, visible for operators, never a silent disappearance."""
        row = self._visible(db, job_id, tenant_id)
        if row is None:
            return None
        attempts = row.attempts + 1
        terminal = "DEAD" if attempts >= row.max_attempts else "QUEUED"
        ok = self._finish(db, job_id, tenant_id,
                          status=terminal, result=None, error=error,
                          extra={"attempts": attempts,
                                 "claimed_by": None, "lease_expires_at": None})
        return terminal if ok else None

    def recover_expired_leases(self, db: Session) -> int:
        """Requeue jobs whose worker died mid-scan (lease expired while
        CLAIMED). Attempts are counted; exhaustion becomes DEAD. Returns the
        number of rows touched. This is the reaper: nothing stays CLAIMED
        forever."""
        now = utcnow()
        rows = db.scalars(
            select(BinaryScanJob)
            .where(BinaryScanJob.status == "CLAIMED",
                   BinaryScanJob.lease_expires_at.is_not(None),
                   BinaryScanJob.lease_expires_at < now)).all()
        recovered = 0
        for row in rows:
            attempts = row.attempts + 1
            status = "DEAD" if attempts >= row.max_attempts else "QUEUED"
            result = db.execute(
                update(BinaryScanJob)
                .where(BinaryScanJob.id == row.id,
                       BinaryScanJob.version == row.version,
                       BinaryScanJob.status == "CLAIMED")
                .values(status=status, attempts=attempts,
                        claimed_by=None, lease_expires_at=None,
                        version=row.version + 1, updated_at=now,
                        error="lease expired: worker did not finish; requeued"
                        if status == "QUEUED" else
                        "lease expired repeatedly: dead-lettered after "
                        f"{attempts} attempts"))
        if result.rowcount == 1:
            recovered += 1
        db.commit()
        return recovered

    # -- investigation surface -------------------------------------------
    def list_jobs(self, db: Session, *, tenant_id: Optional[str] = None,
                  status: Optional[str] = None,
                  limit: int = 50) -> list[Dict[str, Any]]:
        """Bounded job listing for investigation — the dead letter is
        READABLE, never just a counter. Ordering: newest first."""
        stmt = select(BinaryScanJob).order_by(BinaryScanJob.created_at.desc())
        if tenant_id is not None:
            stmt = stmt.where(BinaryScanJob.tenant_id == tenant_id)
        if status is not None:
            stmt = stmt.where(BinaryScanJob.status == status)
        rows = db.scalars(stmt.limit(max(1, min(int(limit), 200)))).all()
        return [self._job_summary(row) for row in rows]

    def get_job(self, db: Session, job_id: str,
                tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        row = self._visible(db, job_id, tenant_id)
        return self._job_summary(row) if row is not None else None

    def replay_dead(self, db: Session, job_id: str,
                    tenant_id: Optional[str] = None) -> Tuple[bool, str]:
        """Requeue a dead-lettered job after investigation. Only DEAD rows:
        a live job is never replayed underneath its worker — that is what
        the version CAS is for. The replay is a fresh attempt budget."""
        row = self._visible(db, job_id, tenant_id)
        if row is None:
            return False, "job not found"
        now = utcnow()
        result = db.execute(
            update(BinaryScanJob)
            .where(BinaryScanJob.id == row.id,
                   BinaryScanJob.version == row.version,
                   BinaryScanJob.status == "DEAD")
            .values(status="QUEUED", attempts=0,
                    claimed_by=None, lease_expires_at=None,
                    error=None, version=row.version + 1, updated_at=now))
        db.commit()
        if result.rowcount != 1:
            return False, ("job is not a dead letter (or moved underfoot) "
                           "— replay refused")
        return True, "requeued"

    def _job_summary(self, row: BinaryScanJob) -> Dict[str, Any]:
        def iso(value: Any) -> Optional[str]:
            return value.isoformat() if value is not None else None

        return {
            "job_id": row.job_id,
            "tenant_id": row.tenant_id,
            "status": row.status,
            "attempts": row.attempts,
            "max_attempts": row.max_attempts,
            "original_filename": row.original_filename,
            "source_type": row.source_type,
            "source_location": row.source_location,
            "uploaded_by": row.uploaded_by,
            "profile": row.profile,
            "trace_id": row.trace_id,
            "claimed_by": row.claimed_by,
            "lease_expires_at": iso(row.lease_expires_at),
            "started_at": iso(row.started_at),
            "completed_at": iso(row.completed_at),
            "created_at": iso(row.created_at),
            "updated_at": iso(row.updated_at),
            "error": row.error,
            "result": row.result,
        }

    # -- introspection ---------------------------------------------------
    def _refer_blob(self, db: Session, *, tenant_id: str, sha256: str,
                    data: bytes, now) -> None:
        from sqlalchemy import select as _select

        blob = db.scalar(
            _select(BinaryArtifactBlob)
            .where(BinaryArtifactBlob.tenant_id == tenant_id,
                   BinaryArtifactBlob.sha256 == sha256))
        if blob is None:
            db.add(BinaryArtifactBlob(
                tenant_id=tenant_id, sha256=sha256,
                ciphertext=protect(data, tenant_id=tenant_id),
                bytes_size=len(data), ref_count=1))
        else:
            blob.ref_count += 1
            blob.updated_at = now

    def _resolve_blob(self, db: Session, *, tenant_id: str,
                      sha256: str) -> bytes:
        from sqlalchemy import select as _select

        blob = db.scalar(
            _select(BinaryArtifactBlob)
            .where(BinaryArtifactBlob.tenant_id == tenant_id,
                   BinaryArtifactBlob.sha256 == sha256))
        if blob is None:
            raise ValueError(
                "artifact bytes are not in the blob store for this tenant — "
                "a job whose content is gone is a failure, never a scan of "
                "nothing")
        return unprotect(bytes(blob.ciphertext), tenant_id=tenant_id)

    def as_dict(self, db: Optional[Session] = None) -> Dict[str, Any]:
        counts: Dict[str, Any]
        if db is not None:
            counts = {
                "pending": self._depth(db),
                "accepted_total": db.scalar(
                    select(func.count()).select_from(BinaryScanJob)) or 0,
                "processed_total": db.scalar(
                    select(func.count()).select_from(BinaryScanJob)
                    .where(BinaryScanJob.status == "SUCCEEDED")) or 0,
                "failed_total": db.scalar(
                    select(func.count()).select_from(BinaryScanJob)
                    .where(BinaryScanJob.status.in_(("FAILED", "DEAD")))) or 0,
            }
        else:
            counts = {
                "pending": None,
                "accepted_total": self._accepted,
                "processed_total": self._processed,
                "failed_total": self._failed,
            }
        return {
            **counts,
            "refused_total": self._refused,
            "limits": {
                "max_artifact_bytes": self.limits.max_artifact_bytes,
                "max_seconds_per_job": self.limits.max_seconds_per_job,
                "max_queue_depth": self.limits.max_queue_depth,
            },
            "lease_seconds": self.lease_seconds,
            "max_attempts": self.max_attempts,
            "encryption": encryption_status(),
            "dedup": ({"blobs": db.scalar(
                select(func.count()).select_from(BinaryArtifactBlob)) or 0,
                "references": db.scalar(
                    select(func.coalesce(func.sum(
                        BinaryArtifactBlob.ref_count), 0))) or 0,
                "note": ("content-addressed: bytes stored once per "
                         "(tenant, sha256); jobs reference, never copy")}
                if db is not None else None),
            "backend": "database_leased_jobs",
            "durable": True,
            "note": ("durable database handoff — job rows hold the bounded "
                     "artifact bytes and survive restart; claims are "
                     "cross-replica leases with compare-and-set versioning, "
                     "expired leases are requeued and exhausted retries are "
                     "dead-lettered (counted, never silently dropped)"),
        }

    # -- internals -------------------------------------------------------
    def _depth(self, db: Session) -> int:
        return db.scalar(
            select(func.count()).select_from(BinaryScanJob)
            .where(BinaryScanJob.status.in_(("QUEUED", "CLAIMED")))) or 0

    def _visible(self, db: Session, job_id: str,
                 tenant_id: Optional[str]) -> Optional[BinaryScanJob]:
        row = db.scalar(select(BinaryScanJob)
                        .where(BinaryScanJob.job_id == job_id))
        if row is None:
            return None
        if tenant_id is not None and row.tenant_id != tenant_id:
            return None  # foreign: indistinguishable from missing
        return row

    def _claim(self, db: Session, row: BinaryScanJob,
               worker_id: str = "api-inline-worker") -> bool:
        now = utcnow()
        result = db.execute(
            update(BinaryScanJob)
            .where(BinaryScanJob.id == row.id,
                   BinaryScanJob.version == row.version,
                   BinaryScanJob.status == "QUEUED")
            .values(status="CLAIMED", claimed_by=worker_id,
                    lease_expires_at=now + timedelta(seconds=self.lease_seconds),
                    started_at=row.started_at or now,
                    version=row.version + 1, updated_at=now))
        db.commit()
        return result.rowcount == 1

    def _finish(self, db: Session, job_id: str, tenant_id: Optional[str],
                *, status: str, result: Optional[Dict[str, Any]],
                error: Optional[str],
                extra: Optional[Dict[str, Any]] = None) -> bool:
        row = self._visible(db, job_id, tenant_id)
        if row is None:
            return False
        now = utcnow()
        values = {
            "status": status, "result": result, "error": error,
            "completed_at": now, "version": row.version + 1, "updated_at": now,
        }
        if extra:
            values.update(extra)
        outcome = db.execute(
            update(BinaryScanJob)
            .where(BinaryScanJob.id == row.id,
                   BinaryScanJob.version == row.version,
                   BinaryScanJob.status == "CLAIMED")
            .values(**values))
        db.commit()
        return outcome.rowcount == 1

    def _execute(self, db: Session, row: BinaryScanJob,
                 on_result: Optional[Callable[[ScanResult], Any]] = None
                 ) -> Dict[str, Any]:
        started = time.perf_counter()
        try:
            data = self._resolve_blob(db, tenant_id=row.tenant_id,
                                      sha256=row.artifact_sha256)
            result = run_scan(
                tenant_id=row.tenant_id, data=data,
                original_filename=row.original_filename,
                source_type=row.source_type, uploaded_by=row.uploaded_by,
                source_location=row.source_location, profile=row.profile)
        except ValueError as exc:
            self._failed += 1
            self.fail(db, row.job_id, str(exc), tenant_id=row.tenant_id)
            return {"status": "failed", "reason": str(exc),
                    "tenant_id": row.tenant_id}
        elapsed = time.perf_counter() - started
        if elapsed > self.limits.max_seconds_per_job:
            self._failed += 1
            reason = (
                f"job took {elapsed:.1f}s, above the wall-clock limit "
                f"{self.limits.max_seconds_per_job}s — reported as a "
                "failure, never silently truncated")
            self.fail(db, row.job_id, reason, tenant_id=row.tenant_id)
            return {"status": "failed", "scan_id": result.scan_id,
                    "tenant_id": row.tenant_id, "reason": reason}
        summary = {
            "status": "completed", "scan_id": result.scan_id,
            "tenant_id": row.tenant_id, "elapsed_seconds": round(elapsed, 4),
            "finding_count": len(result.findings), "timings": result.timings,
        }
        self._processed += 1
        self.complete(db, row.job_id, summary, tenant_id=row.tenant_id)
        if on_result is not None:
            on_result(result)
        return summary
