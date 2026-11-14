"""Development-only process-local scan orchestration (§12, §13).

This queue is intentionally NOT durable: restarting its API process loses
pending artifacts and another replica cannot claim them. The production API
refuses its async endpoints until a durable, protected artifact handoff exists.

A bounded job queue with backpressure — under load the offer is refused
and COUNTED, never silently dropped (§9/§14). A worker processes one
job at a time under declared limits: maximum artifact bytes, maximum
wall-clock per job (enforced cooperatively between stages — each stage
is independently bounded by the parsers' read limits), and the queue
depth itself. Timings per stage are recorded on every run (§13: intake,
hash, format, symbols, dependencies, detection, deep-analysis, RAM,
CPU, storage, failure rate, findings, evidence completeness) — the
stage timings are what this module can measure honestly; a deep-analysis
time exists only when an authorized deep-analysis adapter ran.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from binary_intelligence.pipeline import ScanResult, run_scan

DEFAULT_MAX_QUEUE = 32
DEFAULT_MAX_SECONDS = 120.0


@dataclass
class WorkerLimits:
    max_artifact_bytes: int = 256 * 1024 * 1024
    max_seconds_per_job: float = DEFAULT_MAX_SECONDS
    max_queue_depth: int = DEFAULT_MAX_QUEUE

    def __post_init__(self) -> None:
        if self.max_seconds_per_job <= 0 or self.max_queue_depth <= 0:
            raise ValueError(
                "worker limits are positive — an unlimited worker is how "
                "a scanner becomes the outage (§13/§14)")


@dataclass
class ScanJob:
    job_id: str
    tenant_id: str
    data: bytes
    original_filename: str
    source_type: str
    uploaded_by: str
    source_location: Optional[str] = None
    profile: str = "standard"


@dataclass
class ScanJobQueue:
    """A bounded FIFO of scan jobs. Backpressure refuses and counts —
    it never silently drops a job (§14)."""
    limits: WorkerLimits = field(default_factory=WorkerLimits)
    _pending: List[ScanJob] = field(default_factory=list)
    _refused: int = 0
    _accepted: int = 0
    _processed: int = 0
    _failed: int = 0

    @property
    def pending(self) -> int:
        return len(self._pending)

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

    def submit(self, job: ScanJob, db: Any = None) -> Tuple[bool, str]:
        """Offer one job. False + reason under backpressure. The optional
        ``db`` keeps the call signature identical to the durable queue; a
        process-local queue has nowhere to put it and ignores it."""
        if len(job.data) > self.limits.max_artifact_bytes:
            self._refused += 1
            return False, (
                f"artifact is {len(job.data)} bytes, above the worker "
                f"limit {self.limits.max_artifact_bytes} — refused (§14)")
        if self.pending >= self.limits.max_queue_depth:
            self._refused += 1
            return False, (
                f"queue is full at {self.limits.max_queue_depth} — "
                "backpressure refuses and counts, it never silently "
                "drops a job")
        self._pending.append(job)
        self._accepted += 1
        return True, "queued"

    def process_job(self, job_id: str,
                    on_result: Optional[Callable[[ScanResult], Any]] = None,
                    tenant_id: Optional[str] = None,
                    db: Any = None,
                    ) -> Optional[Dict[str, Any]]:
        """Pop only a visible job; a foreign id is indistinguishable from
        a missing one and is never consumed or run. None is reserved for
        an explicitly unscoped platform worker/operator."""
        for index, candidate in enumerate(self._pending):
            if candidate.job_id == job_id and (
                    tenant_id is None or candidate.tenant_id == tenant_id):
                job = self._pending.pop(index)
                return self._execute(job, on_result=on_result)
        return None

    def process_one(self, on_result: Optional[Callable[[ScanResult], Any]]
                    = None, db: Any = None) -> Optional[Dict[str, Any]]:
        """Pop and run one job under the wall-clock limit. Returns the
        run summary, or None when the queue is empty. A job that exceeds
        the time budget is reported as a FAILURE with its reason — never
        quietly truncated."""
        if not self._pending:
            return None
        job = self._pending.pop(0)
        return self._execute(job, on_result=on_result)

    def _execute(self, job: ScanJob,
                 on_result: Optional[Callable[[ScanResult], Any]] = None
                 ) -> Dict[str, Any]:
        started = time.perf_counter()
        try:
            result = run_scan(
                tenant_id=job.tenant_id, data=job.data,
                original_filename=job.original_filename,
                source_type=job.source_type, uploaded_by=job.uploaded_by,
                source_location=job.source_location, profile=job.profile)
        except ValueError as exc:
            self._failed += 1
            return {"status": "failed", "reason": str(exc),
                    "tenant_id": job.tenant_id}
        elapsed = time.perf_counter() - started
        if elapsed > self.limits.max_seconds_per_job:
            self._failed += 1
            return {
                "status": "failed", "scan_id": result.scan_id,
                "tenant_id": job.tenant_id,
                "reason": (
                    f"job took {elapsed:.1f}s, above the wall-clock limit "
                    f"{self.limits.max_seconds_per_job}s — reported as a "
                    "failure, never silently truncated"),
            }
        self._processed += 1
        if on_result is not None:
            on_result(result)
        return {
            "status": "completed", "scan_id": result.scan_id,
            "tenant_id": job.tenant_id,
            "elapsed_seconds": round(elapsed, 4),
            "finding_count": len(result.findings),
            "timings": result.timings,
        }

    def as_dict(self, db: Any = None) -> Dict[str, Any]:
        return {
            "pending": self.pending,
            "accepted_total": self.accepted_count,
            "processed_total": self.processed_count,
            "failed_total": self.failed_count,
            "refused_total": self.refused_count,
            "limits": {
                "max_artifact_bytes": self.limits.max_artifact_bytes,
                "max_seconds_per_job": self.limits.max_seconds_per_job,
                "max_queue_depth": self.limits.max_queue_depth,
            },
            "backend": "process_local_development_only",
            "durable": False,
            "note": "development-only bounded queue with backpressure — "
                    "refusals are counted and never silently dropped, but "
                    "pending jobs do not survive restart or cross replicas (§14)",
        }
