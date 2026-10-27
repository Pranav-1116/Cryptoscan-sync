"""Durable per-run records for synchronous specialized scanners (§4.8/§5, round 44).

A synchronous scan that only returns its result leaves no per-run identity:
an operator cannot later answer "which run produced this, when, under which
admission decision, and what did it cover" — the shared latest-cycle listing
is not that run's status. Each specialized trigger now writes a ``ScanJob``
row BEFORE executing (status RUNNING) and stamps the outcome after, so the
synchronous collectors share the ONE durable-job contract the queued worker
pipeline already uses (``GET /api/v1/jobs/{id}``).

Honesty properties:

* The row is committed before the scan runs, so a crash mid-run leaves a
  visible RUNNING job (the existing reaper later fails it) instead of no
  record at all — outcome unknown is disclosed, never invented.
* The admission decision that authorized the run is stored on the record.
* ``coverage`` is bounded counts/labels from the scan result — never the
  full payload (which can be large and may carry finding content).
* The record is tenant-bound (``tenant_id`` from the server-resolved request
  context, never from the request body).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from db.repositories.job_repository import JobRepository

logger = logging.getLogger(__name__)

#: string values are truncated to this length inside coverage summaries
_MAX_COVERAGE_STRING = 80


def coverage_from_result(result: Any) -> dict[str, Any]:
    """Bounded, content-free summary of a scan result for the job record.

    Numbers and booleans pass through; strings are truncated; lists/dicts
    become their lengths. Anything else (None included) is dropped. The
    summary describes SIZE, never finding content.
    """
    coverage: dict[str, Any] = {}
    if not isinstance(result, dict):
        return coverage
    for key, value in result.items():
        if key == "admission":
            continue
        if isinstance(value, bool) or isinstance(value, (int, float)):
            coverage[str(key)] = value
        elif isinstance(value, str):
            coverage[str(key)] = value[:_MAX_COVERAGE_STRING]
        elif isinstance(value, (list, dict)):
            coverage[f"{key}_count"] = len(value)
    return coverage


class DurableScanRun:
    """Context manager wrapping one synchronous specialized scan execution.

    Usage::

        with DurableScanRun(db, job_type="CLOUD_SCAN", target=path,
                            user=ctx.username, admission=decision,
                            tenant_id=ctx.tenant_id) as run:
            result = scanner.scan_filesystem(target)
            run.succeed(coverage=coverage_from_result(result))
        # run.job_id is the durable identity; HTTP errors raised inside the
        # block stamp the record FAILED with the reason before propagating.
    """

    def __init__(
        self,
        db: Session,
        *,
        job_type: str,
        target: str,
        user: str,
        admission: dict | None = None,
        tenant_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        self._db = db
        self._repo = JobRepository(db)
        self._job_type = job_type
        self._target = str(target)
        self._user = str(user)
        self._admission = admission
        self._tenant_id = tenant_id
        self._metadata = metadata or {}
        self._job = None

    def __enter__(self) -> "DurableScanRun":
        progress: dict[str, Any] = {"execution": "synchronous"}
        if self._admission is not None:
            progress["admission"] = self._admission
        if self._metadata:
            progress["run"] = self._metadata
        self._job = self._repo.create(
            job_type=self._job_type,
            target_repo=self._target,
            target_branch="sync",
            triggered_by=self._user,
            status="RUNNING",
            progress=progress,
            tenant_id=self._tenant_id,
        )
        # RUNNING -> RUNNING is the documented stage-progress transition;
        # it stamps started_at so a completed run keeps its real duration
        # even though it never passed through QUEUED.
        self._repo.update_status(self._job.id, "RUNNING")
        # commit before the scan runs: the record must exist even if the
        # process dies mid-execution
        self._db.commit()
        return self

    @property
    def job_id(self) -> str:
        if self._job is None:
            raise RuntimeError("DurableScanRun used outside its context")
        return str(self._job.id)

    def _progress(self) -> dict[str, Any]:
        progress = self._job.progress if isinstance(self._job.progress, dict) else {}
        return dict(progress)

    def plan(self, items):
        from api.security.partial_progress import plan
        plan(self, items)

    def collect_phase(self, endpoint, phase, operation, admission):
        from api.security.partial_progress import collect
        return collect(self, endpoint, phase, operation, admission)

    def conclusions(self):
        from db.models.assurance import CollectionPhaseReceipt
        phases = self._db.query(CollectionPhaseReceipt).filter_by(job_id=self.job_id, tenant_id=self._tenant_id).all()
        if not phases:
            return None
        return {"recording_completed": True,
                "observation_succeeded": all(p.observation_succeeded is True for p in phases),
                "collection_complete": all(p.state == "COMPLETED" for p in phases),
                "posture_acceptable": None, "posture_reason": "SEPARATE_POLICY_EVALUATION_REQUIRED"}

    def succeed(self, *, coverage: dict | None = None, scan_id: str | None = None) -> None:
        progress = self._progress()
        conclusions = self.conclusions()
        if conclusions is not None:
            if not conclusions["collection_complete"]:
                raise RuntimeError("Interrupted/partial scope cannot finalize as a completed batch")
            progress["collection_conclusions"] = conclusions
        if coverage is not None:
            progress["coverage"] = coverage
        updated = self._repo.update_status(self._job.id, "COMPLETED", scan_id=scan_id, progress=progress)
        if updated is None:
            raise RuntimeError("Durable run completion was refused")
        self._db.commit()

    def fail(self, error: Any) -> None:
        self._repo.update_status(
            self._job.id, "FAILED",
            error_message=str(error)[:500], progress=self._progress(),
        )
        self._db.commit()

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc is not None:
            try:
                self.fail(f"{exc_type.__name__ if exc_type else 'Error'}: {exc}")
            except Exception:  # noqa: BLE001 — stamping must never mask the original error
                logger.warning("durable_run_fail_stamp_failed", exc_info=True)
        return False
