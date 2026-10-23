"""Execute one queued job through the pipeline."""

from __future__ import annotations

import logging

from worker.core.execution_gate import gate_job
from worker.core.job_consumer import ScanJob
from worker.core.queued_authority import QueueRefused, QueueDeferred, reconcile, claim
from worker.pipeline.pipeline_runner import PipelineRunner

logger = logging.getLogger(__name__)


class JobExecutor:
    def __init__(self, **kwargs):
        self.runner = PipelineRunner()

    def execute(self, job: ScanJob) -> bool:
        """Resolve persisted authority before choosing a scope or execution branch."""
        from db.tenancy import tenant_scope

        try:
            job = reconcile(job)
        except QueueRefused as exc:
            # An untrusted descriptor must not be able to fail a victim row.
            logger.warning("queue_descriptor_refused", extra={"job_id": job.job_id, "reason": str(exc)})
            return False
        with tenant_scope(job.tenant_id):
            return self._execute_in_scope(job)

    def _execute_in_scope(self, job: ScanJob) -> bool:
        from cloud_scanner.estate import is_org_target, should_run_cloud_job

        from worker.pipeline.binary_job import is_binary_target, run_binary_job

        if is_binary_target(job.target_repo):
            # a binary scan has no repository to clone; it walks a path under the
            # configured source roots and produces the same artifact the
            # synchronous endpoint does
            return self._gated(job, repository_target=False, run=lambda: run_binary_job(job))
        if is_org_target(job.target_repo):
            from worker.pipeline.org_job import run_org_job

            return self._gated(job, repository_target=False, run=lambda: run_org_job(job))
        if should_run_cloud_job(job):
            from worker.pipeline.cloud_job import run_cloud_job

            return self._gated(job, repository_target=False, run=lambda: run_cloud_job(job))
        from worker.pipeline.pipeline_runner import trace_id_from_job

        def _run_pipeline() -> bool:
            scan_id = self.runner.run(
                job_id=job.job_id,
                target_repo=job.target_repo,
                target_branch=job.target_branch,
                target_commit=job.target_commit,
                triggered_by=job.triggered_by,
                system_id=getattr(job, "system_id", None),
                trace_id=trace_id_from_job(job),
            )
            return bool(scan_id)

        return self._gated(job, repository_target=True, run=_run_pipeline)

    def _gated(self, job: ScanJob, *, repository_target: bool, run) -> bool:
        """Run one execution branch behind the round-46 execution gate.

        Admission happened at enqueue; the gate re-derives the decisions at
        execution time — an emergency stop engaged after enqueue, a tightened
        safe-scan policy, or source roots that no longer contain the target
        refuse the job HERE, the row is stamped FAILED with the reason, and
        no collector runs.
        """
        permitted, reason = gate_job(job, repository_target=repository_target)
        if not permitted:
            message = f"execution gate: {reason}"
            logger.warning("job_refused_at_execution", extra={"job_id": job.job_id, "reason": reason})
            self._stamp_refusal(job, message)
            return False
        try:
            attempt = claim(job)
        except QueueDeferred:
            from db.repositories.execution_outbox import defer
            defer(job.job_id, job.tenant_id)
            logger.info("controlled_job_deferred", extra={"job_id": job.job_id})
            return False
        except QueueRefused as exc:
            logger.warning("queue_authority_refused", extra={"job_id": job.job_id, "reason": str(exc)})
            self._stamp_refusal(job, "execution authority: " + str(exc))
            return False
        from db.repositories.execution_control import execution_scope, finish_attempt
        try:
            with execution_scope(attempt):
                outcome = bool(run())
        except BaseException:
            try:
                finish_attempt(attempt, False)
            except Exception as exc:
                # Preserve the original interruption. An unavailable SQL write
                # does NOT prove external work stopped or free reservations;
                # the durable deadline reaper will fence the attempt UNKNOWN.
                logger.warning(
                    "interrupted_attempt_recovery_deferred",
                    extra={"job_id": job.job_id, "error_type": type(exc).__name__},
                )
            raise
        return bool(finish_attempt(attempt, outcome))

    @staticmethod
    def _stamp_refusal(job: ScanJob, message: str) -> None:
        """Best-effort FAILED stamp for a job the execution gate refused.

        The refusal usually happens *because* the database could not be read —
        that is the gate's fail-closed rule — so the stamp itself must never
        become the error. Raising here replaced a clean policy refusal with an
        ``UnboundExecutionError``/``OperationalError`` out of ``execute()``,
        left the row un-stamped, and buried the reason: the pool logged
        ``job_execution_failed`` (a crash) instead of a refusal with a cause.
        Log and hand the row to the reaper, which owns orphaned jobs.
        """
        from db.connection.session import SessionLocal

        session = None
        try:
            session = SessionLocal()
            from sqlalchemy import update
            from db.models.scan_job import ScanJob as JobRow
            from db.models.base import utcnow

            # Never turn forged/duplicate work into a write against a foreign
            # row or fail another worker's already-claimed RUNNING execution.
            session.execute(
                update(JobRow)
                .where(
                    JobRow.id == job.job_id,
                    JobRow.tenant_id == job.tenant_id,
                    JobRow.status == "QUEUED",
                )
                .values(status="FAILED", version=JobRow.version + 1, completed_at=utcnow(), error_message=message[:500])
            )
            session.commit()
        except Exception as exc:  # noqa: BLE001 — a refused job must not raise
            try:
                if session is not None:
                    session.rollback()
            except Exception:  # noqa: BLE001
                logger.debug("job_refusal_rollback_failed", exc_info=True)
            logger.warning(
                "job_refusal_stamp_failed",
                extra={"job_id": job.job_id, "reason": message, "error_type": type(exc).__name__},
            )
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    logger.debug("job_refusal_session_close_failed", exc_info=True)
