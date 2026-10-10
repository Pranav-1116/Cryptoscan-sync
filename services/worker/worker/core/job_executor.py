"""Execute one queued job through the pipeline."""

from __future__ import annotations

import logging

from worker.core.job_consumer import ScanJob
from worker.pipeline.pipeline_runner import PipelineRunner

logger = logging.getLogger(__name__)


class JobExecutor:
    def __init__(self, **kwargs):
        self.runner = PipelineRunner()

    def execute(self, job: ScanJob) -> bool:
        """Run the job inside its owning tenant's scope.

        The scope wraps every branch, not just the pipeline: a binary, org or
        cloud job writes the same tenant-owned rows. Outside a scope the ORM
        guard is inert and stamp_tenant is a no-op, so the results would land
        with tenant_id NULL — the platform estate, readable by every tenant.

        ``tenant_id`` None is the platform-owned case and also what a job
        queued before the field existed looks like; tenant_scope(None) is a
        no-op, so those keep behaving exactly as before.
        """
        from db.tenancy import tenant_scope

        with tenant_scope(job.tenant_id):
            return self._execute_in_scope(job)

    def _execute_in_scope(self, job: ScanJob) -> bool:
        from cloud_scanner.estate import is_org_target, should_run_cloud_job

        from worker.pipeline.binary_job import is_binary_target, run_binary_job

        if is_binary_target(job.target_repo):
            # a binary scan has no repository to clone; it walks a path under the
            # configured source roots and produces the same artifact the
            # synchronous endpoint does
            return run_binary_job(job)
        if is_org_target(job.target_repo):
            from worker.pipeline.org_job import run_org_job

            return run_org_job(job)
        if should_run_cloud_job(job):
            from worker.pipeline.cloud_job import run_cloud_job

            return run_cloud_job(job)
        from worker.pipeline.pipeline_runner import trace_id_from_job

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
