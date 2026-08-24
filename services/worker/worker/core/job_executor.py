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
        result = self.runner.run(
            job_id=job.job_id,
            target_repo=job.target_repo,
            target_branch=job.target_branch,
            target_commit=job.target_commit,
            triggered_by=job.triggered_by,
        )
        return bool(result.get("success"))
