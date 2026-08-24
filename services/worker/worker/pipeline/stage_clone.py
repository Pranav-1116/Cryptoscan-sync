"""
Pipeline Stage 1: Clone repository.
Clones the target Git repository to the workspace.
"""
from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext
from worker.workspace.repo_cloner import RepoCloner

logger = logging.getLogger(__name__)


class StageClone:
    """Clone stage: git clone to workspace."""

    async def execute(self, ctx: PipelineContext) -> PipelineContext:
        """
        Clone repo to workspace_dir/repo.

        Raises: CloneError if clone fails.
        """
        cloner = RepoCloner()
        repo_path = Path(ctx.workspace_dir) / "repo"

        logger.info(
            "clone_start",
            extra={
                "job_id": ctx.job_id,
                "repo": ctx.target_repo,
                "branch": ctx.target_branch,
                "path": str(repo_path),
            },
        )

        try:
            commit_hash = await cloner.clone(
                repo_url=ctx.target_repo,
                branch=ctx.target_branch,
                target_path=str(repo_path),
                depth=1,
            )

            logger.info(
                "clone_success",
                extra={
                    "job_id": ctx.job_id,
                    "repo": ctx.target_repo,
                    "commit": commit_hash,
                },
            )

            return ctx.update(
                repo_path=str(repo_path),
                target_commit=commit_hash,
            )

        except Exception as exc:
            logger.exception(
                "clone_failed",
                extra={
                    "job_id": ctx.job_id,
                    "repo": ctx.target_repo,
                    "error": str(exc),
                },
            )
            raise