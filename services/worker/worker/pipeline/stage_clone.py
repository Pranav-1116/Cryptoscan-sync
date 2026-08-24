"""Pipeline stage: clone the target repository."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext
from worker.workspace.repo_cloner import RepoCloner

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, cloner: RepoCloner | None = None) -> PipelineContext:
    dest = Path(ctx.workspace_dir) / "repo"
    cloner = cloner or RepoCloner()
    commit = cloner.clone(
        repo_url=ctx.target_repo,
        branch=ctx.target_branch,
        target_path=str(dest),
        commit=ctx.target_commit,
    )
    ctx.repo_path = str(dest if dest.exists() else commit)
    if dest.exists():
        ctx.target_commit = str(commit)
    logger.info("stage_clone_done", extra={"path": ctx.repo_path, "commit": ctx.target_commit})
    return ctx


class StageClone:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
