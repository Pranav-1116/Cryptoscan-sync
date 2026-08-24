"""Detect languages present in the cloned workspace."""

from __future__ import annotations

import logging

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    from scanner.core.language_detector import detect_languages_in_repo

    languages = detect_languages_in_repo(ctx.repo_path) if ctx.repo_path else []
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["languages"] = languages
    logger.info("stage_language_detect_done", extra={"languages": languages})
    return ctx


class StageLanguageDetect:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
