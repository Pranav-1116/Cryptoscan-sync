"""Scan Terraform / CloudFormation / Kubernetes manifests for crypto config."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    root = Path(ctx.repo_path)
    if not root.exists():
        return ctx
    try:
        from cloud_scanner.core.scanner import CloudScanner
    except Exception:
        logger.debug("cloud_scanner_unavailable")
        return ctx
    result = CloudScanner(live=False).scan_filesystem(root, scan_id=ctx.scan_id)
    ctx.cloud_result = result
    ctx.findings.extend(result.get("findings") or [])
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["cloud"] = {
        "resources": result.get("resources") or 0,
        "issues": result.get("issues") or 0,
        "providers": result.get("providers") or [],
    }
    logger.info("stage_cloud_scan_done", extra=ctx.scan_meta["cloud"])
    return ctx


class StageCloudScan:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
