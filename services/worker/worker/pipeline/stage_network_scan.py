"""Discover TLS endpoints and local certificates in the scanned tree."""

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
        from network_scanner.core.scanner import NetworkTlsScanner
    except Exception:
        logger.debug("network_scanner_unavailable")
        return ctx
    result = NetworkTlsScanner(live=False).scan_filesystem(root, scan_id=ctx.scan_id)
    ctx.tls_result = result
    ctx.findings.extend(result.get("findings") or [])
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["tls"] = {
        "targets": len(result.get("targets") or []),
        "certificates": len(result.get("certificates") or []),
        "alerts": len(result.get("alerts") or []),
    }
    logger.info("stage_network_scan_done", extra=ctx.scan_meta["tls"])
    return ctx


class StageNetworkScan:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
