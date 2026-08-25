"""Update certificate inventory after a network TLS scan."""

from __future__ import annotations

import logging

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    result = dict(ctx.tls_result or {})
    certs = list(result.get("certificates") or [])
    try:
        from network_scanner.inventory.certificate_deduplicator import dedupe_certificates
        from network_scanner.inventory.expiry_monitor import expiry_alerts
    except Exception:
        logger.debug("cert_inventory_imports_unavailable")
        return ctx
    merged = dedupe_certificates([], certs)
    alerts = expiry_alerts(merged)
    result["inventory"] = merged
    result["alerts"] = alerts
    ctx.tls_result = result
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["certs"] = {"count": len(merged), "alerts": len(alerts)}
    logger.info("stage_cert_inventory_done", extra=ctx.scan_meta["certs"])
    return ctx


class StageCertInventory:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
