"""Run static, container, network, and cloud scanners for one workspace."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_cloud_scan import execute as cloud_scan
from worker.pipeline.stage_network_scan import execute as network_scan
from worker.pipeline.stage_scan import execute as static_scan


def execute(ctx: PipelineContext) -> PipelineContext:
    static_scan(ctx)
    try:
        from worker.pipeline.stage_container_scan import execute as container_scan

        container_scan(ctx)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    network_scan(ctx)
    try:
        from worker.pipeline.stage_cert_inventory import execute as cert_inventory

        cert_inventory(ctx)
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    cloud_scan(ctx)
    return ctx


class StageMultiScanner:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
