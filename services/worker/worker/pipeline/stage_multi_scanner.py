"""Run static, container, network, and cloud scanners for one workspace."""

from __future__ import annotations

from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.stage_cloud_scan import execute as cloud_scan
from worker.pipeline.stage_network_scan import execute as network_scan
from worker.pipeline.stage_scan import execute as static_scan


def execute(ctx: PipelineContext) -> PipelineContext:
    static_scan(ctx)
    try:
        from worker.pipeline.stage_container_scan import execute as container_scan

        container_scan(ctx)
    except Exception:
        pass
    network_scan(ctx)
    try:
        from worker.pipeline.stage_cert_inventory import execute as cert_inventory

        cert_inventory(ctx)
    except Exception:
        pass
    cloud_scan(ctx)
    return ctx


class StageMultiScanner:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
