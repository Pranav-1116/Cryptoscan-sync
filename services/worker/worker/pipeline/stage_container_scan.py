"""Optional container / image-root inventory stage."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext) -> PipelineContext:
    root = Path(ctx.repo_path)
    if not root.exists():
        return ctx
    markers = {"dockerfile", "requirements.txt", "package.json", "pom.xml", "go.mod"}
    has_manifest = False
    has_binary = False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name in markers or path.suffix.lower() == ".csproj":
            has_manifest = True
        if path.suffix.lower() == ".jar" or name.startswith("libcrypto"):
            has_binary = True
        if has_manifest or has_binary:
            break
    if not has_manifest and not has_binary:
        return ctx
    try:
        from container_scanner.core.scanner import ContainerScanner
    except Exception:
        logger.debug("container_scanner_unavailable")
        return ctx
    result = ContainerScanner().scan_filesystem(root, scan_id=ctx.scan_id)
    ctx.container_result = result
    ctx.findings.extend(result.get("findings") or [])
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["container"] = {
        "packages": len(result.get("packages") or []),
        "libraries": len(result.get("libraries") or []),
        "vulnerabilities": len(result.get("vulnerabilities") or []),
    }
    logger.info("stage_container_scan_done", extra=ctx.scan_meta["container"])
    return ctx


class StageContainerScan:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
