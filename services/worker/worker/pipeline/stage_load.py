"""Pipeline stage: persist scan + evidence."""

from __future__ import annotations

import logging
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext

logger = logging.getLogger(__name__)


def execute(ctx: PipelineContext, session) -> PipelineContext:
    from db.loader.evidence_loader import EvidenceLoader
    from db.loader.pre_load_verifier import verify_records

    ok, err = verify_records(ctx.evidence_records)
    if not ok:
        raise RuntimeError(f"pre-load verification failed: {err}")
    loader = EvidenceLoader(session)
    scan = loader.load(
        scan_meta=ctx.scan_meta,
        evidence_records=ctx.evidence_records,
        manifest=ctx.manifest,
        scan_id=ctx.scan_id,
    )
    ctx.scan_id = scan.id
    if ctx.container_result:
        try:
            from db.models.container_scan import ContainerScan
            from db.repositories.vulnerability_repository import VulnerabilityRepository

            result = ctx.container_result
            session.add(
                ContainerScan(
                    scan_id=scan.id,
                    target=str(Path(ctx.repo_path)),
                    package_count=len(result.get("packages") or []),
                    library_count=len(result.get("libraries") or []),
                    vuln_count=len(result.get("vulnerabilities") or []),
                    result=result,
                )
            )
            if result.get("vulnerabilities"):
                VulnerabilityRepository(session).replace_for_scan(scan.id, result["vulnerabilities"])
        except Exception:
            logger.debug("container_scan_persist_skipped", exc_info=True)
    session.flush()
    logger.info("stage_load_done", extra={"scan_id": scan.id})
    return ctx


class StageLoad:
    def execute(self, ctx: PipelineContext, session) -> PipelineContext:
        return execute(ctx, session)
