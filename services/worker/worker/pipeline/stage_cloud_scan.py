"""Scan Terraform / CloudFormation / Kubernetes manifests for crypto config.

CLOUD jobs (cloud://provider/account targets) run a *live* scan with full
telemetry; filesystem targets get the IaC scan. Either way the scan_meta
"cloud" block now reports the live_scan verdict so a configured-but-failing
provider can never masquerade as an empty success downstream.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from worker.pipeline.pipeline_runner import PipelineContext
from worker.pipeline.public_failure import log_job_failure, public_cloud_telemetry, public_count

logger = logging.getLogger(__name__)


def _cloud_live_enabled() -> bool:
    return os.environ.get("CRYPTOSCAN_CLOUD_LIVE", "").strip().lower() in {"1", "true", "yes", "on"}


def _run_live(ctx: PipelineContext) -> dict:
    """Live scan for a cloud:// target. Providers parsed from the target."""
    from cloud_scanner.core.scanner import CloudScanner
    from cloud_scanner.estate import parse_cloud_target

    provider, account = parse_cloud_target(ctx.target_repo)
    regions = [r for r in (os.environ.get("CRYPTOSCAN_CLOUD_REGIONS") or "").split(",") if r.strip()] or None
    result = CloudScanner(live=False).scan_live(
        providers=[provider.upper()] if provider else None,
        regions=regions,
        role_arn=os.environ.get("CRYPTOSCAN_AWS_ROLE_ARN") or os.environ.get("AWS_ROLE_ARN"),
        azure_subscription=account if provider == "azure" else None,
        gcp_project=account if provider == "gcp" else None,
        scan_id=ctx.scan_id,
    )
    return result


def _safe_providers(value: object) -> list[str]:
    """Only known provider names belong in stage metadata or log extras."""
    if not isinstance(value, list):
        return []
    return sorted({provider for provider in value if type(provider) is str and provider in {"AWS", "AZURE", "GCP"}})


def _safe_live_scan(value: object) -> dict | None:
    return public_cloud_telemetry(value) if isinstance(value, dict) else None


def execute(ctx: PipelineContext) -> PipelineContext:
    from cloud_scanner.estate import parse_cloud_target, should_run_cloud_job

    if should_run_cloud_job(
        {"job_type": getattr(ctx, "job_type", "") or "", "target_repo": ctx.target_repo}
    ):
        try:
            result = _run_live(ctx)
        except Exception as exc:
            log_job_failure(logger, "stage_cloud_scan_live_failed", exc, job_id=ctx.job_id, stage="cloud_scan")
            provider, _account = parse_cloud_target(ctx.target_repo)
            ctx.cloud_result = {"live": True, "findings": [], "resources": 0, "issues": 0}
            ctx.scan_meta = dict(ctx.scan_meta or {})
            ctx.scan_meta["cloud"] = {
                "resources": 0,
                "issues": 0,
                "providers": [],
                "provider": provider.upper() if provider in {"aws", "azure", "gcp"} else "unknown",
                "live": True,
                "live_scan": {
                    "enabled": True,
                    "status": "FAILED",
                    "resources_scanned": 0,
                    "errors": [{"error": "Cloud provider call failed"}],
                    "truncations": [],
                    "error_count": 1,
                    "truncation_count": 0,
                },
            }
            return ctx
        ctx.cloud_result = result
        ctx.findings.extend(result.get("findings") or [])
        ctx.scan_meta = dict(ctx.scan_meta or {})
        safe_scan = _safe_live_scan(result.get("live_scan"))
        ctx.scan_meta["cloud"] = {
            "resources": public_count(result.get("resources")),
            "issues": public_count(result.get("issues")),
            "providers": _safe_providers(result.get("providers")),
            "live": True,
            "live_scan": safe_scan,
        }
        logger.info(
            "stage_cloud_scan_live_done",
            extra={"status": safe_scan["status"] if safe_scan else "UNKNOWN"},
        )
        return ctx

    root = Path(ctx.repo_path)
    if not root.exists():
        return ctx
    try:
        from cloud_scanner.core.scanner import CloudScanner
    except Exception:
        logger.debug("cloud_scanner_unavailable")
        return ctx
    result = CloudScanner(live=_cloud_live_enabled()).scan_filesystem(root, scan_id=ctx.scan_id)
    ctx.cloud_result = result
    ctx.findings.extend(result.get("findings") or [])
    ctx.scan_meta = dict(ctx.scan_meta or {})
    ctx.scan_meta["cloud"] = {
        "resources": public_count(result.get("resources")),
        "issues": public_count(result.get("issues")),
        "providers": _safe_providers(result.get("providers")),
        "live": bool(result.get("live")),
        "live_scan": _safe_live_scan(result.get("live_scan")),
    }
    logger.info("stage_cloud_scan_done", extra=ctx.scan_meta["cloud"])
    return ctx


class StageCloudScan:
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        return execute(ctx)
