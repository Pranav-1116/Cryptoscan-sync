"""Execute a CLOUD org job: enumerate an org, fan out, roll up.

Targets like ``cloud://aws-org/<mgmt-account-id>`` (or azure-org://tenant,
gcp-org://folder) are one job that becomes N parallel account scans with
per-account telemetry and an org-level verdict.
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from typing import Any

from cloud_scanner.estate import ingest_findings, org_provider, parse_cloud_target
from worker.pipeline.public_failure import (
    log_job_failure, public_cloud_telemetry, public_count, public_failure, public_status,
)

logger = logging.getLogger(__name__)


def run_org_job(job) -> bool:
    from db.connection.session import SessionLocal
    from db.repositories.job_repository import JobRepository

    session = SessionLocal()
    jobs = JobRepository(session)
    try:
        jobs.update_status(job.job_id, "RUNNING", progress={"current_stage": "cloud_org_inventory", "percent": 5})
        session.commit()
        result = _scan_org(job)
        findings = result.get("findings") or []
        by_account = _group_by_account(findings)
        ingested_systems = 0
        for account_id, rows in by_account.items():
            ingested = ingest_findings(
                session,
                rows,
                scan_id=job.job_id,
                account=account_id,
                stamp=True,
            )
            ingested_systems += int(ingested.get("systems") or 0)
        session.commit()

        live_scan = result.get("live_scan") or {}
        safe_scan = public_cloud_telemetry(live_scan)
        if live_scan.get("errors") or any(row.get("error") for row in result.get("accounts") or []):
            logger.warning("org_job_scan_errors", extra={
                "job_id": job.job_id, "stage": "cloud_org_inventory", "error_type": "ScanTelemetryError",
                "error_count": safe_scan["error_count"],
            })
        status = "COMPLETED" if safe_scan["status"] != "FAILED" else "FAILED"
        progress = {
            "current_stage": "cloud_org_inventory",
            "percent": 100,
            "status": status,
            "cloud": {
                "org": True,
                "provider": result.get("provider") if isinstance(result.get("provider"), str)
                            and result.get("provider") in {"aws", "azure", "gcp"} else "unknown",
                "accounts_discovered": public_count(result.get("accounts_discovered")),
                "accounts_scanned": safe_scan.get("accounts_scanned"),
                "accounts_failed": safe_scan.get("accounts_failed"),
                "resources": public_count(result.get("resources")),
                "systems": ingested_systems,
                "truncated": result.get("truncated") is True,
                "live_scan": safe_scan,
                "accounts": [
                    {"account_id": row.get("account_id"), "ok": row.get("ok") is True,
                     "resources": public_count(row.get("resources")), "status": public_status(row.get("status")),
                     "error": public_failure("Cloud account", "cloud_org_inventory") if row.get("error") else None}
                    for row in (result.get("accounts") or [])[:50]
                ],
            },
        }
        jobs.update_status(
            job.job_id,
            status,
            progress=progress,
            error_message=None if status == "COMPLETED" else _failure_summary(result)[:500],
        )
        session.commit()
        logger.info(
            "org_job_done",
            extra={
                "job_id": job.job_id,
                "accounts": progress["cloud"]["accounts_discovered"],
                "resources": progress["cloud"]["resources"],
                "status": safe_scan["status"],
            },
        )
        return status == "COMPLETED"
    except Exception as exc:  # noqa: BLE001 — job boundary
        log_job_failure(logger, "org_job_failed", exc, job_id=job.job_id, stage="cloud_org_inventory")
        try:
            session.rollback()
            jobs.update_status(
                job.job_id, "FAILED",
                error_message=public_failure("Cloud organization inventory", "cloud_org_inventory"),
                progress={"current_stage": "cloud_org_inventory", "status": "FAILED", "percent": 100},
            )
            session.commit()
        except Exception as status_exc:
            log_job_failure(logger, "org_job_failure_status_persist_failed", status_exc,
                            job_id=job.job_id, stage="cloud_org_inventory")
            session.rollback()
        return False
    finally:
        session.close()


def _scan_org(job) -> dict[str, Any]:
    from cloud_scanner.org.job import scan_org

    provider = org_provider(job.target_repo) or "aws-org"
    _scheme, identifier = parse_cloud_target(job.target_repo)
    kwargs: dict[str, Any] = {}
    base = provider.replace("-org", "")
    if base == "aws":
        kwargs["role_name"] = os.environ.get("CRYPTOSCAN_AWS_ORG_ROLE_NAME") or "CryptoScanCrossAccountRole"
    elif base == "gcp" and identifier:
        if identifier.startswith("folders/"):
            kwargs["folder"] = identifier.split("/", 1)[1]
        elif identifier.isdigit():
            kwargs["organization"] = identifier
        else:
            kwargs["folder"] = identifier
    regions = [r for r in (os.environ.get("CRYPTOSCAN_CLOUD_REGIONS") or "").split(",") if r.strip()]
    if regions:
        kwargs["regions"] = regions
    return scan_org(provider, **kwargs)


def _group_by_account(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in findings:
        account = str((row.get("metadata") or {}).get("cloud_account") or (row.get("extra") or {}).get("account") or "org")
        groups[account].append(row)
    return dict(groups)


def _failure_summary(result: dict[str, Any]) -> str:
    safe_scan = public_cloud_telemetry(result.get("live_scan") or {})
    return (
        f"{public_failure('Cloud organization inventory', 'cloud_org_inventory')}: "
        f"{safe_scan.get('accounts_failed', 0)} accounts failed, 0 resources"
    )
