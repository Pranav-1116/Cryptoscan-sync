"""Execute a CLOUD inventory job without cloning a git repository."""

from __future__ import annotations

import logging
from typing import Any

from cloud_scanner.estate import ingest_findings, parse_cloud_target
from worker.core.job_consumer import ScanJob
from worker.pipeline.public_failure import log_job_failure, public_cloud_telemetry, public_count, public_failure

logger = logging.getLogger(__name__)


def run_cloud_job(job: ScanJob) -> bool:
    from db.connection.session import SessionLocal
    from db.repositories.job_repository import JobRepository

    session = SessionLocal()
    jobs = JobRepository(session)
    try:
        jobs.update_status(job.job_id, "RUNNING", progress={"current_stage": "cloud_inventory", "percent": 5})
        session.commit()
        result = _scan(session, job)
        findings = result.get("findings") or []
        live_scan = result.get("live_scan") or {}
        safe_scan = public_cloud_telemetry(live_scan) if live_scan else None
        if live_scan.get("errors") or result.get("errors"):
            logger.warning("cloud_job_scan_errors", extra={
                "job_id": job.job_id, "stage": "cloud_inventory", "error_type": "ScanTelemetryError",
                "error_count": safe_scan["error_count"] if safe_scan else 0,
            })
        if safe_scan and safe_scan["status"] == "FAILED":
            # Configured but every call errored — report failure, never an
            # empty success, and do not stamp systems CURRENT from nothing.
            summary = (
                f"{public_failure('Cloud inventory', 'cloud_inventory')}: "
                f"{safe_scan['error_count']} errors, 0 resources"
            )
            jobs.update_status(
                job.job_id,
                "FAILED",
                error_message=summary[:500],
                progress={
                    "current_stage": "cloud_inventory",
                    "percent": 100,
                    "status": "FAILED",
                    "cloud": {
                        "resources": 0,
                        "systems": 0,
                        "live_scan": safe_scan,
                    },
                },
            )
            session.commit()
            logger.warning("cloud_job_live_scan_failed", extra={
                "job_id": job.job_id, "stage": "cloud_inventory", "error_type": "ScanTelemetryError",
                "error_count": safe_scan["error_count"],
            })
            return False
        ingested = ingest_findings(
            session,
            findings,
            scan_id=job.job_id,
            account=parse_cloud_target(job.target_repo)[1],
            stamp=True,
        )
        if job.system_id and ingested.get("systems"):
            from db.repositories.system_repository import SystemRepository

            SystemRepository(session).stamp_scan(
                job.system_id,
                scan_id=job.job_id,
                status="CURRENT",
                target=job.target_repo,
                component_count=int(ingested.get("systems") or 0),
                algorithms=ingested.get("algorithms") or {},
            )
        session.commit()
        jobs.update_status(
            job.job_id,
            "COMPLETED",
            progress={
                "current_stage": "cloud_inventory",
                "percent": 100,
                "status": "COMPLETED",
                "cloud": {
                    "resources": public_count(result.get("resources")),
                    "systems": public_count(ingested.get("systems")),
                    "errors": safe_scan["errors"] if safe_scan else [],
                    "live_scan": safe_scan,
                },
            },
        )
        session.commit()
        logger.info(
            "cloud_job_done",
            extra={"job_id": job.job_id, "systems": public_count(ingested.get("systems")),
                   "resources": public_count(result.get("resources"))},
        )
        return True
    except Exception as exc:
        log_job_failure(logger, "cloud_job_failed", exc, job_id=job.job_id, stage="cloud_inventory")
        try:
            session.rollback()
            jobs.update_status(
                job.job_id, "FAILED",
                error_message=public_failure("Cloud inventory", "cloud_inventory"),
                progress={"current_stage": "cloud_inventory", "status": "FAILED", "percent": 100},
            )
            session.commit()
        except Exception as status_exc:
            log_job_failure(logger, "cloud_job_failure_status_persist_failed", status_exc,
                            job_id=job.job_id, stage="cloud_inventory")
            session.rollback()
        return False
    finally:
        session.close()


def _scan(session, job: ScanJob) -> dict[str, Any]:
    from cloud_scanner.core.scanner import CloudScanner
    from db.repositories.intelligence_repository import IntelligenceRepository

    provider, identifier = parse_cloud_target(job.target_repo)
    account = IntelligenceRepository(session).find_cloud_account(provider, identifier)
    providers = [provider.upper()] if provider in {"aws", "azure", "gcp"} else ["AWS", "AZURE", "GCP"]
    return CloudScanner(live=True).scan_live(
        providers=providers,
        regions=getattr(account, "regions", None) if account else None,
        role_arn=getattr(account, "role_arn", None) if account else None,
        azure_subscription=identifier if provider == "azure" else None,
        gcp_project=identifier if provider == "gcp" else None,
    )
