"""Execute a CLOUD inventory job without cloning a git repository."""

from __future__ import annotations

import logging
from typing import Any

from cloud_scanner.estate import ingest_findings, parse_cloud_target
from worker.core.job_consumer import ScanJob

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
                    "resources": result.get("resources") or 0,
                    "systems": ingested.get("systems") or 0,
                    "errors": result.get("errors") or [],
                },
            },
        )
        session.commit()
        logger.info(
            "cloud_job_done",
            extra={"job_id": job.job_id, "systems": ingested.get("systems"), "resources": result.get("resources")},
        )
        return True
    except Exception as exc:
        logger.exception("cloud_job_failed", extra={"job_id": job.job_id})
        try:
            session.rollback()
            jobs.update_status(job.job_id, "FAILED", error_message=str(exc)[:500])
            session.commit()
        except Exception:
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
