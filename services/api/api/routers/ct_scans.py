"""Spec-named certificate-transparency scan endpoints (`/ct-scans`).

The CT-monitoring core (poll a CT source for a monitored domain, compare
against known serials / approved issuers, flag NEW and ROGUE certificates)
lives in ``keyassure.ct_monitor`` and is already served as an assurance
check at ``/crypto-assurance/ct-monitor``. This router puts the SAME core
behind the specialized-scan contract (round 44/§4.8): central admission (the
CT fetch is an outbound network read, so it is admitted as active probing),
a tenant-bound durable ``ScanJob`` row (status, admission decision, bounded
coverage) readable at ``GET /jobs/{id}``, and per-domain honest errors — a
domain that cannot be checked is reported as an error, never folded into a
green summary.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import TenantContext, get_db_session, get_tenant_context
from api.security.scan_admission import admit_scan
from api.security.scan_runs import DurableScanRun, coverage_from_result

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ct-scans", tags=["ct-scans"])


class CtScanRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=200)
    known_serials: list[str] = Field(default_factory=list)
    allowed_issuers: list[str] = Field(default_factory=list)


@router.post("")
@router.post("/")
@router.post("/scan")
def trigger_ct_scan(
    body: CtScanRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: Session = Depends(get_db_session),
):
    """Monitor monitored domains in CT logs as a durable, admitted run."""
    decision = admit_scan(active_probing_requested=True)
    target = ", ".join(body.domains)[:500]
    with DurableScanRun(
        db, job_type="CT_MONITOR", target=target,
        user=ctx.username, admission=decision, tenant_id=ctx.tenant_id,
        metadata={"domains": len(body.domains)},
    ) as run:
        from keyassure.ct_monitor import CtMonitorError, monitor_domain, summarize

        # monitor_domain returns CtReport objects on success (summarize reads
        # their attributes); errors become plain dicts so per-domain failures
        # are reported, never silently dropped from the summary
        ok_reports: list = []
        out_reports: list[dict] = []
        for domain in body.domains:
            try:
                report = monitor_domain(
                    domain, known_serials=body.known_serials,
                    allowed_issuers=body.allowed_issuers)
            except CtMonitorError as exc:
                out_reports.append({"domain": domain, "error": str(exc),
                                    "observed": [], "new_certs": [], "rogue_certs": []})
                continue
            ok_reports.append(report)
            out_reports.append(report if isinstance(report, dict) else report.__dict__)
        if ok_reports:
            summary = dict(summarize(ok_reports))
        else:
            summary = {"domains_monitored": 0, "total_observed": 0,
                       "new_cert_alerts": 0, "rogue_cert_alerts": 0,
                       "rogue_domains": [], "new_domains": []}
        summary["domains"] = len(body.domains)
        summary["errors"] = sum(1 for r in out_reports if "error" in r)
        coverage = coverage_from_result({
            "domains": summary["domains"],
            "observed_certs": sum(len(r.get("observed") or []) for r in out_reports),
            "new_certs": sum(len(r.get("new_certs") or []) for r in out_reports),
            "rogue_certs": sum(len(r.get("rogue_certs") or []) for r in out_reports),
            "errors": summary["errors"],
        })
        run.succeed(coverage=coverage)
    return {"job_id": run.job_id, "admission": decision,
            "summary": summary, "reports": out_reports}
