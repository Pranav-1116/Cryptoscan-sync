"""Scan list and detail."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.dependencies import (
    TenantContext,
    get_current_user,
    get_db_session,
    get_job_repository,
    get_scan_repository,
    get_tenant_context,
    require_auditor,
)
from api.security.estate_history import history_context
from api.schemas.job_schemas import TriggerScanResponse
from api.schemas.scan_schemas import ScanListResponse, ScanResponse
from db.repositories.job_repository import JobRepository
from db.repositories.scan_repository import ScanRepository
from shared_models.safe_finding import safe_finding

router = APIRouter(prefix="/scans", tags=["scans"])


def _slim_statistics(stats: Optional[dict]) -> Optional[dict]:
    """List/detail responses carry the cascade *summary* only; the full report is GET /scans/{id}/cascade."""
    if not stats or "cascade" not in stats:
        return stats
    slim = dict(stats)
    cascade = slim.pop("cascade") or {}
    slim["cascade_summary"] = cascade.get("summary")
    return slim


def _to_response(scan) -> ScanResponse:
    return ScanResponse(
        scan_id=scan.id,
        status=scan.status,
        target_location=scan.target_location,
        target_type=scan.target_type,
        target_branch=scan.target_branch,
        target_commit=scan.target_commit,
        scanner_id=scan.scanner_id,
        scanner_version=scan.scanner_version,
        operator=scan.operator,
        scan_start=scan.scan_start.isoformat() if scan.scan_start else None,
        scan_end=scan.scan_end.isoformat() if scan.scan_end else None,
        duration_seconds=scan.duration_seconds,
        statistics=_slim_statistics(scan.statistics),
        manifest_hash=scan.manifest_hash,
        error_message=scan.error_message,
    )


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: str | None = None,
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
    ctx: TenantContext = Depends(history_context),
):
    scans, total = repo.list_scans(status=status, page=page, page_size=page_size, owner=ctx.tenant_id)
    return ScanListResponse(
        scans=[_to_response(s) for s in scans],
        total_count=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: str,
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
    ctx: TenantContext = Depends(history_context),
):
    scan = repo.get_by_id(scan_id)
    if scan is None or getattr(scan, "tenant_id", None) != ctx.tenant_id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(scan)


@router.get("/{scan_id}/coverage")
def get_scan_coverage(
    scan_id: str,
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
    db: Session = Depends(get_db_session),
):
    """Scan coverage statement (audit 49 P1#6, round 28): positive AND
    negative evidence, side by side.

    What this records beyond the usual per-finding views:

    * zero-observation file origins — the scanner's origin universe
      (source/test/generated/vendored/archive) with the origins this scan
      found *nothing* in, so absence is visible and queryable;
    * observations per detector, resolved from evidence provenance —
      a detector with zero observations in a scan it participated in is
      the "searched and not found" record.

    Honest edge: a zero can mean "searched, nothing found" or "origin
    did not apply to this target" — the payload says which question a
    zero answers and which it cannot.
    """
    from db.repositories.evidence_repository import EvidenceRepository
    from normalization.calibration import UNATTRIBUTED, detector_key

    scan = repo.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    stats = dict(scan.statistics or {})
    by_origin = dict(stats.get("findings_by_origin") or {})
    try:
        from scanner.core.code_origin import ARCHIVE, GENERATED, SOURCE, TEST, VENDORED
        origin_universe = [SOURCE, TEST, GENERATED, VENDORED, ARCHIVE]
    except Exception:  # noqa: BLE001 — scanner package unavailable in this deploy
        origin_universe = ["source", "test", "generated", "vendored", "archive"]

    origins = []
    for origin in origin_universe:
        count = int(by_origin.get(origin) or 0)
        origins.append({
            "origin": origin,
            "observations": count,
            "zero_observation": count == 0,
        })

    live = EvidenceRepository(db).get_all_for_scan(scan_id, include_deleted=False)
    per_detector: dict[str, int] = {}
    for row in live:
        key = detector_key({
            "scanner_ids": (row.scanner_ids or []) if hasattr(row, "scanner_ids") else [],
            "provenance": row.provenance,
            "finding_data": row.finding_data,
        })
        per_detector[key] = per_detector.get(key, 0) + 1

    total_findings = int(stats.get("total_findings") or 0)
    return {
        "scan_id": scan_id,
        "scanner_id": scan.scanner_id,
        "status": scan.status,
        "files_scanned": int(stats.get("files_scanned") or 0),
        "files_with_crypto": int(stats.get("files_with_crypto") or 0),
        "files_skipped": int(stats.get("files_skipped") or 0),
        "files_with_errors": int(stats.get("files_with_errors") or 0),
        "total_findings": total_findings,
        "origins": origins,
        "detectors": [
            {"detector": name, "observations": per_detector[name]}
            for name in sorted(per_detector)
        ],
        "unattributed_observations": per_detector.get(UNATTRIBUTED, 0),
        "clean_scan": total_findings == 0,
        "method": {
            "zero_interpretation": "a zero-observation origin means the scan "
                                   "recorded nothing there — either nothing "
                                   "was found, or the origin did not apply "
                                   "to this target; the scan statistics "
                                   "(files scanned/skipped) say which "
                                   "files were searched, not which origins "
                                   "were applicable",
            "negative_evidence": "absence is recorded, never inferred: "
                                 "zero rows are surfaced, not assumed from "
                                 "silence",
            "clean_scan_path": "a zero-finding scan feeds the clean-scan "
                               "baseline proposal path (round 23)",
        },
    }


@router.get("/{scan_id}/cascade")
def get_scan_cascade(
    scan_id: str,
    section: Optional[str] = Query(None, description="providers | libraries | shared_keys | weak_parameters | migration_waves | systems | summary"),
    system: Optional[str] = Query(None, description="restrict providers/weak_parameters to one business system (needs cryptoscan-systems.yml)"),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
):
    """Dependency & cascade report of a scan: crypto providers with blast radius, migration waves,
    third-party crypto libraries, shared key material, key sizes below the floor, business-system roll-up."""
    scan = repo.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    cascade = (scan.statistics or {}).get("cascade")
    if not cascade:
        raise HTTPException(status_code=404, detail="No cascade report for this scan (scanner < 1.1 or CRYPTOSCAN_CASCADE=0)")
    if system:
        systems = {s["system"]: s for s in cascade.get("systems") or []}
        if system not in systems:
            raise HTTPException(status_code=404, detail=f"System {system!r} not in this scan's system map")
        from fnmatch import fnmatch

        def _in(path: str) -> bool:
            path = path.split("!", 1)[0]
            return any(path == g.rstrip("/") or path.startswith(g.rstrip("/").removesuffix("/**").removesuffix("/*") + "/") or fnmatch(path, g) for g in systems[system]["paths"])

        cascade = dict(cascade)
        cascade["providers"] = [p for p in cascade.get("providers") or [] if _in(p["file"])]
        cascade["weak_parameters"] = [w for w in cascade.get("weak_parameters") or [] if _in(w["file"])]
        cascade["systems"] = [systems[system]]
    if section:
        if section not in cascade:
            raise HTTPException(status_code=400, detail=f"unknown section {section!r}")
        value = cascade[section]
        return {"scan_id": scan_id, "section": section, "total": len(value) if isinstance(value, list) else None,
                section: value[:limit] if isinstance(value, list) else value}
    out = {"scan_id": scan_id, "summary": cascade.get("summary"), "files_in_graph": cascade.get("files_in_graph"), "edges": cascade.get("edges"),
           "migration_waves": cascade.get("migration_waves"), "systems": cascade.get("systems"), "truncated": cascade.get("truncated")}
    for k in ("providers", "libraries", "package_dependencies", "shared_keys", "key_references", "weak_parameters", "unresolved_relationships"):
        out[k] = (cascade.get(k) or [])[:limit]
    return out


from evidence.intelligence.key_reconciliation import reconcile_key_inventory  # noqa: E402


@router.get("/{scan_id}/key-reconciliation")
def get_key_reconciliation(
    scan_id: str,
    source_scan: Optional[list[str]] = Query(None, description="scan ids of source repositories to reconcile against; default = newest completed scan per target"),
    limit: int = Query(500, ge=1, le=5000),
    user: str = Depends(get_current_user),
    repo: ScanRepository = Depends(get_scan_repository),
    db: Session = Depends(get_db_session),
):
    """Reconcile a key-inventory scan (HSM / KMS / keystore / certificate exports, `CRYPTOSCAN_KEY_INVENTORY=1`)
    with the key identifiers referenced by scanned source: consumers, orphans, and code keys missing from every inventory."""
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan

    scan = repo.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    inventory = [
        safe_finding(row.finding_data or {}) for row in db.query(EvidenceRecord).filter(EvidenceRecord.scan_id == scan_id).all()
        if ((row.finding_data or {}).get("source") or {}).get("type") == "KEY_INVENTORY"
    ]
    if not inventory:
        raise HTTPException(status_code=404, detail="Scan has no KEY_INVENTORY findings (enable CRYPTOSCAN_KEY_INVENTORY=1 on the key-export target)")
    if source_scan:
        sources = [s for s in (repo.get_by_id(sid) for sid in source_scan) if s is not None]
        if len(sources) != len(source_scan):
            raise HTTPException(status_code=404, detail="source_scan not found")
    else:
        sources, seen_targets = [], set()
        for s in db.query(Scan).filter(Scan.status == "COMPLETED", Scan.id != scan_id).order_by(Scan.scan_start.desc()).limit(200).all():
            if s.target_location in seen_targets or not ((s.statistics or {}).get("cascade") or {}).get("key_references"):
                continue
            seen_targets.add(s.target_location)
            sources.append(s)
    refs = [(s.id, r) for s in sources for r in (((s.statistics or {}).get("cascade") or {}).get("key_references") or [])]
    out = reconcile_key_inventory(inventory, refs)
    for k in ("consumers", "orphans", "not_in_inventory"):
        out[k] = out[k][:limit]
    return {"scan_id": scan_id, "source_scans": [{"scan_id": s.id, "target_location": s.target_location} for s in sources], **out}


@router.post("/{scan_id}/retry", response_model=TriggerScanResponse)
def retry_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    user: str = Depends(require_auditor),
    ctx: TenantContext = Depends(get_tenant_context),
    scans: ScanRepository = Depends(get_scan_repository),
    jobs: JobRepository = Depends(get_job_repository),
    db: Session = Depends(get_db_session),
):
    scan = scans.get_by_id(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    # tenant contexts spend plan quota on every scan they trigger (platform
    # estate retries are unmetered)
    if ctx.tenant_id:
        from api.security.tenancy import quota_check
        from db.repositories.tenant_repository import TenantRepository

        t_repo = TenantRepository(db)
        tenant = t_repo.get(ctx.tenant_id)
        allowed, reason = quota_check(
            tenant.plan if tenant else "FREE", "scan_run",
            t_repo.month_usage(ctx.tenant_id, "scan_run"))
        if not allowed:
            raise HTTPException(status_code=402, detail=f"quota_exceeded: {reason}")
        t_repo.record_usage(ctx.tenant_id, "scan_run", 1, detail=f"retry:{scan_id}")
    from api.routers.trigger import enqueue_scan_job

    return enqueue_scan_job(
        jobs,
        background_tasks,
        repo_url=scan.target_location,
        branch=scan.target_branch or "main",
        commit=scan.target_commit,
        triggered_by=user,
        job_type="RETRY",
    )
