"""CycloneDX 1.5 CBOM catalog, export, ingest, and comparison."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_job_repository
from api.schemas.cbom_schemas import CustomCbomRequest, DiffCbomRequest, IngestCbomRequest
from cbom.generator import CbomGenerator
from cbom.inventory import (
    bom_system_name,
    diff_records,
    records_from_bom,
    search_records,
    summarize_records,
    validate_document,
)
from db.models.scan import Scan
from db.repositories.asset_repository import AssetRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.scan_repository import ScanRepository
from db.repositories.system_repository import SystemRepository
from db.repositories.vulnerability_repository import VulnerabilityRepository

router = APIRouter(prefix="/cbom", tags=["cbom"])


def _render(bom: dict, fmt: str, signed: bool):
    generator = CbomGenerator()
    if signed:
        from api.config.settings import get_settings

        secret = getattr(get_settings(), "SECRET_KEY", None) or "cryptoscan-dev"
        bom = generator.sign(bom, secret)
    if fmt == "xml":
        return Response(content=generator.to_xml(bom), media_type="application/xml")
    return JSONResponse(bom)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _located_assets(db: Session) -> list[dict[str, Any]]:
    systems, _ = SystemRepository(db).list_systems(page=1, page_size=1000)
    seen: set[str] = set()
    located: list[dict[str, Any]] = []
    sys_repo = SystemRepository(db)
    for system in systems:
        for asset in sys_repo.assets_for(system.id):
            seen.add(asset.id)
            data = asset.to_dict()
            data["system_id"] = system.id
            data["system_name"] = system.name
            located.append(data)
    assets, _ = AssetRepository(db).list_assets(page=1, page_size=5000)
    for asset in assets:
        if asset.id in seen:
            continue
        data = asset.to_dict()
        data["system_id"] = None
        data["system_name"] = "unassigned"
        located.append(data)
    return located


def _records_for_system(db: Session, system_id: str) -> tuple[Any, list[Any]]:
    repo = SystemRepository(db)
    system = repo.get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return system, repo.assets_for(system_id)


def _records_for_scan(db: Session, scan_id: str) -> tuple[Scan, list[Any]]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan, EvidenceRepository(db).get_all_for_scan(scan_id)


def _resolve_ref(db: Session, ref) -> tuple[str, str | None, list[Any]]:
    if ref.bom is not None:
        check = validate_document(ref.bom)
        if not check["ok"]:
            raise HTTPException(status_code=422, detail="; ".join(check["errors"]))
        return bom_system_name(ref.bom), None, records_from_bom(ref.bom)
    if ref.system_id:
        system, records = _records_for_system(db, ref.system_id)
        return system.name, system.id, records
    if ref.scan_id:
        scan, records = _records_for_scan(db, ref.scan_id)
        return scan.target_location, scan.id, records
    raise HTTPException(status_code=422, detail="Provide system_id, scan_id, or bom")


@router.get("")
@router.get("/")
def cbom_catalog(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    coverage: str | None = None,
    q: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    sys_repo = SystemRepository(db)
    systems, system_total = sys_repo.list_systems(page=page, page_size=page_size, coverage=coverage, q=q)
    catalog = [sys_repo.catalog_row(system) for system in systems]
    coverage_totals = sys_repo.coverage_summary()
    algorithms = AssetRepository(db).algorithm_counts()
    scans, scan_total = ScanRepository(db).list_scans(page=1, page_size=20)
    scan_sources = []
    for scan in scans:
        stats = scan.statistics if isinstance(scan.statistics, dict) else {}
        scan_sources.append(
            {
                "source_type": "scan",
                "source_id": scan.id,
                "name": scan.target_location,
                "status": scan.status,
                "components": stats.get("total_findings"),
                "scanned_at": _iso(getattr(scan, "scan_start", None) or getattr(scan, "created_at", None)),
                "spec": "CycloneDX 1.5",
            }
        )
    return {
        "spec": "CycloneDX 1.5",
        "systems": catalog,
        "scans": scan_sources,
        "page": page,
        "page_size": page_size,
        "coverage": coverage_totals,
        "totals": {
            "systems": system_total,
            "scans": scan_total,
            "components": sum(int(item.get("components") or 0) for item in catalog),
            "unknown_crypto": coverage_totals.get("unknown_crypto"),
            "with_cbom": coverage_totals.get("with_cbom"),
            "coverage_pct": coverage_totals.get("coverage_pct"),
            "algorithms": algorithms,
        },
    }


@router.get("/coverage")
def cbom_coverage(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return SystemRepository(db).coverage_summary()


class ScanUncoveredRequest(BaseModel):
    limit: int = 25


@router.post("/scan-uncovered")
def cbom_scan_uncovered(
    background_tasks: BackgroundTasks,
    body: ScanUncoveredRequest | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs=Depends(get_job_repository),
):
    from api.routers.trigger import enqueue_scan_job

    from cloud_scanner.estate import CAMPAIGN_LOOKAHEAD, plan_campaign

    limit = min(max(int((body.limit if body else 25) or 25), 1), 100)
    lookahead = min(max(limit * 40, 200), CAMPAIGN_LOOKAHEAD)
    planned = plan_campaign(SystemRepository(db).list_uncovered(limit=lookahead), limit=limit)
    queued = []
    skipped = []
    for item in planned:
        target = (item.get("target") or "").strip()
        if not target:
            skipped.append({"id": item.get("system_id"), "name": item.get("name"), "reason": "no_target"})
            continue
        result = enqueue_scan_job(
            jobs,
            background_tasks,
            repo_url=target,
            branch=item.get("branch") or "main",
            triggered_by=user,
            job_type=item.get("job_type") or "COVERAGE",
            system_id=item.get("system_id"),
        )
        queued.append({**item, "job_id": result.job_id})
    remaining = max(0, int(SystemRepository(db).coverage_summary().get("scannable") or 0) - len(queued))
    git_n = sum(1 for item in queued if item.get("job_type") != "CLOUD")
    cloud_n = sum(1 for item in queued if item.get("job_type") == "CLOUD")
    return {
        "queued": len(queued),
        "git_jobs": git_n,
        "cloud_jobs": cloud_n,
        "skipped": skipped,
        "remaining": remaining,
        "jobs": queued,
        "message": (
            f"Queued {git_n} git scans and {cloud_n} cloud account inventories. "
            "Cryptography stays unknown on systems that have not been scanned."
        ),
    }


@router.get("/portfolio")
def cbom_portfolio(
    fmt: str = Query("json"),
    signed: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    records = _located_assets(db)
    bom = CbomGenerator().from_records(
        records,
        name="cryptoscan-portfolio",
        version="aggregate",
        metadata_properties=[
            {"name": "cryptoscan:scope", "value": "estate"},
            {"name": "cryptoscan:systems", "value": str(len({row.get("system_id") for row in records if row.get("system_id")}))},
        ],
    )
    return _render(bom, fmt, signed)


@router.get("/search")
def cbom_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(200, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    located = AssetRepository(db).search_located(q, limit=limit)
    hits = search_records(located, q, limit=limit)
    return {"query": q, "total_count": len(hits), "matches": hits}


@router.post("/validate")
def cbom_validate(
    body: IngestCbomRequest,
    user: str = Depends(get_current_user),
):
    document = validate_document(body.bom)
    crypto = records_from_bom(body.bom)
    return {
        **document,
        "crypto_components": len(crypto),
        "name": bom_system_name(body.bom),
    }


@router.post("/ingest")
def cbom_ingest(
    body: IngestCbomRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    check = validate_document(body.bom)
    if not check["ok"]:
        raise HTTPException(status_code=422, detail="; ".join(check["errors"]))
    records = records_from_bom(body.bom)
    if not records:
        raise HTTPException(status_code=422, detail="No cryptographic components in document")
    name = (body.system_name or bom_system_name(body.bom)).strip()
    if not name:
        raise HTTPException(status_code=422, detail="system_name is required")
    sys_repo = SystemRepository(db)
    system = sys_repo.get_or_create(
        name,
        owner=body.owner,
        environment=body.environment,
        description="Imported from CycloneDX CBOM",
    )
    extra = dict(system.extra or {})
    extra["cbom"] = {
        "spec_version": body.bom.get("specVersion"),
        "serial_number": body.bom.get("serialNumber"),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "component_count": len(records),
        "source": "ingest",
    }
    system.extra = extra
    stored = AssetRepository(db).replace_for_scan(
        f"cbom-ingest:{system.id}",
        [
            {
                "algorithm": item["algorithm"],
                "purpose": item.get("purpose"),
                "mode": item.get("mode"),
                "key_size": item.get("key_size"),
                "file_path": item.get("file_path") or f"cbom://{item.get('name') or item['algorithm']}",
                "line_number": int(item.get("line_number") or 0),
                "confidence": "HIGH",
                "scanner_ids": ["cbom-ingest"],
                "libraries": [],
                "dedup_key": item.get("id"),
            }
            for item in records
        ],
    )
    for asset in stored:
        sys_repo.attach_asset(system.id, asset.id)
    sys_repo.stamp_scan(
        system.id,
        scan_id=None,
        status="CURRENT",
        component_count=len(stored),
        algorithms={item["algorithm"]: 1 for item in records},
    )
    summary = summarize_records(
        stored,
        source_type="system",
        source_id=system.id,
        name=system.name,
        environment=system.environment,
    )
    return {"system": system.to_dict(), "imported": len(stored), "summary": summary}


@router.post("/diff")
def cbom_diff(
    body: DiffCbomRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    left_name, left_id, left_records = _resolve_ref(db, body.left)
    right_name, right_id, right_records = _resolve_ref(db, body.right)
    result = diff_records(left_records, right_records)
    result["left"] = {"name": left_name, "source_id": left_id, "components": len(left_records)}
    result["right"] = {"name": right_name, "source_id": right_id, "components": len(right_records)}
    return result


@router.get("/scan/{scan_id}")
def cbom_for_scan(
    scan_id: str,
    fmt: str = Query("json"),
    signed: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    scan, rows = _records_for_scan(db, scan_id)
    bom = CbomGenerator().from_records(
        rows,
        name=scan.target_location,
        version=scan.target_commit or scan.target_branch or "unknown",
        tool_version=scan.scanner_version,
    )
    return _render(bom, fmt, signed)


@router.get("/system/{system_id}")
def cbom_for_system(
    system_id: str,
    fmt: str = Query("json"),
    signed: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    system, assets = _records_for_system(db, system_id)
    records = []
    for asset in assets:
        data = asset.to_dict() if hasattr(asset, "to_dict") else {"algorithm": getattr(asset, "algorithm", "UNKNOWN")}
        data["system_id"] = system.id
        data["system_name"] = system.name
        records.append(data)
    bom = CbomGenerator().from_records(records, name=system.name, version=system.environment or "unknown")
    return _render(bom, fmt, signed)


@router.post("/custom")
def cbom_custom(
    body: CustomCbomRequest,
    fmt: str = Query("json"),
    signed: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    if not body.asset_ids:
        raise HTTPException(status_code=422, detail="asset_ids is required")
    repo = AssetRepository(db)
    records = []
    missing = []
    for asset_id in body.asset_ids:
        row = repo.get_by_id(asset_id)
        if row is None:
            missing.append(asset_id)
            continue
        payload = row.to_dict() if hasattr(row, "to_dict") else {
            "id": getattr(row, "id", asset_id),
            "algorithm": getattr(row, "algorithm", "UNKNOWN"),
            "mode": getattr(row, "mode", None),
            "key_size": getattr(row, "key_size", None),
            "purpose": getattr(row, "purpose", None),
            "file_path": getattr(row, "file_path", None),
            "line_number": getattr(row, "line_number", None),
        }
        if body.include_evidence and hasattr(row, "evidence_links"):
            payload["evidence_ids"] = [link.evidence_id for link in row.evidence_links]
        records.append(payload)
    if missing and not records:
        raise HTTPException(status_code=404, detail=f"Assets not found: {missing}")
    vulns = None
    if body.include_vulnerabilities:
        try:
            rows, _ = VulnerabilityRepository(db).list_vulns(page=1, page_size=200)
            vulns = [item.to_dict() if hasattr(item, "to_dict") else item for item in rows]
        except Exception:
            vulns = None
    bom = CbomGenerator().from_records(records, name=body.name, vulnerabilities=vulns)
    return _render(bom, fmt, signed)
