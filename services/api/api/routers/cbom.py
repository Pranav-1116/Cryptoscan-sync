"""CycloneDX 1.5 CBOM service endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from cbom.generator import CbomGenerator
from db.models.scan import Scan
from db.repositories.asset_repository import AssetRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.system_repository import SystemRepository

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


@router.get("/scan/{scan_id}")
def cbom_for_scan(
    scan_id: str,
    fmt: str = Query("json"),
    signed: bool = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = EvidenceRepository(db).get_all_for_scan(scan_id)
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
    repo = SystemRepository(db)
    system = repo.get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    assets = repo.assets_for(system_id)
    bom = CbomGenerator().from_records(assets, name=system.name, version=system.environment or "unknown")
    return _render(bom, fmt, signed)


class CustomCbomRequest(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)
    include_vulnerabilities: bool = True
    include_evidence: bool = True
    name: str = "custom-selection"


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
            from db.repositories.vulnerability_repository import VulnerabilityRepository

            rows, _ = VulnerabilityRepository(db).list_vulns(page=1, page_size=200)
            vulns = [item.to_dict() if hasattr(item, "to_dict") else item for item in rows]
        except Exception:
            vulns = None
    bom = CbomGenerator().from_records(records, name=body.name, vulnerabilities=vulns)
    return _render(bom, fmt, signed)
