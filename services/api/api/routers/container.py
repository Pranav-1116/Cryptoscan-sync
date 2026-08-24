"""On-demand container / image-root scans."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from container_scanner.core.scanner import ContainerScanner
from db.models.container_scan import ContainerScan
from db.repositories.vulnerability_repository import VulnerabilityRepository

router = APIRouter(prefix="/container", tags=["container"])


class ContainerScanRequest(BaseModel):
    path: str
    scan_id: str | None = None


@router.post("/scan")
def scan_container(
    body: ContainerScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    target = Path(body.path)
    if not target.exists():
        raise HTTPException(status_code=404, detail="Container filesystem not found")
    result = ContainerScanner().scan_filesystem(target, scan_id=body.scan_id)
    row = ContainerScan(
        scan_id=result["scan_id"],
        target=str(target),
        package_count=len(result.get("packages") or []),
        library_count=len(result.get("libraries") or []),
        vuln_count=len(result.get("vulnerabilities") or []),
        result=result,
    )
    db.add(row)
    if result.get("vulnerabilities"):
        VulnerabilityRepository(db).replace_for_scan(result["scan_id"], result["vulnerabilities"])
    db.flush()
    return {"id": row.id, **result}


@router.get("/scans")
def list_container_scans(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from sqlalchemy import select

    rows = list(db.execute(select(ContainerScan).order_by(ContainerScan.created_at.desc()).limit(50)).scalars())
    return {"scans": [row.to_dict() | {"result": row.result} for row in rows]}
