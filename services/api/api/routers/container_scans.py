"""Spec-named container scan endpoints (`/container-scans`)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.routers.container import _persist
from container_scanner.core.scanner import ContainerScanner
from container_scanner.image.puller import ImagePullError
from db.models.container_scan import ContainerScan

router = APIRouter(prefix="/container-scans", tags=["container-scans"])


class ContainerScanRequest(BaseModel):
    path: str | None = None
    image: str | None = None
    archive: str | None = None
    scan_id: str | None = None
    live_cve: bool = True


@router.post("")
@router.post("/")
@router.post("/scan")
def trigger_container_scan(
    body: ContainerScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    if not (body.path or body.image or body.archive):
        raise HTTPException(status_code=422, detail="path, image, or archive is required")
    scanner = ContainerScanner(live_cve=body.live_cve)
    try:
        if body.archive or body.image:
            result = scanner.scan(image=body.image, archive=body.archive, scan_id=body.scan_id)
        else:
            target = Path(body.path or "")
            if not target.exists():
                raise HTTPException(status_code=404, detail="Container filesystem not found")
            result = scanner.scan_filesystem(target, scan_id=body.scan_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ImagePullError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    row = _persist(db, result)
    return {"id": row.id, **result}


@router.get("")
@router.get("/", operation_id="list_container_scans_trailing_slash_api_v1_container_scans_get")
def list_container_scans(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """List recent container scans.

    Both routes hit this handler (with and without the trailing slash); the
    second carries an explicit ``operation_id`` because FastAPI derives the
    same one for both, and a duplicate operationId breaks generated clients
    and the OpenAPI contract (audit 11).
    """
    from sqlalchemy import select

    rows = list(db.execute(select(ContainerScan).order_by(ContainerScan.created_at.desc()).limit(50)).scalars())
    return {"scans": [row.to_dict() | {"result": row.result} for row in rows], "total_count": len(rows)}
