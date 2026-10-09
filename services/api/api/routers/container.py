"""On-demand container / image / archive scans."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from container_scanner.core.scanner import ContainerScanner
from container_scanner.image.puller import ImagePullError
from db.models.container_scan import ContainerScan
from db.repositories.vulnerability_repository import VulnerabilityRepository

router = APIRouter(prefix="/container", tags=["container"])


class ContainerScanRequest(BaseModel):
    path: str | None = None
    image: str | None = None
    archive: str | None = None
    scan_id: str | None = None
    live_cve: bool = True


def _persist(db: Session, result: dict) -> ContainerScan:
    row = ContainerScan(
        scan_id=result["scan_id"],
        target=str(result.get("target") or ""),
        package_count=len(result.get("packages") or []),
        library_count=len(result.get("libraries") or []),
        vuln_count=len(result.get("vulnerabilities") or []),
        result=result,
    )
    db.add(row)
    if result.get("vulnerabilities"):
        VulnerabilityRepository(db).replace_for_scan(result["scan_id"], result["vulnerabilities"])
    db.flush()
    return row


@router.post("/scan")
def scan_container(
    body: ContainerScanRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    if not (body.path or body.image or body.archive):
        raise HTTPException(status_code=422, detail="path, image, or archive is required")
    scanner = ContainerScanner(live_cve=body.live_cve)
    try:
        if body.archive or body.image:
            result = scanner.scan(
                image=body.image,
                archive=body.archive,
                scan_id=body.scan_id,
            )
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


def _previous_run_for_target(db: Session, row: ContainerScan) -> ContainerScan | None:
    """The most recent stored scan for the same target that is OLDER than ``row``."""
    from sqlalchemy import select

    stmt = (
        select(ContainerScan)
        .where(ContainerScan.target == row.target)
        .order_by(ContainerScan.created_at.desc(), ContainerScan.id.desc())
    )
    rows = list(db.execute(stmt).scalars())
    ids = [item.id for item in rows]
    if row.id not in ids:
        return None
    older = rows[ids.index(row.id) + 1 :]
    return older[0] if older else None


def _run_by_scan_id(db: Session, scan_id: str) -> ContainerScan | None:
    from sqlalchemy import select

    stmt = select(ContainerScan).where(ContainerScan.scan_id == scan_id).limit(1)
    return db.execute(stmt).scalars().first()


@router.get("/scans/{scan_id}")
def get_container_scan(scan_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Fetch one stored container scan (full result payload)."""
    row = _run_by_scan_id(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return {"id": row.id, **(row.result or {})}


@router.get("/scans/{scan_id}/sbom")
def container_scan_sbom(scan_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """CycloneDX 1.5 SBOM for a stored scan."""
    from container_scanner.reports.sbom import build_sbom

    row = _run_by_scan_id(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return build_sbom(row.result or {})


@router.get("/scans/{scan_id}/spdx")
def container_scan_spdx(scan_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """SPDX 2.3 SBOM for a stored scan."""
    from container_scanner.reports.spdx import build_spdx

    row = _run_by_scan_id(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return build_spdx(row.result or {})


@router.get("/scans/{scan_id}/metrics")
def container_scan_metrics(scan_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Prometheus text for a stored scan."""
    from fastapi.responses import Response

    from container_scanner.reports.metrics import CONTENT_TYPE, render_prometheus

    row = _run_by_scan_id(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return Response(content=render_prometheus(row.result or {}), media_type=CONTENT_TYPE)


@router.get("/scans/{scan_id}/drift")
def container_scan_drift(scan_id: str, user: str = Depends(get_current_user), db: Session = Depends(get_db_session)):
    """Drift between this stored scan and the previous one for the same target."""
    from container_scanner.reports.scan_drift import diff_scans

    row = _run_by_scan_id(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="scan not found")
    previous = _previous_run_for_target(db, row)
    if previous is None:
        return {
            "verdict": "UNCHANGED",
            "change_count": 0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            "summary": {},
            "headline": None,
            "changes": [],
            "detail": "no earlier stored scan for this target; drift needs two",
        }
    report = diff_scans(previous.result or {}, row.result or {})
    report["previous_scan_id"] = previous.scan_id
    report["current_scan_id"] = row.scan_id
    return report


@router.post("/sbom")
def render_sbom(body: dict, user: str = Depends(get_current_user)):
    """CycloneDX SBOM from an inline scan result (no storage round-trip)."""
    from container_scanner.reports.sbom import build_sbom

    return build_sbom(body.get("result") or body)


@router.get("/scans")
def list_container_scan_history(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Container scan history (alias of GET /container-scans).

    Renamed from ``list_container_scans`` (same path, same behavior): the old
    name collided with the ``container_scans`` router's function — FastAPI
    derives operationIds from function name + path, and ``/container/scans``
    and ``/container-scans`` normalize to the same id
    (``list_container_scans_api_v1_container_scans_get``), which breaks
    generated OpenAPI clients (audit 11's contract-testing gap).
    """
    from sqlalchemy import select

    rows = list(db.execute(select(ContainerScan).order_by(ContainerScan.created_at.desc()).limit(50)).scalars())
    return {"scans": [row.to_dict() | {"result": row.result} for row in rows]}
