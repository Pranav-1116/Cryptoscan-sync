"""
Baselines router.
Manage approved baseline scans for drift detection.
"""
from __future__ import annotations

import logging
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.dependencies import get_current_user, get_baseline_repository
from db.repositories.baseline_repository import BaselineRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/baselines", tags=["baselines"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class BaselineResponse(BaseModel):
    baseline_id: str
    system_identifier: str
    environment: str
    approved_scan_id: str
    approved_by: str
    approved_at: str
    status: str
    notes: Optional[str]
    created_at: str


class ApproveBaselineRequest(BaseModel):
    scan_id: str = Field(description="The scan_id to approve as baseline")
    system_identifier: str = Field(
        description="Unique identifier for the system (e.g. repo URL)",
        max_length=200,
    )
    environment: str = Field(
        default="production",
        description="Environment: production, staging, dev",
        max_length=50,
    )
    notes: Optional[str] = Field(
        default=None,
        description="Human-readable notes for the approval",
        max_length=2000,
    )


class BaselineListResponse(BaseModel):
    items: List[BaselineResponse]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _baseline_to_response(b) -> BaselineResponse:
    return BaselineResponse(
        baseline_id=str(b.baseline_id),
        system_identifier=b.system_identifier,
        environment=b.environment,
        approved_scan_id=str(b.approved_scan_id),
        approved_by=b.approved_by,
        approved_at=b.approved_at.isoformat() if b.approved_at else None,
        status=b.status,
        notes=b.notes,
        created_at=b.created_at.isoformat() if b.created_at else None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=BaselineListResponse,
    summary="List approved baselines",
)
async def list_baselines(
    current_user: Annotated[str, Depends(get_current_user)],
    baseline_repo: BaselineRepository = Depends(get_baseline_repository),
    system_identifier: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> BaselineListResponse:
    """List all approved baseline scans, optionally filtered by system/environment."""
    offset = (page - 1) * page_size
    baselines, total = await baseline_repo.list_baselines(
        system_identifier=system_identifier,
        environment=environment,
        offset=offset,
        limit=page_size,
    )
    return BaselineListResponse(
        items=[_baseline_to_response(b) for b in baselines],
        total=total,
    )


@router.get(
    "/{baseline_id}",
    response_model=BaselineResponse,
    summary="Get baseline detail",
)
async def get_baseline(
    baseline_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    baseline_repo: BaselineRepository = Depends(get_baseline_repository),
) -> BaselineResponse:
    """Get a specific baseline by ID."""
    baseline = await baseline_repo.get_by_id(baseline_id)
    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline {baseline_id} not found",
        )
    return _baseline_to_response(baseline)


@router.post(
    "",
    response_model=BaselineResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Approve a scan as baseline",
)
async def approve_baseline(
    request_body: ApproveBaselineRequest,
    current_user: Annotated[str, Depends(get_current_user)],
    baseline_repo: BaselineRepository = Depends(get_baseline_repository),
) -> BaselineResponse:
    """
    Approve a completed scan as the reference baseline for a system.

    This action:
    1. Supersedes any existing ACTIVE baseline for the same system+environment
    2. Creates a new ACTIVE baseline record
    3. Future scans of this system will be compared against this baseline

    Requires: Authenticated user (approval is recorded in audit trail)
    """
    # Supersede existing active baseline
    await baseline_repo.supersede_active(
        system_identifier=request_body.system_identifier,
        environment=request_body.environment,
    )

    baseline = await baseline_repo.create(
        scan_id=request_body.scan_id,
        system_identifier=request_body.system_identifier,
        environment=request_body.environment,
        approved_by=current_user,
        notes=request_body.notes,
    )

    logger.info(
        "baseline_approved",
        extra={
            "baseline_id": str(baseline.baseline_id),
            "scan_id": request_body.scan_id,
            "system": request_body.system_identifier,
            "approved_by": current_user,
        },
    )

    return _baseline_to_response(baseline)


@router.delete(
    "/{baseline_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a baseline",
)
async def revoke_baseline(
    baseline_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    baseline_repo: BaselineRepository = Depends(get_baseline_repository),
) -> None:
    """
    Revoke (supersede) a baseline.
    The baseline record is retained for audit purposes but status becomes SUPERSEDED.
    """
    baseline = await baseline_repo.get_by_id(baseline_id)
    if baseline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline {baseline_id} not found",
        )

    await baseline_repo.set_status(baseline_id=baseline_id, new_status="SUPERSEDED")
    logger.info(
        "baseline_revoked",
        extra={"baseline_id": baseline_id, "revoked_by": current_user},
    )