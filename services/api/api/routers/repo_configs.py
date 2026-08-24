"""
Repository configurations router.
Manage which repositories are scanned and how.
"""
from __future__ import annotations

import logging
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, HttpUrl

from api.dependencies import get_current_user, get_repo_config_repository
from db.repositories.repo_config_repository import RepoConfigRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/repo-configs", tags=["repo-configurations"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RepoConfigResponse(BaseModel):
    config_id: str
    repo_url: str
    repo_name: str
    enabled: bool
    scan_on_push: bool
    scan_on_pr: bool
    baseline_scan_id: Optional[str]
    notification_emails: List[str]
    created_at: str
    updated_at: Optional[str]


class CreateRepoConfigRequest(BaseModel):
    repo_url: HttpUrl = Field(description="Git repository URL")
    repo_name: str = Field(max_length=200, description="Human-readable repository name")
    enabled: bool = Field(default=True)
    scan_on_push: bool = Field(default=True, description="Auto-scan on push events")
    scan_on_pr: bool = Field(default=False, description="Auto-scan on PR events")
    notification_emails: List[str] = Field(
        default_factory=list,
        description="Email addresses for drift/compliance alerts",
    )


class UpdateRepoConfigRequest(BaseModel):
    enabled: Optional[bool] = None
    scan_on_push: Optional[bool] = None
    scan_on_pr: Optional[bool] = None
    notification_emails: Optional[List[str]] = None


class RepoConfigListResponse(BaseModel):
    items: List[RepoConfigResponse]
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_to_response(c) -> RepoConfigResponse:
    return RepoConfigResponse(
        config_id=str(c.config_id),
        repo_url=c.repo_url,
        repo_name=c.repo_name,
        enabled=c.enabled,
        scan_on_push=c.scan_on_push,
        scan_on_pr=c.scan_on_pr,
        baseline_scan_id=str(c.baseline_scan_id) if c.baseline_scan_id else None,
        notification_emails=c.notification_emails or [],
        created_at=c.created_at.isoformat() if c.created_at else None,
        updated_at=c.updated_at.isoformat() if c.updated_at else None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=RepoConfigListResponse, summary="List repo configurations")
async def list_repo_configs(
    current_user: Annotated[str, Depends(get_current_user)],
    repo_config_repo: RepoConfigRepository = Depends(get_repo_config_repository),
    enabled_only: bool = Query(default=False),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> RepoConfigListResponse:
    offset = (page - 1) * page_size
    configs, total = await repo_config_repo.list_configs(
        enabled_only=enabled_only,
        offset=offset,
        limit=page_size,
    )
    return RepoConfigListResponse(
        items=[_config_to_response(c) for c in configs],
        total=total,
    )


@router.get("/{config_id}", response_model=RepoConfigResponse, summary="Get repo configuration")
async def get_repo_config(
    config_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    repo_config_repo: RepoConfigRepository = Depends(get_repo_config_repository),
) -> RepoConfigResponse:
    config = await repo_config_repo.get_by_id(config_id)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repo configuration {config_id} not found",
        )
    return _config_to_response(config)


@router.post(
    "",
    response_model=RepoConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create repo configuration",
)
async def create_repo_config(
    request_body: CreateRepoConfigRequest,
    current_user: Annotated[str, Depends(get_current_user)],
    repo_config_repo: RepoConfigRepository = Depends(get_repo_config_repository),
) -> RepoConfigResponse:
    """
    Register a repository for CryptoScan monitoring.

    After creation:
    1. Configure the GitHub webhook to point to /webhooks/github
    2. The repo will be automatically scanned on qualifying events
    """
    # Check for duplicate
    existing = await repo_config_repo.get_by_url(str(request_body.repo_url))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Repository already configured: {request_body.repo_url}",
        )

    config = await repo_config_repo.create(
        repo_url=str(request_body.repo_url),
        repo_name=request_body.repo_name,
        enabled=request_body.enabled,
        scan_on_push=request_body.scan_on_push,
        scan_on_pr=request_body.scan_on_pr,
        notification_emails=request_body.notification_emails,
    )

    logger.info(
        "repo_config_created",
        extra={"config_id": str(config.config_id), "repo": str(request_body.repo_url)},
    )
    return _config_to_response(config)


@router.patch(
    "/{config_id}",
    response_model=RepoConfigResponse,
    summary="Update repo configuration",
)
async def update_repo_config(
    config_id: str,
    request_body: UpdateRepoConfigRequest,
    current_user: Annotated[str, Depends(get_current_user)],
    repo_config_repo: RepoConfigRepository = Depends(get_repo_config_repository),
) -> RepoConfigResponse:
    """Partially update a repository configuration."""
    config = await repo_config_repo.get_by_id(config_id)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repo configuration {config_id} not found",
        )

    updates = request_body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No fields to update",
        )

    updated = await repo_config_repo.update(config_id=config_id, updates=updates)
    return _config_to_response(updated)


@router.delete(
    "/{config_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete repo configuration",
)
async def delete_repo_config(
    config_id: str,
    current_user: Annotated[str, Depends(get_current_user)],
    repo_config_repo: RepoConfigRepository = Depends(get_repo_config_repository),
) -> None:
    """Remove a repository from CryptoScan monitoring."""
    config = await repo_config_repo.get_by_id(config_id)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repo configuration {config_id} not found",
        )

    await repo_config_repo.delete(config_id=config_id)
    logger.info(
        "repo_config_deleted",
        extra={"config_id": config_id, "deleted_by": current_user},
    )