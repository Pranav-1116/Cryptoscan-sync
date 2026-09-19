"""Repository configuration CRUD."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies import get_current_user, get_repo_config_repository
from db.models.repo_configuration import RepoConfiguration
from db.repositories.repo_config_repository import RepoConfigRepository

router = APIRouter(prefix="/repos", tags=["repos"])


class RepoBody(BaseModel):
    repo_url: str
    repo_name: str
    enabled: bool = True
    scan_on_push: bool = True
    scan_on_pr: bool = True


@router.get("")
def list_repos(user: str = Depends(get_current_user), repo: RepoConfigRepository = Depends(get_repo_config_repository)):
    return [
        {
            "config_id": r.id,
            "repo_url": r.repo_url,
            "repo_name": r.repo_name,
            "enabled": r.enabled,
            "scan_on_push": r.scan_on_push,
        }
        for r in repo.get_all(limit=200)
    ]


@router.post("")
def create_repo(
    body: RepoBody,
    user: str = Depends(get_current_user),
    repo: RepoConfigRepository = Depends(get_repo_config_repository),
):
    if repo.get_by_url(body.repo_url):
        raise HTTPException(status_code=409, detail="Repository already configured")
    created = repo.create(
        RepoConfiguration(
            repo_url=body.repo_url,
            repo_name=body.repo_name,
            enabled=body.enabled,
            scan_on_push=body.scan_on_push,
            scan_on_pr=body.scan_on_pr,
        )
    )
    return {"config_id": created.id, "repo_url": created.repo_url}
