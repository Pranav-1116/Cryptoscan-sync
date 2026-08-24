from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class TriggerScanRequest(BaseModel):
    repo_url: str = Field(..., min_length=1)
    branch: Optional[str] = "main"
    commit: Optional[str] = None
    scan_type: Optional[str] = "GIT_REPOSITORY"

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: str) -> str:
        raw = value.strip()
        if not raw:
            raise ValueError("repo_url is required")
        ok = (
            raw.startswith(("http://", "https://", "git@", "local://", "file://", "/"))
            or raw.startswith("ssh://")
            or raw.endswith(".git")
        )
        if not ok:
            raise ValueError("repo_url must be a git URL, local:// path, or absolute path")
        return raw


class TriggerScanResponse(BaseModel):
    job_id: str
    status: str
    created_at: str
    message: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: str
    job_type: str | None = None
    target_repo: str | None = None
    target_branch: str | None = None
    target_commit: str | None = None
    scan_id: str | None = None
    error_message: str | None = None
    created_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    progress: dict | None = None
