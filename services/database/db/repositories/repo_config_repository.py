"""Repo configuration repository."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.repo_configuration import RepoConfiguration
from db.repositories.base_repository import BaseRepository


class RepoConfigRepository(BaseRepository[RepoConfiguration]):
    def __init__(self, session: Session):
        super().__init__(RepoConfiguration, session)

    def get_by_url(self, repo_url: str) -> RepoConfiguration | None:
        stmt = select(RepoConfiguration).where(RepoConfiguration.repo_url == repo_url)
        return self.session.execute(stmt).scalar_one_or_none()

    def is_allowed(self, repo_url: str) -> bool:
        cfg = self.get_by_url(repo_url)
        if cfg is None:
            # Allow all in development when no configs exist
            any_cfg = self.session.execute(select(RepoConfiguration).limit(1)).scalar_one_or_none()
            return any_cfg is None
        return bool(cfg.enabled and cfg.scan_on_push)
