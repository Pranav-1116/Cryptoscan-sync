"""CRUD for registered cloud accounts."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.cloud_account import CloudAccount
from db.repositories.base_repository import BaseRepository
from db.repositories.intelligence_repository import IntelligenceRepository


class CloudAccountRepository(BaseRepository[CloudAccount]):
    def __init__(self, session: Session):
        super().__init__(CloudAccount, session)
        self._intel = IntelligenceRepository(session)

    def list_accounts(self) -> list[CloudAccount]:
        return self._intel.list_cloud_accounts()

    def create_account(self, **kwargs) -> CloudAccount:
        return self._intel.create_cloud_account(**kwargs)
