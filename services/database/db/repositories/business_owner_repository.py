"""CRUD for business owners."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.business_owner import BusinessOwner
from db.repositories.base_repository import BaseRepository
from db.repositories.intelligence_repository import IntelligenceRepository


class BusinessOwnerRepository(BaseRepository[BusinessOwner]):
    def __init__(self, session: Session):
        super().__init__(BusinessOwner, session)
        self._intel = IntelligenceRepository(session)

    def list_owners(self) -> list[BusinessOwner]:
        return self._intel.list_owners()

    def create_owner(self, **kwargs) -> BusinessOwner:
        return self._intel.create_owner(**kwargs)
