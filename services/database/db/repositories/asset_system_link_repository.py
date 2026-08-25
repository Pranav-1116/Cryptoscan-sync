"""CRUD for asset ↔ system links."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.system_asset import SystemAsset
from db.repositories.base_repository import BaseRepository
from db.repositories.system_repository import SystemRepository


class AssetSystemLinkRepository(BaseRepository[SystemAsset]):
    def __init__(self, session: Session):
        super().__init__(SystemAsset, session)
        self._systems = SystemRepository(session)

    def attach(self, system_id: str, asset_id: str) -> SystemAsset:
        return self._systems.attach_asset(system_id, asset_id)

    def assets_for(self, system_id: str):
        return self._systems.assets_for(system_id)
