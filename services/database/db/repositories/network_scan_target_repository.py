"""CRUD for scheduled TLS probe targets."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.network_scan_target import NetworkScanTarget
from db.repositories.base_repository import BaseRepository
from db.repositories.intelligence_repository import IntelligenceRepository


class NetworkScanTargetRepository(BaseRepository[NetworkScanTarget]):
    def __init__(self, session: Session):
        super().__init__(NetworkScanTarget, session)
        self._intel = IntelligenceRepository(session)

    def list_targets(self) -> list[NetworkScanTarget]:
        return self._intel.list_targets()

    def upsert(self, endpoint: str, **kwargs) -> NetworkScanTarget:
        return self._intel.upsert_target(endpoint, **kwargs)
