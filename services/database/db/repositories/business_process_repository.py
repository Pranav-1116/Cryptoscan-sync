"""CRUD for revenue-bearing business processes."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.business_process import BusinessProcess
from db.models.system_business_process import SystemBusinessProcess
from db.repositories.base_repository import BaseRepository
from db.repositories.intelligence_repository import IntelligenceRepository


class BusinessProcessRepository(BaseRepository[BusinessProcess]):
    def __init__(self, session: Session):
        super().__init__(BusinessProcess, session)
        self._intel = IntelligenceRepository(session)

    def list_processes(self) -> list[BusinessProcess]:
        return self._intel.list_processes()

    def create_process(self, **kwargs) -> BusinessProcess:
        return self._intel.create_process(**kwargs)

    def link_process(self, system_id: str, process_id: str, role: str | None = "PRIMARY") -> SystemBusinessProcess:
        return self._intel.link_process(system_id, process_id, role)

    def process_system_ids(self, process_id: str) -> list[str]:
        return self._intel.process_system_ids(process_id)
