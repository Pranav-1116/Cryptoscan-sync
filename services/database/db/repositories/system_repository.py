"""System inventory persistence."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.models.system_dependency import SystemDependency
from db.repositories.base_repository import BaseRepository


class SystemRepository(BaseRepository[System]):
    def __init__(self, session: Session):
        super().__init__(System, session)

    def list_systems(self, page: int = 1, page_size: int = 50) -> tuple[list[System], int]:
        total = int(self.session.execute(select(func.count()).select_from(System)).scalar_one())
        stmt = select(System).order_by(System.name).offset((page - 1) * page_size).limit(page_size)
        return list(self.session.execute(stmt).scalars().all()), total

    def get_by_name(self, name: str) -> System | None:
        return self.session.execute(select(System).where(System.name == name)).scalar_one_or_none()

    def attach_asset(self, system_id: str, asset_id: str) -> SystemAsset:
        existing = self.session.execute(
            select(SystemAsset).where(SystemAsset.system_id == system_id, SystemAsset.asset_id == asset_id)
        ).scalar_one_or_none()
        if existing:
            return existing
        link = SystemAsset(system_id=system_id, asset_id=asset_id)
        self.session.add(link)
        self.session.flush()
        return link

    def assets_for(self, system_id: str) -> list[CryptoAsset]:
        stmt = (
            select(CryptoAsset)
            .join(SystemAsset, SystemAsset.asset_id == CryptoAsset.id)
            .where(SystemAsset.system_id == system_id)
        )
        return list(self.session.execute(stmt).scalars().all())

    def add_dependency(self, parent_id: str, child_id: str, relation: str | None = None) -> SystemDependency:
        existing = self.session.execute(
            select(SystemDependency).where(
                SystemDependency.parent_id == parent_id,
                SystemDependency.child_id == child_id,
            )
        ).scalar_one_or_none()
        if existing:
            return existing
        edge = SystemDependency(parent_id=parent_id, child_id=child_id, relation=relation)
        self.session.add(edge)
        self.session.flush()
        return edge

    def dependencies_for(self, system_id: str) -> list[SystemDependency]:
        stmt = select(SystemDependency).where(SystemDependency.parent_id == system_id)
        return list(self.session.execute(stmt).scalars().all())
