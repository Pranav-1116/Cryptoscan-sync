"""Tenant-safe persistence for network inventory revisions."""
from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from db.models.network_inventory import NetworkInventoryRevision


class NetworkInventoryRepository:
    def __init__(self, session: Session):
        self.session = session

    def latest(self, inventory_id: str = "default") -> NetworkInventoryRevision | None:
        return self.session.execute(
            select(NetworkInventoryRevision)
            .where(NetworkInventoryRevision.inventory_id == inventory_id)
            .order_by(desc(NetworkInventoryRevision.revision))
            .limit(1)
        ).scalars().first()

    def history(self, inventory_id: str = "default", limit: int = 50) -> list[NetworkInventoryRevision]:
        return list(self.session.execute(
            select(NetworkInventoryRevision)
            .where(NetworkInventoryRevision.inventory_id == inventory_id)
            .order_by(desc(NetworkInventoryRevision.revision))
            .limit(limit)
        ).scalars())

    def create_revision(self, inventory_id: str = "default", **values) -> NetworkInventoryRevision:
        current = self.latest(inventory_id)
        revision = current.revision + 1 if current else 1
        row = NetworkInventoryRevision(inventory_id=inventory_id, revision=revision, **values)
        self.session.add(row)
        self.session.flush()
        return row
