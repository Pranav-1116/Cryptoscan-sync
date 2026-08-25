"""CRUD for vendors and system-vendor links."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.vendor import SystemVendor, Vendor
from db.repositories.base_repository import BaseRepository
from db.repositories.intelligence_repository import IntelligenceRepository


class VendorRepository(BaseRepository[Vendor]):
    def __init__(self, session: Session):
        super().__init__(Vendor, session)
        self._intel = IntelligenceRepository(session)

    def list_vendors(self) -> list[Vendor]:
        return self._intel.list_vendors()

    def create_vendor(self, name: str, criticality: str | None = None, **kwargs) -> Vendor:
        return self._intel.create_vendor(name, criticality=criticality, **kwargs)

    def get_vendor(self, vendor_id: str) -> Vendor | None:
        return self._intel.get_vendor(vendor_id)

    def update_vendor(self, vendor_id: str, **kwargs) -> Vendor | None:
        return self._intel.update_vendor(vendor_id, **kwargs)

    def link_vendor(self, system_id: str, vendor_id: str) -> SystemVendor:
        return self._intel.link_vendor(system_id, vendor_id)

    def vendor_system_ids(self, vendor_id: str) -> list[str]:
        return self._intel.vendor_system_ids(vendor_id)
