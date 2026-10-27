"""Tenant-safe persistence for vendor due-diligence profile revisions."""
from __future__ import annotations

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from db.models.vendor import Vendor
from db.models.vendor_profile import VendorProfileRevision


class VendorProfileRepository:
    def __init__(self, session: Session):
        self.session = session

    def latest(self, vendor_id: str) -> VendorProfileRevision | None:
        return self.session.execute(
            select(VendorProfileRevision)
            .where(VendorProfileRevision.vendor_id == vendor_id)
            .order_by(desc(VendorProfileRevision.revision))
            .limit(1)
        ).scalars().first()

    def history(self, vendor_id: str, limit: int = 50) -> list[VendorProfileRevision]:
        return list(self.session.execute(
            select(VendorProfileRevision)
            .where(VendorProfileRevision.vendor_id == vendor_id)
            .order_by(desc(VendorProfileRevision.revision))
            .limit(limit)
        ).scalars())

    def create_revision(self, vendor_id: str, **values) -> VendorProfileRevision:
        # The ORM tenant guard applies here as well as in the API. Do not rely
        # on the foreign key alone: vendor ids are globally unique, while this
        # operation must never attach a profile to a vendor hidden by tenant
        # isolation.
        vendor_exists = self.session.execute(
            select(Vendor.id).where(Vendor.id == vendor_id)
        ).scalars().first()
        if vendor_exists is None:
            raise ValueError("vendor is not visible in the active tenant scope")
        current = self.latest(vendor_id)
        next_revision = (current.revision + 1) if current else 1
        row = VendorProfileRevision(vendor_id=vendor_id, revision=next_revision, **values)
        self.session.add(row)
        self.session.flush()
        return row
