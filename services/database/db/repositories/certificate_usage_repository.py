"""CRUD for certificate usage locations."""

from __future__ import annotations

from sqlalchemy.orm import Session

from db.models.certificate_usage import CertificateUsage
from db.repositories.base_repository import BaseRepository
from db.repositories.maturity_repository import MaturityRepository


class CertificateUsageRepository(BaseRepository[CertificateUsage]):
    def __init__(self, session: Session):
        super().__init__(CertificateUsage, session)
        self._maturity = MaturityRepository(session)

    def upsert(self, fingerprint: str, location: str, usage_type: str = "UNKNOWN") -> CertificateUsage:
        return self._maturity.upsert_usage(fingerprint, location, usage_type)

    def usages_for(self, fingerprint: str) -> list[CertificateUsage]:
        return self._maturity.usages_for(fingerprint)
