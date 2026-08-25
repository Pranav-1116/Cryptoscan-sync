"""CRUD for crypto_asset_evidence links."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.repositories.base_repository import BaseRepository


class AssetEvidenceLinkRepository(BaseRepository[CryptoAssetEvidence]):
    def __init__(self, session: Session):
        super().__init__(CryptoAssetEvidence, session)

    def link(self, asset_id: str, evidence_id: str) -> CryptoAssetEvidence:
        existing = self.session.execute(
            select(CryptoAssetEvidence).where(
                CryptoAssetEvidence.asset_id == asset_id,
                CryptoAssetEvidence.evidence_id == evidence_id,
            )
        ).scalar_one_or_none()
        if existing:
            return existing
        row = CryptoAssetEvidence(asset_id=asset_id, evidence_id=evidence_id)
        self.session.add(row)
        self.session.flush()
        return row

    def evidence_ids_for(self, asset_id: str) -> list[str]:
        rows = self.session.execute(
            select(CryptoAssetEvidence.evidence_id).where(CryptoAssetEvidence.asset_id == asset_id)
        ).scalars()
        return list(rows)

    def asset_ids_for(self, evidence_id: str) -> list[str]:
        rows = self.session.execute(
            select(CryptoAssetEvidence.asset_id).where(CryptoAssetEvidence.evidence_id == evidence_id)
        ).scalars()
        return list(rows)
