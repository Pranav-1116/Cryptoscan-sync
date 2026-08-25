"""Crypto asset persistence."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.models.crypto_asset import CryptoAsset
from db.models.crypto_asset_evidence import CryptoAssetEvidence
from db.repositories.base_repository import BaseRepository


class AssetRepository(BaseRepository[CryptoAsset]):
    def __init__(self, session: Session):
        super().__init__(CryptoAsset, session)

    def list_assets(
        self,
        *,
        algorithm: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[CryptoAsset], int]:
        stmt = select(CryptoAsset)
        count_stmt = select(func.count()).select_from(CryptoAsset)
        if algorithm:
            stmt = stmt.where(CryptoAsset.algorithm == algorithm)
            count_stmt = count_stmt.where(CryptoAsset.algorithm == algorithm)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = stmt.order_by(CryptoAsset.algorithm, CryptoAsset.file_path).offset((page - 1) * page_size).limit(page_size)
        return list(self.session.execute(stmt).scalars().all()), total

    def algorithm_counts(self) -> dict[str, int]:
        stmt = select(CryptoAsset.algorithm, func.count()).group_by(CryptoAsset.algorithm)
        return {str(row[0] or "UNKNOWN"): int(row[1]) for row in self.session.execute(stmt).all()}

    def search_located(self, query: str, *, limit: int = 200) -> list[dict]:
        from db.models.system import System
        from db.models.system_asset import SystemAsset

        needle = f"%{query.lower()}%"
        stmt = (
            select(CryptoAsset, System)
            .outerjoin(SystemAsset, SystemAsset.asset_id == CryptoAsset.id)
            .outerjoin(System, System.id == SystemAsset.system_id)
            .where(
                or_(
                    func.lower(CryptoAsset.algorithm).like(needle),
                    func.lower(func.coalesce(CryptoAsset.mode, "")).like(needle),
                    func.lower(CryptoAsset.file_path).like(needle),
                    func.lower(func.coalesce(System.name, "")).like(needle),
                )
            )
            .limit(limit)
        )
        hits = []
        for asset, system in self.session.execute(stmt).all():
            data = asset.to_dict()
            data["system_id"] = system.id if system is not None else None
            data["system_name"] = system.name if system is not None else "unassigned"
            hits.append(data)
        return hits

    def replace_for_scan(self, scan_id: str, assets: list[dict]) -> list[CryptoAsset]:
        existing = list(self.session.execute(select(CryptoAsset)).scalars())
        # Keep assets from other scans; we key by identity and refresh
        by_key = {(a.algorithm, a.purpose or "", a.file_path, a.line_number): a for a in existing}
        stored: list[CryptoAsset] = []
        for item in assets:
            key = (
                item["algorithm"],
                item.get("purpose") or "",
                item.get("file_path") or "",
                int(item.get("line_number") or 0),
            )
            row = by_key.get(key)
            if row is None:
                row = CryptoAsset(
                    algorithm=item["algorithm"],
                    purpose=item.get("purpose"),
                    mode=item.get("mode"),
                    key_size=item.get("key_size"),
                    file_path=item.get("file_path") or "unknown",
                    line_number=int(item.get("line_number") or 0),
                    source_language=item.get("source_language"),
                    confidence=item.get("confidence") or "LOW",
                    is_hardcoded_key=bool(item.get("is_hardcoded_key")),
                    occurrence_count=int(item.get("occurrence_count") or 1),
                    scanner_ids=item.get("scanner_ids") or [],
                    libraries=item.get("libraries") or [],
                    extra={
                        "scan_id": scan_id,
                        "dedup_key": item.get("dedup_key"),
                        "members": item.get("members") or [],
                        "primary_evidence_id": item.get("primary_evidence_id"),
                    },
                )
                self.session.add(row)
                self.session.flush()
            else:
                row.confidence = item.get("confidence") or row.confidence
                row.occurrence_count = int(item.get("occurrence_count") or row.occurrence_count)
                row.scanner_ids = item.get("scanner_ids") or row.scanner_ids
                row.libraries = item.get("libraries") or row.libraries
                extra = dict(row.extra or {})
                extra["scan_id"] = scan_id
                if item.get("dedup_key"):
                    extra["dedup_key"] = item.get("dedup_key")
                row.extra = extra
            for evidence_id in item.get("evidence_ids") or []:
                exists = self.session.execute(
                    select(CryptoAssetEvidence).where(
                        CryptoAssetEvidence.asset_id == row.id,
                        CryptoAssetEvidence.evidence_id == evidence_id,
                    )
                ).scalar_one_or_none()
                if exists is None:
                    self.session.add(CryptoAssetEvidence(asset_id=row.id, evidence_id=evidence_id))
            stored.append(row)
        self.session.flush()
        return stored
