"""Crypto asset persistence."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from shared_models.asset_identity import crypto_asset_key_from_row

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
        q: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[CryptoAsset], int]:
        stmt = select(CryptoAsset)
        count_stmt = select(func.count()).select_from(CryptoAsset)
        if algorithm:
            stmt = stmt.where(CryptoAsset.algorithm == algorithm)
            count_stmt = count_stmt.where(CryptoAsset.algorithm == algorithm)
        if q:
            # §5 (round 62): SERVER-side search — the term is matched in the
            # database across the whole estate (not only the loaded page),
            # over the fields an operator actually searches: asset id,
            # identity spine, algorithm, file location.
            needle = f"%{q.strip()}%"
            from sqlalchemy import or_
            condition = or_(
                CryptoAsset.id == q.strip(),
                CryptoAsset.asset_key.ilike(needle),
                CryptoAsset.algorithm.ilike(needle),
                CryptoAsset.file_path.ilike(needle),
            )
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)
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
        """Persist this scan's deduplicated assets, keyed by identity.

        Assets live across scans (a re-scan refreshes matching rows; other
        scans' rows are kept). Only rows whose file_path occurs in this
        batch are loaded — the previous full-table load made every scan
        slower as asset history grew (10k accumulated rows added ~50s to a
        50-file scan).
        """
        paths = {str(item.get("file_path") or "") for item in assets}
        stmt = select(CryptoAsset)
        if paths:
            conditions = [CryptoAsset.file_path.in_(sorted(paths))]
            if "" in paths:  # NULL paths keyed to "" in the identity tuple
                conditions.append(CryptoAsset.file_path.is_(None))
            stmt = stmt.where(or_(*conditions))
        existing = list(self.session.execute(stmt).scalars())
        # Keep assets from other scans; we key by identity and refresh
        by_key = {(a.algorithm, a.purpose or "", a.file_path, a.line_number): a for a in existing}
        stored: list[CryptoAsset] = []
        pending_links: list[tuple[CryptoAsset, list]] = []
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
                    asset_key=crypto_asset_key_from_row(item) or None,
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
            else:
                # repair the spine on legacy rows touched by a refresh:
                # pre-0092 rows converge to the canonical key on contact
                expected_key = crypto_asset_key_from_row(item)
                if row.asset_key != expected_key:
                    row.asset_key = expected_key
                row.confidence = item.get("confidence") or row.confidence
                row.occurrence_count = int(item.get("occurrence_count") or row.occurrence_count)
                row.scanner_ids = item.get("scanner_ids") or row.scanner_ids
                row.libraries = item.get("libraries") or row.libraries
                extra = dict(row.extra or {})
                extra["scan_id"] = scan_id
                if item.get("dedup_key"):
                    extra["dedup_key"] = item.get("dedup_key")
                row.extra = extra
            pending_links.append((row, list(item.get("evidence_ids") or [])))
            stored.append(row)
        self.session.flush()  # single flush assigns ids for the new rows

        # one bulk query instead of one SELECT per (asset, evidence) pair
        asset_ids = [row.id for row, _ in pending_links]
        wanted = {(row.id, eid) for _, eids in pending_links for eid in eids}
        existing_pairs: set[tuple] = set()
        if asset_ids and wanted:
            rows = self.session.execute(
                select(CryptoAssetEvidence.asset_id, CryptoAssetEvidence.evidence_id).where(
                    CryptoAssetEvidence.asset_id.in_(asset_ids),
                    CryptoAssetEvidence.evidence_id.in_([eid for _, eids in pending_links for eid in eids]),
                )
            ).all()
            existing_pairs = {(a, e) for a, e in rows}
        for row, eids in pending_links:
            for evidence_id in eids:
                if (row.id, evidence_id) not in existing_pairs:
                    self.session.add(CryptoAssetEvidence(asset_id=row.id, evidence_id=evidence_id))
        self.session.flush()
        return stored

    # --------------------------------------------------------- cloud inventory

    def upsert_cloud_asset(self, asset: dict) -> tuple[CryptoAsset, bool]:
        """Idempotent insert/update for cloud-collected keys, keyed by file_path.

        Cloud collectors produce stable refs (aws-kms://<region>/<keyId>,
        azure-kv://<vault>/<name>), so re-collection updates the existing row
        instead of stacking duplicates. first_seen_at survives updates;
        last_seen_at does not.
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        extra = dict(asset.get("extra") or {})
        extra["last_seen_at"] = now
        existing = self.session.execute(
            select(CryptoAsset).where(CryptoAsset.file_path == asset["file_path"])
        ).scalar_one_or_none()
        if existing is None:
            extra["first_seen_at"] = now
            row = CryptoAsset(
                algorithm=asset["algorithm"],
                purpose=asset.get("purpose"),
                key_size=asset.get("key_size"),
                asset_key=crypto_asset_key_from_row(asset) or None,
                file_path=asset["file_path"],
                line_number=0,
                source_language=asset.get("source_language") or "cloud-kms",
                confidence="HIGH",
                extra=extra,
            )
            self.session.add(row)
            self.session.flush()
            return row, True
        existing.algorithm = asset["algorithm"]
        existing.asset_key = crypto_asset_key_from_row(asset) or None
        existing.key_size = asset.get("key_size")
        existing.purpose = asset.get("purpose")
        existing.source_language = asset.get("source_language") or "cloud-kms"
        existing.confidence = "HIGH"
        existing.extra = {**(existing.extra or {}), **extra}
        self.session.flush()
        return existing, False
