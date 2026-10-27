"""Evidence repository."""

from __future__ import annotations

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from db.models.evidence_record import EvidenceRecord
from db.repositories.base_repository import BaseRepository


class EvidenceRepository(BaseRepository[EvidenceRecord]):
    def __init__(self, session: Session):
        super().__init__(EvidenceRecord, session)

    def list_for_scan(
        self,
        scan_id: str,
        *,
        algorithm: str | None = None,
        compliance_status: str | None = None,
        hardcoded_only: bool = False,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[EvidenceRecord], int]:
        stmt = select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)
        count_stmt = select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)
        if algorithm:
            stmt = stmt.where(EvidenceRecord.algorithm == algorithm)
            count_stmt = count_stmt.where(EvidenceRecord.algorithm == algorithm)
        if compliance_status:
            stmt = stmt.where(EvidenceRecord.compliance_status == compliance_status)
            count_stmt = count_stmt.where(EvidenceRecord.compliance_status == compliance_status)
        if hardcoded_only:
            stmt = stmt.where(EvidenceRecord.is_hardcoded_key.is_(True))
            count_stmt = count_stmt.where(EvidenceRecord.is_hardcoded_key.is_(True))
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = (
            stmt.order_by(EvidenceRecord.chain_position)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all()), total

    def list_all(
        self,
        *,
        algorithm: str | None = None,
        compliance_status: str | None = None,
        scan_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[EvidenceRecord], int]:
        stmt = select(EvidenceRecord)
        count_stmt = select(func.count()).select_from(EvidenceRecord)
        if scan_id:
            stmt = stmt.where(EvidenceRecord.scan_id == scan_id)
            count_stmt = count_stmt.where(EvidenceRecord.scan_id == scan_id)
        if algorithm:
            stmt = stmt.where(EvidenceRecord.algorithm == algorithm)
            count_stmt = count_stmt.where(EvidenceRecord.algorithm == algorithm)
        if compliance_status:
            stmt = stmt.where(EvidenceRecord.compliance_status == compliance_status)
            count_stmt = count_stmt.where(EvidenceRecord.compliance_status == compliance_status)
        total = int(self.session.execute(count_stmt).scalar_one())
        stmt = (
            stmt.order_by(EvidenceRecord.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(self.session.execute(stmt).scalars().all()), total

    def get_by_scan(self, scan_id: str) -> list[EvidenceRecord]:
        return self.get_all_for_scan(scan_id)

    def get_all_for_scan(self, scan_id: str) -> list[EvidenceRecord]:
        stmt = (
            select(EvidenceRecord)
            .where(EvidenceRecord.scan_id == scan_id)
            .order_by(EvidenceRecord.chain_position)
        )
        return list(self.session.execute(stmt).scalars().all())

    def algorithm_breakdown(self) -> list[dict]:
        stmt = select(
            EvidenceRecord.algorithm,
            func.count().label("total"),
            func.sum(
                case((EvidenceRecord.compliance_status == "PASS", 1), else_=0)
            ).label("compliant"),
            func.sum(
                case((EvidenceRecord.compliance_status == "FAIL", 1), else_=0)
            ).label("failed"),
        ).group_by(EvidenceRecord.algorithm)
        rows = self.session.execute(stmt).all()
        result = []
        for row in rows:
            total = int(row.total or 0)
            compliant = int(row.compliant or 0)
            failed = int(row.failed or 0)
            result.append(
                {
                    "algorithm": row.algorithm,
                    "total": total,
                    "compliant": compliant,
                    "failed": failed,
                    "compliance_pct": round((compliant / total) * 100, 1) if total else 0,
                }
            )
        return sorted(result, key=lambda x: x["total"], reverse=True)
