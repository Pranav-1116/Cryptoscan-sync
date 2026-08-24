"""
Repository for verification_log table operations.

Provides data access for integrity verification records.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..models.verification_log import VerificationLog
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class VerificationRepository(BaseRepository[VerificationLog]):
    """Data access layer for verification_log table."""

    def __init__(self, session: Session) -> None:
        super().__init__(session, VerificationLog)

    def create_verification_record(
        self,
        *,
        scan_id: uuid.UUID,
        verified_by: str,
        result: str,
        chain_valid: bool = True,
        content_hashes_valid: bool = True,
        manifest_valid: bool | None = None,
        findings_count_verified: int | None = None,
        errors: list[dict[str, Any]] | None = None,
        details: dict[str, Any] | None = None,
    ) -> VerificationLog:
        """
        Create a new verification log record.

        Args:
            scan_id: The scan that was verified.
            verified_by: Who/what performed the verification.
            result: 'PASS', 'FAIL', or 'PARTIAL'.
            chain_valid: Whether chain hash linkage is intact.
            content_hashes_valid: Whether content hashes match.
            manifest_valid: Whether manifest hash is valid.
            findings_count_verified: Number of findings checked.
            errors: List of error details if any.
            details: Additional metadata.

        Returns:
            Created VerificationLog record.

        Raises:
            ValueError: If result is not valid.
        """
        valid_results = {"PASS", "FAIL", "PARTIAL"}
        if result not in valid_results:
            raise ValueError(f"Invalid result: {result!r}. Must be one of {valid_results}")

        log_record = VerificationLog(
            scan_id=scan_id,
            verified_by=verified_by,
            result=result,
            chain_valid=chain_valid,
            content_hashes_valid=content_hashes_valid,
            manifest_valid=manifest_valid,
            findings_count_verified=findings_count_verified,
            errors=errors or [],
            details=details or {},
            verified_at=datetime.now(timezone.utc),
        )

        self.session.add(log_record)
        self.session.flush()

        logger.info(
            "Verification record created",
            extra={
                "verification_id": str(log_record.verification_id),
                "scan_id": str(scan_id),
                "result": result,
                "chain_valid": chain_valid,
                "content_hashes_valid": content_hashes_valid,
            },
        )

        return log_record

    def get_latest_for_scan(self, scan_id: uuid.UUID) -> VerificationLog | None:
        """
        Get the most recent verification record for a scan.

        Args:
            scan_id: The scan UUID.

        Returns:
            Most recent VerificationLog or None if never verified.
        """
        stmt = (
            select(VerificationLog)
            .where(VerificationLog.scan_id == scan_id)
            .order_by(desc(VerificationLog.verified_at))
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_all_for_scan(
        self,
        scan_id: uuid.UUID,
        limit: int = 100,
    ) -> list[VerificationLog]:
        """
        Get all verification records for a scan, newest first.

        Args:
            scan_id: The scan UUID.
            limit: Maximum number of records.

        Returns:
            List of VerificationLog records.
        """
        stmt = (
            select(VerificationLog)
            .where(VerificationLog.scan_id == scan_id)
            .order_by(desc(VerificationLog.verified_at))
            .limit(limit)
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_failed_verifications(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> list[VerificationLog]:
        """
        Get all failed verifications (tampering events).

        Args:
            limit: Maximum results.
            offset: Pagination offset.

        Returns:
            List of FAIL verification records, newest first.
        """
        stmt = (
            select(VerificationLog)
            .where(VerificationLog.result == "FAIL")
            .order_by(desc(VerificationLog.verified_at))
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.execute(stmt).scalars().all())

    def count_by_result(self, scan_id: uuid.UUID) -> dict[str, int]:
        """
        Count verification records by result for a scan.

        Args:
            scan_id: The scan UUID.

        Returns:
            Dict mapping result -> count.
        """
        stmt = (
            select(VerificationLog.result, func.count().label("count"))
            .where(VerificationLog.scan_id == scan_id)
            .group_by(VerificationLog.result)
        )
        rows = self.session.execute(stmt).all()
        return {row.result: row.count for row in rows}

    def scan_has_passed_verification(self, scan_id: uuid.UUID) -> bool:
        """
        Check if a scan has at least one PASS verification.

        Args:
            scan_id: The scan UUID.

        Returns:
            True if at least one PASS verification exists.
        """
        stmt = (
            select(func.count())
            .select_from(VerificationLog)
            .where(
                VerificationLog.scan_id == scan_id,
                VerificationLog.result == "PASS",
            )
        )
        count = self.session.execute(stmt).scalar_one()
        return count > 0

    def get_verification_summary(self, since: datetime | None = None) -> dict[str, Any]:
        """
        Get summary statistics for verification runs.

        Args:
            since: Only count verifications since this timestamp.

        Returns:
            Dict with counts by result and other stats.
        """
        base_query = select(VerificationLog.result, func.count().label("count")).group_by(
            VerificationLog.result
        )

        if since:
            base_query = base_query.where(VerificationLog.verified_at >= since)

        rows = self.session.execute(base_query).all()
        counts = {row.result: row.count for row in rows}

        return {
            "total": sum(counts.values()),
            "pass": counts.get("PASS", 0),
            "fail": counts.get("FAIL", 0),
            "partial": counts.get("PARTIAL", 0),
            "tamper_detected": counts.get("FAIL", 0) > 0,
        }