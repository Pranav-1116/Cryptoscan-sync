"""
Post-load verifier - verifies evidence chain integrity in the database.

After bulk insertion, this verifier re-queries the database and
verifies the chain hash linkage is intact in the stored data.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class PostLoadVerificationResult:
    """Result of post-load database verification."""

    passed: bool
    scan_id: str
    records_checked: int = 0
    chain_errors: list[dict[str, Any]] = field(default_factory=list)
    count_mismatch: bool = False
    expected_count: int = 0
    actual_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "scan_id": self.scan_id,
            "records_checked": self.records_checked,
            "chain_errors": self.chain_errors,
            "count_mismatch": self.count_mismatch,
            "expected_count": self.expected_count,
            "actual_count": self.actual_count,
            "total_errors": len(self.chain_errors) + (1 if self.count_mismatch else 0),
        }


class PostLoadVerifier:
    """
    Verifies evidence integrity in the database after insertion.

    Queries the database and re-verifies the chain hash linkage
    to ensure data was stored correctly and not corrupted during
    the write operation.
    """

    def __init__(self, session: Session) -> None:
        self.session = session

    def verify(
        self,
        scan_id: uuid.UUID,
        expected_count: int,
        scan_session_id: str | None = None,
    ) -> PostLoadVerificationResult:
        """
        Verify evidence chain integrity in the database.

        Args:
            scan_id: The scan to verify.
            expected_count: Expected number of evidence records.
            scan_session_id: Session ID for chain anchor.

        Returns:
            PostLoadVerificationResult with pass/fail details.
        """
        result = PostLoadVerificationResult(
            passed=False,
            scan_id=str(scan_id),
            expected_count=expected_count,
        )

        # Step 1: Verify count
        actual_count = self._get_record_count(scan_id)
        result.actual_count = actual_count

        if actual_count != expected_count:
            result.count_mismatch = True
            logger.error(
                "Post-load count mismatch",
                extra={
                    "scan_id": str(scan_id),
                    "expected": expected_count,
                    "actual": actual_count,
                },
            )

        # Step 2: Verify chain hashes from DB
        self._verify_chain_from_db(scan_id, scan_session_id, result)

        result.passed = not result.count_mismatch and len(result.chain_errors) == 0

        if result.passed:
            logger.info(
                "Post-load verification PASSED",
                extra={"scan_id": str(scan_id), "records": actual_count},
            )
        else:
            logger.error(
                "Post-load verification FAILED",
                extra={
                    "scan_id": str(scan_id),
                    "chain_errors": len(result.chain_errors),
                    "count_mismatch": result.count_mismatch,
                },
            )

        return result

    def _get_record_count(self, scan_id: uuid.UUID) -> int:
        """Count evidence records for a scan in the DB."""
        result = self.session.execute(
            text("SELECT COUNT(*) FROM evidence_records WHERE scan_id = :scan_id"),
            {"scan_id": scan_id},
        )
        return result.scalar_one()

    def _verify_chain_from_db(
        self,
        scan_id: uuid.UUID,
        scan_session_id: str | None,
        result: PostLoadVerificationResult,
    ) -> None:
        """Query and verify chain hashes from the database."""
        rows = self.session.execute(
            text(
                """
                SELECT
                    evidence_id,
                    chain_position,
                    content_hash,
                    chain_hash,
                    previous_hash
                FROM evidence_records
                WHERE scan_id = :scan_id
                ORDER BY chain_position ASC
                """
            ),
            {"scan_id": scan_id},
        ).fetchall()

        result.records_checked = len(rows)

        if not rows:
            return

        previous_hash: str | None = None

        for row in rows:
            position = row.chain_position
            content_hash = row.content_hash
            stored_chain_hash = row.chain_hash

            # Compute expected chain hash
            if position == 0:
                prev = scan_session_id or ""
            else:
                prev = previous_hash or ""

            expected_chain_hash = self._compute_chain_hash(content_hash, prev)

            if expected_chain_hash != stored_chain_hash:
                result.chain_errors.append({
                    "evidence_id": str(row.evidence_id),
                    "position": position,
                    "stored_chain_hash": stored_chain_hash,
                    "expected_chain_hash": expected_chain_hash,
                    "error": "Chain hash mismatch in database",
                })

            previous_hash = stored_chain_hash

    @staticmethod
    def _compute_chain_hash(content_hash: str, previous_hash: str) -> str:
        """Compute expected chain hash."""
        combined = content_hash + previous_hash
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()