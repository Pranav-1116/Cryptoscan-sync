"""
Evidence loader - orchestrates loading evidence from JSON files to PostgreSQL.

The full loading pipeline:
1. Read evidence JSON files from disk
2. Verify integrity (pre-load)
3. Load to database with transaction safety
4. Verify insertion (post-load)
5. Record verification result in audit log
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..repositories.scan_repository import ScanRepository
from ..repositories.verification_repository import VerificationRepository
from .bulk_inserter import BulkInserter
from .post_load_verifier import PostLoadVerifier, PostLoadVerificationResult
from .pre_load_verifier import PreLoadVerifier, PreLoadVerificationResult

logger = logging.getLogger(__name__)


@dataclass
class LoadResult:
    """Result of a complete evidence load operation."""

    success: bool
    scan_id: str | None = None
    records_loaded: int = 0
    pre_verification: PreLoadVerificationResult | None = None
    post_verification: PostLoadVerificationResult | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "scan_id": self.scan_id,
            "records_loaded": self.records_loaded,
            "pre_verification": self.pre_verification.to_dict() if self.pre_verification else None,
            "post_verification": self.post_verification.to_dict() if self.post_verification else None,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "warnings": self.warnings,
        }


class EvidenceLoader:
    """
    Orchestrates the complete evidence loading pipeline.

    Implements the Week 4 specification:
    - Pre-load integrity verification
    - Transaction-safe bulk insertion
    - Post-load chain verification
    - Audit trail recording
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self.pre_verifier = PreLoadVerifier()
        self.bulk_inserter = BulkInserter(session)
        self.post_verifier = PostLoadVerifier(session)
        self.scan_repo = ScanRepository(session)
        self.verification_repo = VerificationRepository(session)

    def load_from_files(
        self,
        evidence_file: Path,
        manifest_file: Path | None = None,
        operator: str = "system",
    ) -> LoadResult:
        """
        Load evidence records from JSON files into the database.

        Args:
            evidence_file: Path to evidence-records-{scan_id}.json
            manifest_file: Optional path to manifest-{scan_id}.json
            operator: Who triggered the load.

        Returns:
            LoadResult with success status and details.
        """
        start_time = datetime.now(timezone.utc)

        # Read evidence file
        try:
            evidence_data = self._read_json_file(evidence_file)
        except Exception as e:
            return LoadResult(
                success=False,
                error=f"Failed to read evidence file: {e}",
            )

        # Read manifest file if provided
        manifest_data: dict[str, Any] | None = None
        if manifest_file and manifest_file.exists():
            try:
                manifest_data = self._read_json_file(manifest_file)
            except Exception as e:
                logger.warning(f"Failed to read manifest file: {e}")

        # Extract scan and evidence records
        scan_data = evidence_data.get("scan", {}) or {}
        evidence_records = evidence_data.get("evidence_records", []) or []
        scan_session_id = evidence_data.get("scan_session_id")

        if not scan_data.get("scan_id"):
            return LoadResult(
                success=False,
                error="Evidence file missing scan.scan_id",
            )

        scan_id_str = str(scan_data["scan_id"])

        return self.load_from_data(
            scan_id=scan_id_str,
            scan_data=scan_data,
            evidence_records=evidence_records,
            manifest_data=manifest_data,
            scan_session_id=scan_session_id,
            operator=operator,
            start_time=start_time,
        )

    def load_from_data(
        self,
        scan_id: str,
        scan_data: dict[str, Any],
        evidence_records: list[dict[str, Any]],
        manifest_data: dict[str, Any] | None = None,
        scan_session_id: str | None = None,
        operator: str = "system",
        start_time: datetime | None = None,
    ) -> LoadResult:
        """
        Load evidence records from in-memory data structures.

        This is the main entry point used by the worker pipeline.

        Args:
            scan_id: Scan UUID string.
            scan_data: Scan metadata dict.
            evidence_records: List of evidence record dicts.
            manifest_data: Optional manifest dict.
            scan_session_id: Session ID for chain anchor.
            operator: Who triggered the load.
            start_time: When the operation started.

        Returns:
            LoadResult with success status and details.
        """
        if start_time is None:
            start_time = datetime.now(timezone.utc)

        scan_uuid = uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id

        logger.info(
            "Starting evidence load",
            extra={
                "scan_id": scan_id,
                "evidence_count": len(evidence_records),
                "operator": operator,
            },
        )

        # STEP 1: Pre-load integrity verification
        logger.info("Running pre-load integrity verification...")
        pre_result = self.pre_verifier.verify(
            evidence_records=evidence_records,
            manifest=manifest_data,
            scan_session_id=scan_session_id,
        )

        if not pre_result.passed:
            # ABORT — do not load corrupted data
            logger.error(
                "Pre-load verification FAILED — aborting load",
                extra={
                    "scan_id": scan_id,
                    "errors": pre_result.total_errors,
                },
            )
            self._record_verification_failure(
                scan_uuid=scan_uuid,
                scan_data=scan_data,
                pre_result=pre_result,
                operator=operator,
            )

            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            return LoadResult(
                success=False,
                scan_id=scan_id,
                pre_verification=pre_result,
                error="Pre-load integrity verification failed. Load aborted.",
                duration_seconds=duration,
            )

        # STEP 2: Transaction-safe load
        logger.info("Loading scan and evidence records to database...")
        try:
            scan, records_inserted = self.bulk_inserter.insert_scan_with_evidence(
                scan_data=scan_data,
                evidence_records=evidence_records,
            )
            self.session.flush()
        except Exception as e:
            self.session.rollback()
            logger.error("Database insertion failed", exc_info=True)
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            return LoadResult(
                success=False,
                scan_id=scan_id,
                pre_verification=pre_result,
                error=f"Database insertion failed: {e}",
                duration_seconds=duration,
            )

        # STEP 3: Post-load verification
        logger.info("Running post-load chain verification...")
        post_result = self.post_verifier.verify(
            scan_id=scan_uuid,
            expected_count=len(evidence_records),
            scan_session_id=scan_session_id,
        )

        # STEP 4: Record verification result in audit log
        verification_result = "PASS" if post_result.passed else "FAIL"
        try:
            self.verification_repo.create_verification_record(
                scan_id=scan_uuid,
                verified_by=f"evidence-loader/{operator}",
                result=verification_result,
                chain_valid=len(post_result.chain_errors) == 0,
                content_hashes_valid=len(pre_result.content_hash_errors) == 0,
                findings_count_verified=post_result.records_checked,
                errors=post_result.chain_errors or [],
                details={
                    "pre_verification": pre_result.to_dict(),
                    "post_verification": post_result.to_dict(),
                    "operator": operator,
                },
            )
        except Exception as e:
            logger.warning(f"Failed to record verification log: {e}")

        if not post_result.passed:
            # Post-load verification failed — something went wrong during insert
            # Log the error but don't rollback (data is in, issue is with chain)
            logger.error(
                "Post-load verification FAILED",
                extra={"scan_id": scan_id},
            )

        # Commit everything
        self.session.commit()

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        warnings = []
        if not post_result.passed:
            warnings.append("Post-load chain verification failed — data stored but chain integrity issue detected")

        result = LoadResult(
            success=True,  # Data was loaded even if post-verify had issues
            scan_id=scan_id,
            records_loaded=records_inserted,
            pre_verification=pre_result,
            post_verification=post_result,
            duration_seconds=duration,
            warnings=warnings,
        )

        logger.info(
            "Evidence load complete",
            extra={
                "scan_id": scan_id,
                "records_loaded": records_inserted,
                "duration_seconds": duration,
                "warnings": len(warnings),
            },
        )

        return result

    def _record_verification_failure(
        self,
        scan_uuid: uuid.UUID,
        scan_data: dict[str, Any],
        pre_result: PreLoadVerificationResult,
        operator: str,
    ) -> None:
        """Record a failed pre-load verification in the audit log."""
        try:
            # We need at minimum a scan record for the FK constraint
            # Check if it already exists
            existing = self.scan_repo.get_by_id(scan_uuid)
            if not existing:
                # Create a minimal scan record to anchor the verification log
                from ..models.scan import Scan
                minimal_scan = Scan(
                    scan_id=scan_uuid,
                    scan_start=datetime.now(timezone.utc),
                    scanner_id=scan_data.get("scanner_id", "unknown"),
                    scanner_version=scan_data.get("scanner_version", "0.0.0"),
                    target_type=scan_data.get("target_type", "UNKNOWN"),
                    target_location=scan_data.get("target_location", ""),
                    operator=operator,
                    status="FAILED",
                )
                self.session.add(minimal_scan)
                self.session.flush()

            self.verification_repo.create_verification_record(
                scan_id=scan_uuid,
                verified_by=f"evidence-loader/{operator}",
                result="FAIL",
                chain_valid=len(pre_result.chain_hash_errors) == 0,
                content_hashes_valid=len(pre_result.content_hash_errors) == 0,
                errors=pre_result.content_hash_errors + pre_result.chain_hash_errors,
                details={
                    "stage": "pre_load",
                    "structural_errors": pre_result.structural_errors,
                    "manifest_errors": pre_result.manifest_errors,
                },
            )
            self.session.commit()
        except Exception as e:
            logger.warning(f"Failed to record pre-load verification failure: {e}")
            self.session.rollback()

    @staticmethod
    def _read_json_file(path: Path) -> dict[str, Any]:
        """Read and parse a JSON file."""
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            return json.load(f)