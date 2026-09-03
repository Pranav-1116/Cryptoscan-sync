"""Load evidence records into the database with integrity checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from db.loader.bulk_inserter import BulkInserter
from db.loader.post_load_verifier import PostLoadResult, PostLoadVerifier
from db.loader.pre_load_verifier import PreLoadVerification, verify_records_detailed
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.verification_log import VerificationLog
from db.repositories.verification_repository import VerificationRepository

logger = logging.getLogger(__name__)


@dataclass
class LoadResult:
    """Outcome of an evidence load attempt."""

    success: bool
    records_loaded: int = 0
    error: str | None = None
    scan_id: str | None = None
    pre_verification: PreLoadVerification | None = None
    post_verification: PostLoadResult | None = None


class EvidenceLoader:
    def __init__(self, session: Session):
        self.session = session
        self.bulk_inserter = BulkInserter(session)

    # ------------------------------------------------------------------ #
    # New integrity-checked pipeline
    # ------------------------------------------------------------------ #
    def load_from_data(
        self,
        *,
        scan_id: str,
        scan_data: dict[str, Any],
        evidence_records: list[dict[str, Any]],
        scan_session_id: str | None = None,
        operator: str | None = None,
    ) -> LoadResult:
        """Pre-verify → atomically insert → post-verify, with rollback on any failure."""
        pre = verify_records_detailed(evidence_records, scan_session_id=scan_session_id)
        if not pre.passed:
            return LoadResult(
                success=False,
                error=f"Pre-load integrity verification failed: {pre.error}",
                scan_id=str(scan_id),
                pre_verification=pre,
            )

        # Normalize nested `chain` layout onto the flat keys the inserter reads.
        flat_records = [self._flatten_chain(rec) for rec in evidence_records]
        scan_meta = dict(scan_data)
        scan_meta["scan_id"] = str(scan_id)
        if operator:
            scan_meta["operator"] = operator

        try:
            with self.session.begin_nested():
                _, inserted = self.bulk_inserter.insert_scan_with_evidence(scan_meta, flat_records)
        except Exception as exc:  # noqa: BLE001 — roll back and surface
            logger.warning("evidence_load_insert_failed", extra={"scan_id": str(scan_id), "error": str(exc)})
            return LoadResult(
                success=False,
                error=f"Database insertion failed: {exc}",
                scan_id=str(scan_id),
                pre_verification=pre,
            )

        post = PostLoadVerifier(self.session).verify(
            scan_id=str(scan_id),
            expected_count=inserted,
            scan_session_id=scan_session_id,
        )
        if not post.passed:
            self.session.rollback()
            return LoadResult(
                success=False,
                error=f"Post-load verification failed: {post.error}",
                scan_id=str(scan_id),
                pre_verification=pre,
                post_verification=post,
            )

        chain_ok = not post.chain_errors
        content_ok = not pre.content_hash_errors
        VerificationRepository(self.session).log(
            str(scan_id),
            "PASS",
            verified_by=operator or "evidence-loader",
            details={"loaded": inserted, "expected": inserted},
            chain_valid=chain_ok,
            content_hashes_valid=content_ok,
        )
        self.session.commit()
        return LoadResult(
            success=True,
            records_loaded=inserted,
            scan_id=str(scan_id),
            pre_verification=pre,
            post_verification=post,
        )

    @staticmethod
    def _flatten_chain(rec: dict[str, Any]) -> dict[str, Any]:
        """Return a record with the nested `chain` object projected to flat keys."""
        out = dict(rec)
        chain = out.get("chain")
        if isinstance(chain, dict):
            out.setdefault("chain_position", chain.get("position"))
            out.setdefault("chain_hash", chain.get("chain_hash"))
            out.setdefault("previous_hash", chain.get("previous_hash"))
        return out

    # ------------------------------------------------------------------ #
    # Legacy loader (kept for the static-scanner ingestion path)
    # ------------------------------------------------------------------ #

    def load(
        self,
        *,
        scan_meta: dict[str, Any],
        evidence_records: list[dict[str, Any]],
        manifest: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> Scan:
        now = datetime.now(timezone.utc)
        scan = None
        if scan_id:
            scan = self.session.get(Scan, scan_id)
        if scan is None:
            scan = Scan(
                id=scan_id,
                scan_start=self._parse_dt(scan_meta.get("scan_start")) or now,
                scanner_id=scan_meta.get("scanner_id", "static-java-scanner-v0.1"),
                scanner_version=scan_meta.get("scanner_version", "0.1.0"),
                target_type=scan_meta.get("target_type", "LOCAL_DIRECTORY"),
                target_location=scan_meta.get("target_location")
                or scan_meta.get("target_url")
                or "unknown",
                target_commit=scan_meta.get("target_commit"),
                target_branch=scan_meta.get("target_branch"),
                operator=scan_meta.get("operator", "system"),
                status="RUNNING",
            )
            self.session.add(scan)
            self.session.flush()

        rows: list[EvidenceRecord] = []
        for rec in evidence_records:
            finding = rec.get("finding") or rec.get("finding_data") or {}
            crypto = finding.get("crypto") or {}
            source = finding.get("source") or {}
            metadata = finding.get("metadata") or {}
            rows.append(
                EvidenceRecord(
                    id=rec.get("evidence_id"),
                    scan_id=scan.id,
                    content_hash=rec["content_hash"],
                    chain_hash=rec.get("chain_hash") or rec["content_hash"],
                    chain_position=int(rec.get("chain_position") or 0),
                    previous_hash=rec.get("previous_hash"),
                    algorithm=crypto.get("algorithm") or rec.get("algorithm") or "UNKNOWN",
                    key_size=crypto.get("key_size") or rec.get("key_size"),
                    mode=crypto.get("mode") or rec.get("mode"),
                    padding=crypto.get("padding") or rec.get("padding"),
                    purpose=crypto.get("purpose") or rec.get("purpose"),
                    confidence=(metadata.get("confidence") or rec.get("confidence") or "LOW"),
                    is_hardcoded_key=bool(
                        metadata.get("is_hardcoded_key") or rec.get("is_hardcoded_key")
                    ),
                    file_path=source.get("file_path") or rec.get("file_path") or "unknown",
                    line_number=int(source.get("line_number") or rec.get("line_number") or 0),
                    class_name=source.get("class_name") or rec.get("class_name"),
                    method_name=source.get("method_name") or rec.get("method_name"),
                    finding_data=finding,
                    provenance=rec.get("provenance") or rec.get("integrity"),
                )
            )
        self.session.add_all(rows)

        stats = scan_meta.get("statistics") or {
            "total_findings": len(rows),
            "files_scanned": scan_meta.get("files_scanned", 0),
        }
        scan.mark_completed(
            manifest_hash=(manifest or {}).get("manifest_hash"),
            statistics=stats,
        )
        self.session.add(
            VerificationLog(
                scan_id=scan.id,
                verified_at=now,
                verified_by="db-loader-v0.1",
                result="PASS",
                details={"loaded": len(rows)},
            )
        )
        self.session.flush()
        logger.info("evidence_loaded", extra={"scan_id": scan.id, "count": len(rows)})
        return scan

    @staticmethod
    def _parse_dt(value: Any) -> datetime | None:
        if isinstance(value, datetime):
            return value
        if not value:
            return None
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
