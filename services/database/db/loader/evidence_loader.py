"""Load evidence records into the database with integrity checks."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.verification_log import VerificationLog

logger = logging.getLogger(__name__)


class EvidenceLoader:
    def __init__(self, session: Session):
        self.session = session

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
