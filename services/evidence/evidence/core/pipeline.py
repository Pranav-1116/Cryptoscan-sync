"""Evidence pipeline — raw findings to tamper-evident records."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from evidence.hashing.chain_hasher import ChainHasher
from evidence.hashing.content_hasher import ContentHasher
from evidence.models.evidence_record import EvidenceRecord
from evidence.models.scan_manifest import ScanManifest

logger = logging.getLogger(__name__)


class EvidencePipeline:
    def __init__(self, scan_session_id: str | None = None):
        self.scan_session_id = scan_session_id or str(uuid.uuid4())
        self.evidence_records: list[EvidenceRecord] = []

    def process(
        self,
        findings: list[Any] | None = None,
        scan_id: str | None = None,
        scan_timestamp: str | None = None,
        **kwargs,
    ) -> tuple[list[EvidenceRecord], ScanManifest]:
        if scan_id:
            self.scan_session_id = scan_id
        records = self.process_findings(findings or [])
        if not records:
            empty = ScanManifest(
                manifest_id=str(uuid.uuid4()),
                scan_session_id=self.scan_session_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                total_findings=0,
                first_chain_hash="",
                last_chain_hash="",
                manifest_hash=hashlib.sha256(b"").hexdigest(),
                evidence_records=[],
            )
            return records, empty
        return records, self.create_manifest()

    def process_findings(self, findings: list[Any]) -> list[EvidenceRecord]:
        normalized: list[dict[str, Any]] = []
        for finding in findings:
            if hasattr(finding, "model_dump"):
                normalized.append(finding.model_dump(mode="json"))
            elif isinstance(finding, dict):
                normalized.append(finding)
            else:
                normalized.append({"raw": str(finding)})

        content_hashes = ContentHasher.compute_batch(normalized)
        records: list[EvidenceRecord] = []
        for position, finding in enumerate(normalized):
            finding_id = finding.get("finding_id") or str(uuid.uuid4())
            record = EvidenceRecord(
                evidence_id=str(uuid.uuid4()),
                scan_id=self.scan_session_id,
                content_hash=content_hashes[finding_id],
                chain_position=position,
                finding=finding,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            records.append(record)

        previous = None
        content_list = [r.content_hash for r in records]
        chain_hashes = ChainHasher.compute_chain(content_list, self.scan_session_id)
        for i, record in enumerate(records):
            record.chain_hash = chain_hashes[i]
            record.previous_hash = previous
            previous = chain_hashes[i]

        self.evidence_records = records
        logger.info("evidence_records_created", extra={"count": len(records)})
        return records

    def create_manifest(self) -> ScanManifest:
        if not self.evidence_records:
            raise ValueError("No evidence records to create manifest from")
        evidence_ids = sorted(r.evidence_id for r in self.evidence_records)
        manifest_hash = hashlib.sha256("".join(evidence_ids).encode("utf-8")).hexdigest()
        return ScanManifest(
            manifest_id=str(uuid.uuid4()),
            scan_session_id=self.scan_session_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            total_findings=len(self.evidence_records),
            first_chain_hash=self.evidence_records[0].chain_hash or "",
            last_chain_hash=self.evidence_records[-1].chain_hash or "",
            manifest_hash=manifest_hash,
            evidence_records=[
                {
                    "evidence_id": r.evidence_id,
                    "content_hash": r.content_hash,
                    "chain_hash": r.chain_hash,
                    "chain_position": r.chain_position,
                }
                for r in self.evidence_records
            ],
        )

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        content = [r.content_hash for r in self.evidence_records]
        stored = [r.chain_hash or "" for r in self.evidence_records]
        ok = ChainHasher.verify_chain(content, stored, self.scan_session_id)
        return ok, None if ok else "chain verification failed"
