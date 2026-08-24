"""Scan evidence session helper."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from evidence.core.pipeline import EvidencePipeline
from evidence.models.evidence_record import EvidenceRecord
from evidence.models.scan_manifest import ScanManifest


@dataclass
class EvidenceSession:
    scan_session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    pipeline: EvidencePipeline = field(init=False)

    def __post_init__(self) -> None:
        self.pipeline = EvidencePipeline(scan_session_id=self.scan_session_id)

    def ingest(self, findings: list) -> list[EvidenceRecord]:
        return self.pipeline.process_findings(findings)

    def manifest(self) -> ScanManifest:
        return self.pipeline.create_manifest()
