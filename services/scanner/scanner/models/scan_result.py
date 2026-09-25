"""ScanResult model — complete output of a scan session."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from scanner.models.raw_finding import RawFinding


class ScanTarget(BaseModel):
    type: str = "LOCAL_DIRECTORY"
    location: str = ""
    commit: Optional[str] = None
    branch: Optional[str] = None


class ScanStatistics(BaseModel):
    files_scanned: int = 0
    files_with_crypto: int = 0
    files_skipped: int = 0
    files_with_errors: int = 0
    total_findings: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    duration_seconds: float = 0.0
    # findings per code origin (source/test/generated/vendored/archive) — triage view, never a filter
    findings_by_origin: dict[str, int] = Field(default_factory=dict)
    # UNKNOWN findings whose algorithm was filled from a constant declared in another file
    resolved_cross_file: int = 0


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_start: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_end: Optional[str] = None
    scanner_version: str = "0.1.0"
    scanner_id: str = "static-java-scanner-v0.1"
    scan_target: ScanTarget = Field(default_factory=ScanTarget)
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    findings: list[RawFinding] = Field(default_factory=list)
    parse_errors: list[dict] = Field(default_factory=list)
    status: str = "COMPLETED"
    error_message: Optional[str] = None

    def finalize(self) -> None:
        end = datetime.now(timezone.utc)
        self.scan_end = end.isoformat()
        try:
            start = datetime.fromisoformat(self.scan_start.replace("Z", "+00:00"))
            self.statistics.duration_seconds = (end - start).total_seconds()
        except ValueError:
            self.statistics.duration_seconds = 0.0
        self.statistics.total_findings = len(self.findings)
        by_origin: dict[str, int] = {}
        for f in self.findings:
            o = getattr(f.metadata, "code_origin", None) or "source"
            by_origin[o] = by_origin.get(o, 0) + 1
        self.statistics.findings_by_origin = by_origin
        self.statistics.high_confidence = sum(
            1 for f in self.findings if f.metadata.confidence == "HIGH"
        )
        self.statistics.medium_confidence = sum(
            1 for f in self.findings if f.metadata.confidence == "MEDIUM"
        )
        self.statistics.low_confidence = sum(
            1 for f in self.findings if f.metadata.confidence == "LOW"
        )
        self.statistics.files_with_crypto = len({f.source.file_path for f in self.findings})
        self.statistics.files_with_errors = len(self.parse_errors)

    @property
    def scan_completed(self) -> bool:
        return self.status == "COMPLETED"

    @property
    def files_scanned(self) -> int:
        return self.statistics.files_scanned

    @property
    def duration_seconds(self) -> float:
        return self.statistics.duration_seconds
