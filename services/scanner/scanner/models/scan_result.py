"""ScanResult model - complete output of a scan session."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from scanner.models.raw_finding import RawFinding


class ScanTarget(BaseModel):
    """What was scanned."""
    type: str  # GIT_REPOSITORY or LOCAL_DIRECTORY
    location: str  # URL or path
    commit: Optional[str] = None
    branch: Optional[str] = None


class ScanStatistics(BaseModel):
    """Aggregated statistics from the scan."""
    files_scanned: int = 0
    files_with_crypto: int = 0
    files_skipped: int = 0
    files_with_errors: int = 0
    total_findings: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    duration_seconds: float = 0.0


class ScanResult(BaseModel):
    """Complete result of a scan session."""

    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_start: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    scan_end: Optional[str] = None
    scanner_version: str = "0.1.0"
    scanner_id: str = "static-java-scanner-v0.1"

    scan_target: ScanTarget
    statistics: ScanStatistics = Field(default_factory=ScanStatistics)
    findings: list[RawFinding] = Field(default_factory=list)

    # Errors encountered during scan (but scan continued)
    parse_errors: list[dict] = Field(default_factory=list)

    def finalize(self) -> None:
        """Set scan_end and compute final statistics."""
        from datetime import timezone
        self.scan_end = datetime.now(timezone.utc).isoformat()

        self.statistics.total_findings = len(self.findings)
        self.statistics.high_confidence = sum(
            1 for f in self.findings if f.metadata.confidence == "HIGH"
        )
        self.statistics.medium_confidence = sum(
            1 for f in self.findings if f.metadata.confidence == "MEDIUM"
        )
        self.statistics.low_confidence = sum(
            1 for f in self.findings if f.metadata.confidence == "LOW"
        )
        files_with_crypto = set(f.source.file_path for f in self.findings)
        self.statistics.files_with_crypto = len(files_with_crypto)