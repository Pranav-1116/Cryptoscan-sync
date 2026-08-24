# services/database/db/models/scan.py

"""
Production ORM model for scan sessions.
Represents a single scan execution (static analysis run).
"""

from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, DateTime, Integer, Text, 
    Enum, Index, CheckConstraint, ForeignKey
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
import enum

from db.connection.session import BaseModel


class ScanStatus(str, enum.Enum):
    """Scan execution status enum."""
    QUEUED = "QUEUED"           # Waiting to start
    RUNNING = "RUNNING"         # Currently executing
    COMPLETED = "COMPLETED"     # Finished successfully
    FAILED = "FAILED"           # Failed with error
    CANCELLED = "CANCELLED"     # Manually cancelled


class ScanTargetType(str, enum.Enum):
    """Type of scan target."""
    GIT_REPOSITORY = "GIT_REPOSITORY"
    LOCAL_DIRECTORY = "LOCAL_DIRECTORY"


class Scan(BaseModel):
    """
    ORM model for cryptographic scan sessions.
    One record per scan execution.
    
    Fields:
        scan_id: UUID primary key
        scan_start: When scan started
        scan_end: When scan completed (null if running)
        scanner_id: Scanner version/identifier (e.g., "static-java-scanner-v0.1")
        scanner_version: Semantic version (e.g., "0.1.0")
        target_type: GIT_REPOSITORY or LOCAL_DIRECTORY
        target_location: URL (git) or path (local directory)
        target_commit: Git commit hash (40 chars) if git target
        target_branch: Git branch name if git target
        operator: User or system that triggered scan
        statistics: JSON with scan metrics (files_scanned, total_findings, etc.)
        manifest_hash: SHA-256 of evidence manifest (integrity proof)
        status: QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
        error_message: Error details if status=FAILED
        created_at: Record creation time (auto)
        updated_at: Last update time (auto)
    """
    
    __tablename__ = "scans"
    
    # Scan Metadata
    scan_start = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    
    scan_end = Column(
        DateTime(timezone=True),
        nullable=True,  # Null while running
    )
    
    scanner_id = Column(
        String(100),
        nullable=False,
        index=True,
    )
    
    scanner_version = Column(
        String(20),
        nullable=False,
    )
    
    # Target Configuration
    target_type = Column(
        Enum(ScanTargetType),
        nullable=False,
    )
    
    target_location = Column(
        Text,
        nullable=False,
        index=True,
    )
    
    target_commit = Column(
        String(40),  # Git SHA-1 hash
        nullable=True,
        index=True,
    )
    
    target_branch = Column(
        String(100),
        nullable=True,
    )
    
    # Operational
    operator = Column(
        String(100),
        nullable=False,
    )
    
    status = Column(
        Enum(ScanStatus),
        nullable=False,
        default=ScanStatus.QUEUED,
        index=True,
    )
    
    # Statistics (JSON)
    statistics = Column(
        JSONB,
        nullable=True,
        comment="Scan metrics: files_scanned, total_findings, high_confidence, etc.",
    )
    
    # Integrity
    manifest_hash = Column(
        String(64),  # SHA-256 hex
        nullable=True,
    )
    
    # Error Handling
    error_message = Column(
        Text,
        nullable=True,
    )
    
    # Relationships
    evidence_records = relationship(
        "EvidenceRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )
    
    # Indexes for common queries
    __table_args__ = (
        # Query by target and date
        Index("idx_scans_target_created", "target_location", "created_at"),
        # Query by status
        Index("idx_scans_status", "status"),
        # Query recent scans
        Index("idx_scans_created_at", "created_at"),
        # Ensure commit hash is 40 chars if present
        CheckConstraint(
            "target_commit IS NULL OR length(target_commit) = 40",
            name="ck_scan_commit_hash_length",
        ),
    )
    
    def __init__(
        self,
        scan_start: datetime,
        scanner_id: str,
        scanner_version: str,
        target_type: ScanTargetType,
        target_location: str,
        operator: str,
        target_commit: Optional[str] = None,
        target_branch: Optional[str] = None,
    ):
        """Initialize scan record."""
        self.scan_start = scan_start
        self.scanner_id = scanner_id
        self.scanner_version = scanner_version
        self.target_type = target_type
        self.target_location = target_location
        self.operator = operator
        self.target_commit = target_commit
        self.target_branch = target_branch
        self.status = ScanStatus.QUEUED
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.scan_end is None:
            return None
        return (self.scan_end - self.scan_start).total_seconds()
    
    @property
    def is_completed(self) -> bool:
        """Check if scan completed successfully."""
        return self.status == ScanStatus.COMPLETED
    
    @property
    def is_running(self) -> bool:
        """Check if scan is currently running."""
        return self.status == ScanStatus.RUNNING
    
    def mark_running(self) -> None:
        """Transition status to RUNNING."""
        if self.status != ScanStatus.QUEUED:
            raise ValueError(f"Cannot run scan in {self.status} status")
        self.status = ScanStatus.RUNNING
    
    def mark_completed(self, manifest_hash: str, statistics: dict) -> None:
        """
        Mark scan as completed.
        
        Args:
            manifest_hash: SHA-256 of evidence manifest
            statistics: Scan metrics dictionary
        """
        self.status = ScanStatus.COMPLETED
        self.scan_end = datetime.utcnow()
        self.manifest_hash = manifest_hash
        self.statistics = statistics
    
    def mark_failed(self, error_message: str) -> None:
        """
        Mark scan as failed.
        
        Args:
            error_message: Description of failure
        """
        self.status = ScanStatus.FAILED
        self.scan_end = datetime.utcnow()
        self.error_message = error_message
    
    def to_dict(self, include_error: bool = False) -> dict:
        """
        Convert to dictionary for JSON responses.
        
        Args:
            include_error: Include error_message in output
        
        Returns:
            Dictionary representation
        """
        data = super().to_dict()
        
        # Add computed fields
        data["duration_seconds"] = self.duration_seconds
        data["is_completed"] = self.is_completed
        data["evidence_count"] = len(self.evidence_records) if self.evidence_records else 0
        
        # Remove error if not requested
        if not include_error:
            data.pop("error_message", None)
        
        return data
    
    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, target={self.target_location}, status={self.status})>"