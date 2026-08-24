"""
ScanJob ORM Model
Tracks background scan jobs
"""
from sqlalchemy import Column, String, DateTime, Text, Enum as SQLEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum
from datetime import datetime

from .base import Base


class ScanJobStatus(str, enum.Enum):
    """Job status enum"""
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanJob(Base):
    """
    Scan Job Model
    Tracks async scan jobs from queue
    """
    __tablename__ = "scan_jobs"
    
    job_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_type = Column(String(50), nullable=False)  # GITHUB_WEBHOOK, MANUAL
    
    # Target
    target_repo = Column(Text, nullable=False)
    target_commit = Column(String(40), nullable=True)
    target_branch = Column(String(100), nullable=False)
    
    # Metadata
    triggered_by = Column(String(100), nullable=False)
    status = Column(SQLEnum(ScanJobStatus), nullable=False, default=ScanJobStatus.QUEUED)
    
    # Linked scan (when completed)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<ScanJob {self.job_id} status={self.status}>"