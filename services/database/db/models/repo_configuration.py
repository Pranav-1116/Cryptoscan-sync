"""
RepoConfiguration ORM Model
Per-repository scan configuration
"""
from sqlalchemy import Column, String, DateTime, Boolean, ARRAY, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

from .base import Base


class RepoConfiguration(Base):
    """
    Repository Configuration Model
    Defines which repos to scan and how
    """
    __tablename__ = "repo_configurations"
    
    config_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Repository
    repo_url = Column(String(500), nullable=False, unique=True, index=True)
    repo_name = Column(String(200), nullable=False)
    
    # Scan settings
    enabled = Column(Boolean, nullable=False, default=True)
    scan_on_push = Column(Boolean, nullable=False, default=True)
    scan_on_pr = Column(Boolean, nullable=False, default=False)
    
    # Baseline
    baseline_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"), nullable=True)
    
    # Notifications
    notification_emails = Column(ARRAY(String), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<RepoConfiguration {self.repo_name} enabled={self.enabled}>"