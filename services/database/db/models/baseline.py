"""
Baseline ORM Model
Approved baseline scans for drift detection
"""
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime

from .base import Base


class Baseline(Base):
    """
    Baseline Model
    Represents an approved baseline scan
    """
    __tablename__ = "baselines"
    
    baseline_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # System identification
    system_identifier = Column(String(200), nullable=False, index=True)  # repo URL
    environment = Column(String(50), nullable=False)  # prod, staging, dev
    
    # Approved scan
    approved_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"), nullable=False)
    
    # Approval metadata
    approved_by = Column(String(100), nullable=False)
    approved_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Status
    status = Column(String(20), nullable=False, default="ACTIVE")  # ACTIVE, SUPERSEDED
    
    # Notes
    notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f"<Baseline {self.baseline_id} system={self.system_identifier} status={self.status}>"