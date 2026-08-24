"""
DriftEvent ORM Model
Detected drift from baseline
"""
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from datetime import datetime

from .base import Base


class DriftEvent(Base):
    """
    Drift Event Model
    Records detected drift from baseline
    """
    __tablename__ = "drift_events"
    
    drift_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Baseline reference
    baseline_id = Column(UUID(as_uuid=True), ForeignKey("baselines.baseline_id"), nullable=False, index=True)
    
    # Current scan
    current_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.scan_id"), nullable=False, index=True)
    
    # Detection
    detected_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Drift details
    drift_type = Column(String(50), nullable=False)  # NEW_CRYPTO, REMOVED_CRYPTO
    severity = Column(String(20), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, INFO
    
    drift_details = Column(JSONB, nullable=False)  # Full drift data
    
    # Resolution tracking
    resolution_status = Column(String(50), nullable=False, default="OPEN")  # OPEN, ACKNOWLEDGED, FALSE_POSITIVE, RESOLVED
    resolved_by = Column(String(100), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<DriftEvent {self.drift_id} type={self.drift_type} severity={self.severity}>"