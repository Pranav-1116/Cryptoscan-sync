"""
Drift Repository
CRUD operations for drift events
"""
import logging
from typing import Optional, List
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import and_

from ..models.drift_event import DriftEvent
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class DriftRepository(BaseRepository[DriftEvent]):
    """Repository for DriftEvent model"""
    
    def __init__(self, db: Session):
        super().__init__(DriftEvent, db)
    
    def create(
        self,
        baseline_id: str,
        current_scan_id: str,
        drift_type: str,
        severity: str,
        drift_details: dict
    ) -> DriftEvent:
        """Create drift event"""
        event = DriftEvent(
            baseline_id=baseline_id,
            current_scan_id=current_scan_id,
            drift_type=drift_type,
            severity=severity,
            drift_details=drift_details,
            resolution_status="OPEN"
        )
        
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        
        logger.info(f"Created drift event {event.drift_id} severity={severity}")
        return event
    
    def get_by_scan(self, scan_id: str) -> List[DriftEvent]:
        """Get drift events for scan"""
        return self.db.query(DriftEvent)\
            .filter(DriftEvent.current_scan_id == scan_id)\
            .all()
    
    def get_open_events(
        self,
        severity: Optional[str] = None
    ) -> List[DriftEvent]:
        """Get open drift events"""
        query = self.db.query(DriftEvent)\
            .filter(DriftEvent.resolution_status == "OPEN")
        
        if severity:
            query = query.filter(DriftEvent.severity == severity)
        
        return query.order_by(DriftEvent.detected_at.desc()).all()
    
    def acknowledge(
        self,
        drift_id: str,
        acknowledged_by: str,
        notes: Optional[str] = None
    ):
        """Acknowledge drift event"""
        event = self.get_by_id(drift_id)
        if not event:
            raise ValueError(f"Drift event {drift_id} not found")
        
        event.resolution_status = "ACKNOWLEDGED"
        event.resolved_by = acknowledged_by
        event.resolved_at = datetime.utcnow()
        event.resolution_notes = notes
        
        self.db.commit()
        logger.info(f"Acknowledged drift event {drift_id}")
    
    def resolve(
        self,
        drift_id: str,
        resolved_by: str,
        notes: Optional[str] = None
    ):
        """Resolve drift event"""
        event = self.get_by_id(drift_id)
        if not event:
            raise ValueError(f"Drift event {drift_id} not found")
        
        event.resolution_status = "RESOLVED"
        event.resolved_by = resolved_by
        event.resolved_at = datetime.utcnow()
        event.resolution_notes = notes
        
        self.db.commit()
        logger.info(f"Resolved drift event {drift_id}")
    
    def mark_false_positive(
        self,
        drift_id: str,
        marked_by: str,
        notes: Optional[str] = None
    ):
        """Mark as false positive"""
        event = self.get_by_id(drift_id)
        if not event:
            raise ValueError(f"Drift event {drift_id} not found")
        
        event.resolution_status = "FALSE_POSITIVE"
        event.resolved_by = marked_by
        event.resolved_at = datetime.utcnow()
        event.resolution_notes = notes
        
        self.db.commit()
        logger.info(f"Marked drift event {drift_id} as false positive")