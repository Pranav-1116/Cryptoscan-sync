"""
Baseline Repository
CRUD operations for baselines
"""
import logging
from typing import Optional, List
from datetime import datetime
from sqlalchemy.orm import Session

from ..models.baseline import Baseline
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class BaselineRepository(BaseRepository[Baseline]):
    """Repository for Baseline model"""
    
    def __init__(self, db: Session):
        super().__init__(Baseline, db)
    
    def create(
        self,
        system_identifier: str,
        environment: str,
        approved_scan_id: str,
        approved_by: str,
        notes: Optional[str] = None
    ) -> Baseline:
        """
        Create new baseline
        Supersedes any existing ACTIVE baseline for same system
        """
        # Supersede existing baselines
        existing = self.find_active_baseline(system_identifier, environment)
        if existing:
            existing.status = "SUPERSEDED"
            logger.info(f"Superseded baseline {existing.baseline_id}")
        
        # Create new baseline
        baseline = Baseline(
            system_identifier=system_identifier,
            environment=environment,
            approved_scan_id=approved_scan_id,
            approved_by=approved_by,
            notes=notes,
            status="ACTIVE"
        )
        
        self.db.add(baseline)
        self.db.commit()
        self.db.refresh(baseline)
        
        logger.info(f"Created baseline {baseline.baseline_id} for {system_identifier}")
        return baseline
    
    def find_active_baseline(
        self,
        system_identifier: str,
        environment: str = "prod"
    ) -> Optional[Baseline]:
        """Find active baseline for system"""
        return self.db.query(Baseline)\
            .filter(
                Baseline.system_identifier == system_identifier,
                Baseline.environment == environment,
                Baseline.status == "ACTIVE"
            )\
            .first()
    
    def get_all_active(self) -> List[Baseline]:
        """Get all active baselines"""
        return self.db.query(Baseline)\
            .filter(Baseline.status == "ACTIVE")\
            .all()