"""
ScanJob Repository
CRUD operations for scan jobs
"""
import logging
from typing import Optional, List
from datetime import datetime
from sqlalchemy.orm import Session

from ..models.scan_job import ScanJob, ScanJobStatus
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class JobRepository(BaseRepository[ScanJob]):
    """Repository for ScanJob model"""
    
    def __init__(self, db: Session):
        super().__init__(ScanJob, db)
    
    def create(
        self,
        job_id: str,
        job_type: str,
        target_repo: str,
        target_branch: str,
        triggered_by: str,
        target_commit: Optional[str] = None
    ) -> ScanJob:
        """Create new scan job"""
        job = ScanJob(
            job_id=job_id,
            job_type=job_type,
            target_repo=target_repo,
            target_commit=target_commit,
            target_branch=target_branch,
            triggered_by=triggered_by,
            status=ScanJobStatus.QUEUED
        )
        
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        
        logger.info(f"Created scan job: {job_id}")
        return job
    
    def update_status(
        self,
        job_id: str,
        status: ScanJobStatus,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
        scan_id: Optional[str] = None,
        error_message: Optional[str] = None
    ):
        """Update job status"""
        job = self.get_by_id(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")
        
        job.status = status
        
        if started_at:
            job.started_at = started_at
        
        if completed_at:
            job.completed_at = completed_at
        
        if scan_id:
            job.scan_id = scan_id
        
        if error_message:
            job.error_message = error_message
        
        self.db.commit()
        logger.info(f"Updated job {job_id} status to {status}")
    
    def get_recent_jobs(self, limit: int = 50) -> List[ScanJob]:
        """Get recent jobs ordered by created_at"""
        return self.db.query(ScanJob)\
            .order_by(ScanJob.created_at.desc())\
            .limit(limit)\
            .all()
    
    def get_by_status(self, status: ScanJobStatus) -> List[ScanJob]:
        """Get jobs by status"""
        return self.db.query(ScanJob)\
            .filter(ScanJob.status == status)\
            .all()