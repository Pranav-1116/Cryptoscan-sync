"""
Repository for scans table operations.
"""
from typing import List, Optional
from sqlalchemy import select, desc, and_
from sqlalchemy.orm import Session
from datetime import datetime
from .base_repository import BaseRepository
from ..models.scan import Scan


class ScanRepository(BaseRepository[Scan]):
    """
    Repository for Scan model with custom query methods.
    """
    
    def __init__(self, session: Session):
        super().__init__(Scan, session)
    
    def get_recent_scans(self, limit: int = 10) -> List[Scan]:
        """
        Get most recent scans ordered by start time.
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of recent scans
        """
        stmt = (
            select(Scan)
            .order_by(desc(Scan.scan_start))
            .limit(limit)
        )
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_by_target_location(self, target_location: str) -> List[Scan]:
        """
        Get all scans for a specific target location.
        
        Args:
            target_location: Repository URL or directory path
            
        Returns:
            List of scans for this target
        """
        stmt = (
            select(Scan)
            .where(Scan.target_location == target_location)
            .order_by(desc(Scan.scan_start))
        )
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_by_commit(self, commit_hash: str) -> List[Scan]:
        """
        Get scans for a specific commit.
        
        Args:
            commit_hash: Git commit hash
            
        Returns:
            List of scans for this commit
        """
        stmt = select(Scan).where(Scan.target_commit == commit_hash)
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_by_status(self, status: str) -> List[Scan]:
        """
        Get scans by status.
        
        Args:
            status: Scan status (RUNNING, COMPLETED, FAILED, CANCELLED)
            
        Returns:
            List of scans with this status
        """
        stmt = (
            select(Scan)
            .where(Scan.status == status)
            .order_by(desc(Scan.scan_start))
        )
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_running_scans(self) -> List[Scan]:
        """
        Get all currently running scans.
        
        Returns:
            List of running scans
        """
        return self.get_by_status('RUNNING')
    
    def mark_completed(
        self,
        scan_id: str,
        statistics: dict,
        manifest_hash: str
    ) -> Optional[Scan]:
        """
        Mark scan as completed with results.
        
        Args:
            scan_id: Scan UUID
            statistics: Scan statistics dictionary
            manifest_hash: Evidence manifest hash
            
        Returns:
            Updated scan or None if not found
        """
        return self.update(
            scan_id,
            {
                'status': 'COMPLETED',
                'scan_end': datetime.utcnow(),
                'statistics': statistics,
                'manifest_hash': manifest_hash,
            }
        )
    
    def mark_failed(self, scan_id: str, error_message: str) -> Optional[Scan]:
        """
        Mark scan as failed.
        
        Args:
            scan_id: Scan UUID
            error_message: Error description
            
        Returns:
            Updated scan or None if not found
        """
        return self.update(
            scan_id,
            {
                'status': 'FAILED',
                'scan_end': datetime.utcnow(),
                'statistics': {'error': error_message},
            }
        )
    
    def get_scans_between_dates(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Scan]:
        """
        Get scans within date range.
        
        Args:
            start_date: Start of date range
            end_date: End of date range
            
        Returns:
            List of scans in range
        """
        stmt = (
            select(Scan)
            .where(
                and_(
                    Scan.scan_start >= start_date,
                    Scan.scan_start <= end_date
                )
            )
            .order_by(desc(Scan.scan_start))
        )
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_latest_completed_for_target(
        self,
        target_location: str
    ) -> Optional[Scan]:
        """
        Get most recent completed scan for a target.
        
        Args:
            target_location: Repository URL or directory
            
        Returns:
            Latest completed scan or None
        """
        stmt = (
            select(Scan)
            .where(
                and_(
                    Scan.target_location == target_location,
                    Scan.status == 'COMPLETED'
                )
            )
            .order_by(desc(Scan.scan_start))
            .limit(1)
        )
        result = self.session.execute(stmt)
        return result.scalar_one_or_none()