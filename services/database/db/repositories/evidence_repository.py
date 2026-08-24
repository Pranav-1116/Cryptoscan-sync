"""
Repository for evidence_records table operations.
"""
from typing import List, Optional, Dict, Any
from sqlalchemy import select, and_, func
from sqlalchemy.orm import Session
from .base_repository import BaseRepository
from ..models.evidence_record import EvidenceRecord


class EvidenceRepository(BaseRepository[EvidenceRecord]):
    """
    Repository for EvidenceRecord model with custom query methods.
    """
    
    def __init__(self, session: Session):
        super().__init__(EvidenceRecord, session)
    
    def get_by_scan_id(
        self,
        scan_id: str,
        order_by_position: bool = True
    ) -> List[EvidenceRecord]:
        """
        Get all evidence records for a scan.
        
        Args:
            scan_id: Scan UUID
            order_by_position: Whether to order by chain_position
            
        Returns:
            List of evidence records
        """
        stmt = select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)
        
        if order_by_position:
            stmt = stmt.order_by(EvidenceRecord.chain_position)
        
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_chain_for_verification(self, scan_id: str) -> List[EvidenceRecord]:
        """
        Get evidence chain ordered by position for verification.
        
        Args:
            scan_id: Scan UUID
            
        Returns:
            Ordered list of evidence records
        """
        return self.get_by_scan_id(scan_id, order_by_position=True)
    
    def get_by_algorithm(
        self,
        algorithm: str,
        limit: int = 100
    ) -> List[EvidenceRecord]:
        """
        Get evidence records by algorithm.
        
        Args:
            algorithm: Algorithm name (e.g., 'DES', 'AES')
            limit: Maximum results
            
        Returns:
            List of evidence records
        """
        stmt = (
            select(EvidenceRecord)
            .where(EvidenceRecord.algorithm == algorithm)
            .limit(limit)
        )
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_hardcoded_keys(self, scan_id: Optional[str] = None) -> List[EvidenceRecord]:
        """
        Get all hardcoded key findings.
        
        Args:
            scan_id: Optional scan ID to filter by
            
        Returns:
            List of hardcoded key findings
        """
        stmt = select(EvidenceRecord).where(EvidenceRecord.is_hardcoded_key == True)
        
        if scan_id:
            stmt = stmt.where(EvidenceRecord.scan_id == scan_id)
        
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_by_confidence(
        self,
        confidence: str,
        scan_id: Optional[str] = None
    ) -> List[EvidenceRecord]:
        """
        Get evidence records by confidence level.
        
        Args:
            confidence: Confidence level (HIGH, MEDIUM, LOW)
            scan_id: Optional scan ID to filter by
            
        Returns:
            List of evidence records
        """
        stmt = select(EvidenceRecord).where(EvidenceRecord.confidence == confidence)
        
        if scan_id:
            stmt = stmt.where(EvidenceRecord.scan_id == scan_id)
        
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def get_by_file_path(
        self,
        file_path: str,
        scan_id: Optional[str] = None
    ) -> List[EvidenceRecord]:
        """
        Get evidence records for a specific file.
        
        Args:
            file_path: File path
            scan_id: Optional scan ID to filter by
            
        Returns:
            List of evidence records
        """
        stmt = select(EvidenceRecord).where(EvidenceRecord.file_path == file_path)
        
        if scan_id:
            stmt = stmt.where(EvidenceRecord.scan_id == scan_id)
        
        result = self.session.execute(stmt)
        return list(result.scalars().all())
    
    def count_by_algorithm(self, scan_id: str) -> Dict[str, int]:
        """
        Count findings grouped by algorithm.
        
        Args:
            scan_id: Scan UUID
            
        Returns:
            Dictionary mapping algorithm -> count
        """
        stmt = (
            select(
                EvidenceRecord.algorithm,
                func.count(EvidenceRecord.evidence_id)
            )
            .where(EvidenceRecord.scan_id == scan_id)
            .group_by(EvidenceRecord.algorithm)
        )
        
        result = self.session.execute(stmt)
        return {algorithm: count for algorithm, count in result.all()}
    
    def bulk_insert_with_transaction(
        self,
        evidence_records: List[EvidenceRecord]
    ) -> List[EvidenceRecord]:
        """
        Bulk insert evidence records in a single transaction.
        
        Args:
            evidence_records: List of evidence records to insert
            
        Returns:
            List of inserted records with IDs
        """
        return self.create_many(evidence_records)
    
    def verify_chain_integrity_db(self, scan_id: str) -> bool:
        """
        Verify chain integrity by checking sequential positions in DB.
        
        Args:
            scan_id: Scan UUID
            
        Returns:
            True if chain positions are sequential, False otherwise
        """
        stmt = (
            select(EvidenceRecord.chain_position)
            .where(EvidenceRecord.scan_id == scan_id)
            .order_by(EvidenceRecord.chain_position)
        )
        
        result = self.session.execute(stmt)
        positions = [pos for (pos,) in result.all()]
        
        # Check if positions are 0, 1, 2, 3, ..., N-1
        expected = list(range(len(positions)))
        return positions == expected
    
    def get_by_content_hash(self, content_hash: str) -> Optional[EvidenceRecord]:
        """
        Get evidence record by content hash (for deduplication).
        
        Args:
            content_hash: SHA-256 content hash
            
        Returns:
            Evidence record or None if not found
        """
        stmt = select(EvidenceRecord).where(EvidenceRecord.content_hash == content_hash)
        result = self.session.execute(stmt)
        return result.scalar_one_or_none()