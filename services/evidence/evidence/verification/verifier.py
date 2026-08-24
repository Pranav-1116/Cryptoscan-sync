"""
Main evidence verification engine.
Verifies integrity of evidence records and manifests.
"""
from typing import List, Dict, Any, Tuple, Optional
from ..hashing.content_hasher import ContentHasher
from ..hashing.chain_hasher import ChainHasher
from ..models.evidence_record import EvidenceRecord
from ..models.scan_manifest import ScanManifest
import logging

logger = logging.getLogger(__name__)


class VerificationResult:
    """Result of evidence verification."""
    
    def __init__(self):
        self.is_valid = True
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
    def add_error(self, message: str):
        """Add verification error."""
        self.errors.append(message)
        self.is_valid = False
        
    def add_warning(self, message: str):
        """Add verification warning."""
        self.warnings.append(message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'is_valid': self.is_valid,
            'errors': self.errors,
            'warnings': self.warnings,
        }


class EvidenceVerifier:
    """
    Verifies integrity of evidence records.
    
    Verification checks:
    1. Content hash verification (tamper detection)
    2. Chain hash verification (linkage integrity)
    3. Manifest hash verification (completeness)
    """
    
    @staticmethod
    def verify_evidence_record(record: EvidenceRecord) -> VerificationResult:
        """
        Verify single evidence record.
        
        Args:
            record: Evidence record to verify
            
        Returns:
            VerificationResult with details
        """
        result = VerificationResult()
        
        # Check 1: Verify content hash
        logger.debug(f"Verifying content hash for {record.evidence_id}")
        
        computed_content_hash = ContentHasher.compute_hash(record.finding)
        if computed_content_hash != record.content_hash:
            result.add_error(
                f"Content hash mismatch for evidence {record.evidence_id}. "
                f"Expected: {record.content_hash}, Got: {computed_content_hash}. "
                f"TAMPER DETECTED."
            )
        
        return result
    
    @staticmethod
    def verify_evidence_chain(
        evidence_records: List[EvidenceRecord],
        scan_session_id: str
    ) -> VerificationResult:
        """
        Verify entire evidence chain.
        
        Args:
            evidence_records: List of evidence records (must be sorted by chain_position)
            scan_session_id: Expected scan session ID
            
        Returns:
            VerificationResult with details
        """
        result = VerificationResult()
        
        if not evidence_records:
            result.add_warning("No evidence records to verify")
            return result
        
        logger.info(f"Verifying chain of {len(evidence_records)} evidence records")
        
        # Check 1: Verify records are sorted
        for i, record in enumerate(evidence_records):
            if record.chain_position != i:
                result.add_error(
                    f"Chain position mismatch at index {i}. "
                    f"Expected position {i}, got {record.chain_position}"
                )
        
        # Check 2: Verify each content hash
        for record in evidence_records:
            record_result = EvidenceVerifier.verify_evidence_record(record)
            if not record_result.is_valid:
                result.errors.extend(record_result.errors)
                result.is_valid = False
        
        # Check 3: Verify chain hashes
        logger.debug("Verifying chain hashes")
        previous_chain_hash = None
        
        for i, record in enumerate(evidence_records):
            expected_chain_hash = ChainHasher.compute_chain_hash(
                content_hash=record.content_hash,
                previous_chain_hash=previous_chain_hash,
                scan_session_id=scan_session_id if i == 0 else None
            )
            
            if record.chain_hash != expected_chain_hash:
                result.add_error(
                    f"Chain hash mismatch at position {i}. "
                    f"Expected: {expected_chain_hash}, Got: {record.chain_hash}. "
                    f"CHAIN BROKEN - Tampering or reordering detected."
                )
            
            # Verify previous_hash linkage
            if record.previous_hash != previous_chain_hash:
                result.add_error(
                    f"Previous hash mismatch at position {i}. "
                    f"Expected: {previous_chain_hash}, Got: {record.previous_hash}"
                )
            
            previous_chain_hash = record.chain_hash
        
        if result.is_valid:
            logger.info("Chain verification PASSED")
        else:
            logger.error(f"Chain verification FAILED with {len(result.errors)} errors")
        
        return result
    
    @staticmethod
    def verify_manifest(
        manifest: ScanManifest,
        evidence_records: List[EvidenceRecord]
    ) -> VerificationResult:
        """
        Verify scan manifest against evidence records.
        
        Args:
            manifest: Scan manifest
            evidence_records: Actual evidence records
            
        Returns:
            VerificationResult with details
        """
        result = VerificationResult()
        
        logger.info(f"Verifying manifest {manifest.manifest_id}")
        
        # Check 1: Count matches
        if manifest.total_findings != len(evidence_records):
            result.add_error(
                f"Finding count mismatch. Manifest claims {manifest.total_findings}, "
                f"but found {len(evidence_records)} records. "
                f"Records may have been added or deleted."
            )
        
        # Check 2: First/last chain hash matches
        if evidence_records:
            if manifest.first_chain_hash != evidence_records[0].chain_hash:
                result.add_error("First chain hash mismatch")
            
            if manifest.last_chain_hash != evidence_records[-1].chain_hash:
                result.add_error("Last chain hash mismatch")
        
        # Check 3: Manifest hash verification
        if not manifest.verify_manifest_hash():
            result.add_error("Manifest hash verification failed. Record set may have changed.")
        
        return result