"""
Evidence pipeline orchestrator.
Transforms raw findings into tamper-proof evidence records.
"""
import uuid
from datetime import datetime
from typing import List, Dict, Any
from ..hashing.content_hasher import ContentHasher
from ..hashing.chain_hasher import ChainHasher
from ..models.evidence_record import EvidenceRecord
from ..models.scan_manifest import ScanManifest
import logging

logger = logging.getLogger(__name__)


class EvidencePipeline:
    """
    Orchestrates creation of tamper-proof evidence records from raw findings.
    
    Pipeline stages:
    1. Compute content hashes
    2. Create evidence records
    3. Compute chain hashes
    4. Create scan manifest
    """
    
    def __init__(self, scan_session_id: str):
        """
        Initialize evidence pipeline.
        
        Args:
            scan_session_id: Unique ID for this scan session
        """
        self.scan_session_id = scan_session_id
        self.evidence_records: List[EvidenceRecord] = []
        
    def process_findings(self, findings: List[Dict[str, Any]]) -> List[EvidenceRecord]:
        """
        Process raw findings into evidence records.
        
        Args:
            findings: List of raw finding dictionaries
            
        Returns:
            List of evidence records with integrity proofs
        """
        logger.info(f"Processing {len(findings)} findings for scan {self.scan_session_id}")
        
        # Stage 1: Compute content hashes
        logger.debug("Stage 1: Computing content hashes")
        content_hashes = ContentHasher.compute_batch(findings)
        
        # Stage 2: Create evidence records
        logger.debug("Stage 2: Creating evidence records")
        evidence_records = []
        
        for position, finding in enumerate(findings):
            finding_id = finding.get('finding_id', str(uuid.uuid4()))
            content_hash = content_hashes[finding_id]
            
            evidence_record = EvidenceRecord(
                evidence_id=str(uuid.uuid4()),
                scan_id=self.scan_session_id,
                content_hash=content_hash,
                chain_position=position,
                finding=finding,
                created_at=datetime.utcnow().isoformat() + 'Z'
            )
            
            evidence_records.append(evidence_record)
        
        # Stage 3: Compute chain hashes
        logger.debug("Stage 3: Computing chain hashes")
        self._compute_chain_hashes(evidence_records)
        
        self.evidence_records = evidence_records
        
        logger.info(f"Created {len(evidence_records)} evidence records")
        return evidence_records
    
    def _compute_chain_hashes(self, evidence_records: List[EvidenceRecord]) -> None:
        """
        Compute blockchain-style chain hashes for all evidence records.
        
        Modifies evidence_records in-place, adding chain_hash and previous_hash.
        """
        previous_chain_hash = None
        
        for i, record in enumerate(evidence_records):
            # Compute chain hash
            chain_hash = ChainHasher.compute_chain_hash(
                content_hash=record.content_hash,
                previous_chain_hash=previous_chain_hash,
                scan_session_id=self.scan_session_id if i == 0 else None
            )
            
            # Update record
            record.chain_hash = chain_hash
            record.previous_hash = previous_chain_hash
            
            # Update for next iteration
            previous_chain_hash = chain_hash
    
    def create_manifest(self) -> ScanManifest:
        """
        Create scan manifest with integrity proof.
        
        Returns:
            ScanManifest with summary and verification data
        """
        if not self.evidence_records:
            raise ValueError("No evidence records to create manifest from")
        
        first_hash = self.evidence_records[0].chain_hash
        last_hash = self.evidence_records[-1].chain_hash
        
        # Compute manifest hash (hash of all evidence IDs sorted)
        evidence_ids = sorted([r.evidence_id for r in self.evidence_records])
        manifest_content = ''.join(evidence_ids)
        import hashlib
        manifest_hash = hashlib.sha256(manifest_content.encode('utf-8')).hexdigest()
        
        manifest = ScanManifest(
            manifest_id=str(uuid.uuid4()),
            scan_session_id=self.scan_session_id,
            created_at=datetime.utcnow().isoformat() + 'Z',
            total_findings=len(self.evidence_records),
            first_chain_hash=first_hash,
            last_chain_hash=last_hash,
            manifest_hash=manifest_hash,
            evidence_records=[
                {
                    'evidence_id': r.evidence_id,
                    'content_hash': r.content_hash,
                    'chain_hash': r.chain_hash,
                    'chain_position': r.chain_position,
                }
                for r in self.evidence_records
            ]
        )
        
        return manifest
    
    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        """
        Verify integrity of created evidence records.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        return ChainHasher.verify_chain([
            {
                'chain_position': r.chain_position,
                'content_hash': r.content_hash,
                'chain_hash': r.chain_hash,
                'scan_session_id': self.scan_session_id,
            }
            for r in self.evidence_records
        ])