"""
Scan manifest data model.
Represents the complete integrity proof for a scan session.
"""
from typing import List, Dict, Any
from pydantic import BaseModel, Field


class ScanManifest(BaseModel):
    """
    Manifest of all evidence records for a scan session.
    
    Provides:
    - Summary of total findings
    - First and last chain hashes (for quick verification)
    - Manifest hash (detects record addition/deletion)
    - Full evidence record index
    """
    
    manifest_id: str = Field(..., description="Unique manifest ID")
    scan_session_id: str = Field(..., description="Scan session this manifest covers")
    created_at: str = Field(..., description="Manifest creation timestamp (ISO-8601)")
    
    # Summary
    total_findings: int = Field(..., ge=0, description="Total number of findings")
    first_chain_hash: str = Field(..., description="Chain hash of first finding")
    last_chain_hash: str = Field(..., description="Chain hash of last finding")
    manifest_hash: str = Field(..., description="SHA-256 hash of all evidence IDs")
    
    # Evidence record index
    evidence_records: List[Dict[str, Any]] = Field(
        ...,
        description="Index of all evidence records (id, hashes, position)"
    )
    
    # Integrity proof metadata
    integrity_proof: Dict[str, Any] = Field(
        default_factory=lambda: {
            'algorithm': 'SHA-256-chain',
            'verification_instructions': (
                '1. Verify each content_hash matches finding data. '
                '2. Verify each chain_hash = SHA256(content_hash + previous_hash). '
                '3. Verify manifest_hash = SHA256(sorted evidence IDs).'
            )
        },
        description="Verification instructions for auditors"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "manifest_id": "manifest-uuid",
                "scan_session_id": "scan-uuid",
                "created_at": "2024-01-15T08:30:00Z",
                "total_findings": 34,
                "first_chain_hash": "abc123...",
                "last_chain_hash": "xyz789...",
                "manifest_hash": "manifest-hash-abc...",
                "evidence_records": [
                    {
                        "evidence_id": "evidence-1",
                        "content_hash": "hash-1",
                        "chain_hash": "chain-1",
                        "chain_position": 0
                    }
                ]
            }
        }
    
    def verify_manifest_hash(self) -> bool:
        """
        Verify that manifest_hash matches evidence record IDs.
        
        Returns:
            True if valid, False if tampered
        """
        import hashlib
        
        # Sort evidence IDs
        evidence_ids = sorted([r['evidence_id'] for r in self.evidence_records])
        
        # Compute hash
        manifest_content = ''.join(evidence_ids)
        computed_hash = hashlib.sha256(manifest_content.encode('utf-8')).hexdigest()
        
        return computed_hash == self.manifest_hash