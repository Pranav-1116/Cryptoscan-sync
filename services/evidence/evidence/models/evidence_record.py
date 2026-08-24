"""
Evidence record data model.
Represents a single finding with cryptographic integrity proofs.
"""
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class EvidenceRecord(BaseModel):
    """
    Evidence record with tamper-proof integrity.
    
    This is the authoritative record of a cryptographic finding,
    including all integrity proofs (hashes, chain linkage).
    """
    
    # Unique identifiers
    evidence_id: str = Field(..., description="Unique evidence record ID (UUID)")
    scan_id: str = Field(..., description="Parent scan session ID")
    
    # Content integrity
    content_hash: str = Field(..., description="SHA-256 hash of finding content")
    
    # Chain integrity
    chain_position: int = Field(..., ge=0, description="Position in evidence chain")
    chain_hash: Optional[str] = Field(None, description="Blockchain-style chain hash")
    previous_hash: Optional[str] = Field(None, description="Previous finding's chain hash")
    
    # Original finding data (immutable)
    finding: Dict[str, Any] = Field(..., description="Complete raw finding data")
    
    # Provenance metadata
    created_at: str = Field(..., description="Evidence record creation timestamp (ISO-8601)")
    
    # Integrity metadata
    integrity: Dict[str, Any] = Field(
        default_factory=lambda: {
            'hash_algorithm': 'SHA-256',
            'canonical_form': 'sorted-json-utf8',
            'hash_includes': ['finding'],
            'hash_excludes': ['evidence_id', 'created_at'],
        },
        description="Integrity computation metadata"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
                "scan_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
                "content_hash": "a1b2c3d4e5f6789...",
                "chain_position": 0,
                "chain_hash": "x1y2z3w4v5u6...",
                "previous_hash": None,
                "finding": {
                    "algorithm": "DES",
                    "file_path": "Payment.java",
                    "line_number": 247
                },
                "created_at": "2024-01-15T08:22:31Z"
            }
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.model_dump()
    
    def verify_content_hash(self) -> bool:
        """
        Verify that stored content_hash matches finding data.
        
        Returns:
            True if hash is valid, False if tampered
        """
        from ..hashing.content_hasher import ContentHasher
        return ContentHasher.verify_hash(self.finding, self.content_hash)