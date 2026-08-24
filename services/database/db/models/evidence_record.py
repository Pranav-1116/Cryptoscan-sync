# services/database/db/models/evidence_record.py

"""
Production ORM model for evidence records.
Represents a single cryptographic finding with integrity proofs.
"""

from sqlalchemy import (
    Column, String, Integer, Boolean, Text, ForeignKey,
    Index, CheckConstraint, Enum
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
import enum

from db.connection.session import BaseModel


class Confidence(str, enum.Enum):
    """Confidence level of finding."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ComplianceStatus(str, enum.Enum):
    """Compliance evaluation result."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class EvidenceRecord(BaseModel):
    """
    ORM model for cryptographic evidence/findings.
    One record per discovered crypto API call, algorithm, certificate, etc.
    
    Includes SHA-256 content hash and blockchain-style chain hash for tamper detection.
    
    Fields:
        evidence_id: UUID primary key
        scan_id: Foreign key to Scan
        content_hash: SHA-256 of finding (for tamper detection)
        chain_hash: Blockchain-style chain hash (links to previous finding)
        chain_position: Position in evidence chain (0-indexed)
        previous_hash: Chain hash of previous evidence (null if first)
        
        -- Extracted Fields (for fast queries without JSON parsing)
        algorithm: Canonical algorithm name (AES, RSA, SHA-256, etc.)
        key_size: Key length in bits (128, 256, 2048, etc.)
        mode: Block cipher mode (GCM, ECB, CBC, etc.)
        padding: Padding scheme (PKCS5Padding, NoPadding, etc.)
        purpose: Crypto purpose (ENCRYPTION, HASHING, SIGNING, KEY_EXCHANGE)
        confidence: HIGH, MEDIUM, LOW
        is_hardcoded_key: True if hardcoded cryptographic key detected
        
        -- Source Location
        file_path: Relative path to source file
        line_number: Line number of crypto call
        class_name: Fully-qualified class name
        method_name: Method containing crypto call
        
        -- Full Data (immutable)
        finding_data: Complete raw finding (Pydantic model as JSON)
        provenance: Scanner metadata (version, scan_id, etc.)
        
        -- Policy Evaluation (added later in pipeline)
        normalized_crypto: Normalized/canonical form with NIST/IANA metadata
        policy_evaluation: Policy rule evaluation results
        compliance_status: PASS, FAIL, WARN
        
        created_at: Record creation time (auto)
        updated_at: Last update time (auto)
    """
    
    __tablename__ = "evidence_records"
    
    # Relationship to Scan
    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    scan = relationship("Scan", back_populates="evidence_records")
    
    # ========== Integrity Chain (Tamper Detection) ==========
    content_hash = Column(
        String(64),  # SHA-256 hex (64 chars)
        nullable=False,
        index=True,
        comment="SHA-256 hash of finding content (tamper detection)",
    )
    
    chain_hash = Column(
        String(64),  # SHA-256 hex
        nullable=False,
        comment="Blockchain-style chain hash (links evidence chain)",
    )
    
    chain_position = Column(
        Integer,
        nullable=False,
        index=True,
        comment="Position in evidence chain (0-indexed)",
    )
    
    previous_hash = Column(
        String(64),  # SHA-256 hex
        nullable=True,
        comment="Chain hash of previous evidence record (null if first)",
    )
    
    # ========== Extracted Fields (Fast Queries) ==========
    algorithm = Column(
        String(50),
        nullable=False,
        index=True,
    )
    
    key_size = Column(
        Integer,
        nullable=True,
    )
    
    mode = Column(
        String(50),
        nullable=True,
    )
    
    padding = Column(
        String(50),
        nullable=True,
    )
    
    purpose = Column(
        String(50),
        nullable=True,
    )
    
    confidence = Column(
        Enum(Confidence),
        nullable=False,
        index=True,
    )
    
    is_hardcoded_key = Column(
        Boolean,
        default=False,
        index=True,
        comment="True if hardcoded cryptographic key detected",
    )
    
    # ========== Source Location ==========
    file_path = Column(
        Text,
        nullable=False,
        index=True,
    )
    
    line_number = Column(
        Integer,
        nullable=False,
    )
    
    class_name = Column(
        Text,
        nullable=True,
    )
    
    method_name = Column(
        String(200),
        nullable=True,
    )
    
    # ========== Full Data (Immutable) ==========
    finding_data = Column(
        JSONB,
        nullable=False,
        comment="Complete raw finding as JSON (RawFinding model)",
    )
    
    provenance = Column(
        JSONB,
        nullable=True,
        comment="Scanner metadata (version, scan_session_id, etc.)",
    )
    
    # ========== Normalization & Policy (Added Later) ==========
    normalized_crypto = Column(
        JSONB,
        nullable=True,
        comment="Normalized crypto form with NIST/IANA metadata",
    )
    
    policy_evaluation = Column(
        JSONB,
        nullable=True,
        comment="Policy rule evaluation results",
    )
    
    compliance_status = Column(
        Enum(ComplianceStatus),
        nullable=True,
        index=True,
    )
    
    # ========== Indexes ==========
    __table_args__ = (
        # Query by scan + position (verify chain)
        Index("idx_evidence_scan_position", "scan_id", "chain_position", unique=True),
        # Query by algorithm
        Index("idx_evidence_algorithm", "algorithm"),
        # Query hardcoded keys
        Index("idx_evidence_hardcoded_key", "is_hardcoded_key", 
              postgresql_where=Column("is_hardcoded_key") == True),
        # Query by compliance status
        Index("idx_evidence_compliance", "compliance_status"),
        # Check SHA-256 length
        CheckConstraint(
            "length(content_hash) = 64",
            name="ck_evidence_content_hash_length",
        ),
        CheckConstraint(
            "length(chain_hash) = 64",
            name="ck_evidence_chain_hash_length",
        ),
        CheckConstraint(
            "chain_position >= 0",
            name="ck_evidence_chain_position_positive",
        ),
    )
    
    def __init__(
        self,
        scan_id: str,
        content_hash: str,
        chain_hash: str,
        chain_position: int,
        algorithm: str,
        confidence: Confidence,
        file_path: str,
        line_number: int,
        finding_data: dict,
        previous_hash: str = None,
        **kwargs
    ):
        """Initialize evidence record."""
        self.scan_id = scan_id
        self.content_hash = content_hash
        self.chain_hash = chain_hash
        self.chain_position = chain_position
        self.algorithm = algorithm
        self.confidence = confidence
        self.file_path = file_path
        self.line_number = line_number
        self.finding_data = finding_data
        self.previous_hash = previous_hash
        
        # Optional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @property
    def is_first_in_chain(self) -> bool:
        """Check if this is the first evidence record in chain."""
        return self.chain_position == 0 and self.previous_hash is None
    
    @property
    def integrity_verified(self) -> bool:
        """
        Quick integrity check (not cryptographic verification).
        Checks if hashes are populated and chain position is valid.
        """
        return (
            self.content_hash is not None and len(self.content_hash) == 64 and
            self.chain_hash is not None and len(self.chain_hash) == 64 and
            self.chain_position >= 0
        )
    
    def to_dict(self, include_raw_finding: bool = False) -> dict:
        """
        Convert to dictionary for JSON responses.
        
        Args:
            include_raw_finding: Include full finding_data in output
        
        Returns:
            Dictionary representation
        """
        data = super().to_dict()
        
        # Add computed fields
        data["is_first_in_chain"] = self.is_first_in_chain
        data["integrity_verified"] = self.integrity_verified
        
        # Optionally include raw finding
        if not include_raw_finding:
            data.pop("finding_data", None)
            data.pop("provenance", None)
        
        return data
    
    def __repr__(self) -> str:
        return (
            f"<EvidenceRecord(id={self.id}, algo={self.algorithm}, "
            f"line={self.line_number}, status={self.compliance_status})>"
        )