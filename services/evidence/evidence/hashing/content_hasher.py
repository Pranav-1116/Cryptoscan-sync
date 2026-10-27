"""
SHA-256 content hash computation for evidence tamper detection.
"""

import hashlib
import logging
from typing import Dict, Any

from .canonical_serializer import CanonicalSerializer

logger = logging.getLogger(__name__)


class ContentHasher:
    """
    Computes SHA-256 hash of evidence content.
    
    Process:
    1. Canonicalize JSON (sorted keys, no whitespace)
    2. Encode UTF-8
    3. SHA-256 hash
    4. Output lowercase hex
    """
    
    ALGORITHM = "sha256"
    
    @staticmethod
    def compute_batch(findings: list) -> Dict[str, str]:
        """Hash a list of finding dicts keyed by finding_id."""
        import uuid

        result: Dict[str, str] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                if hasattr(finding, "model_dump"):
                    finding = finding.model_dump(mode="json")
                else:
                    finding = dict(finding)
            finding_id = finding.get("finding_id") or str(uuid.uuid4())
            finding["finding_id"] = finding_id
            digest = ContentHasher.compute_hash(finding)
            if finding_id in result and result[finding_id] != digest:
                raise ValueError(f"conflicting findings share finding_id {finding_id!r}")
            result[finding_id] = digest
        return result

    @staticmethod
    def compute_hash(data: Dict[str, Any]) -> str:
        """
        Compute SHA-256 hash of data.
        
        Args:
            data: Dictionary containing evidence
            
        Returns:
            64-character lowercase hex string
        """
        canonical_bytes = CanonicalSerializer.serialize_to_bytes(data)
        hash_obj = hashlib.sha256(canonical_bytes)
        return hash_obj.hexdigest()
    
    @staticmethod
    def verify_hash(data: Dict[str, Any], expected_hash: str) -> bool:
        """
        Verify that data matches expected hash.
        
        Args:
            data: Dictionary containing evidence
            expected_hash: Expected hash value
            
        Returns:
            True if hash matches, False otherwise
        """
        computed = ContentHasher.compute_hash(data)
        matches = computed == expected_hash
        
        if not matches:
            logger.warning(
                f"Hash mismatch: expected {expected_hash}, got {computed}"
            )
        
        return matches