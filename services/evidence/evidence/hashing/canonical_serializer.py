"""
Canonical JSON serializer for deterministic hashing.
Ensures identical content always produces identical hash.
"""

import json
from typing import Any, Dict
import logging

logger = logging.getLogger(__name__)


class CanonicalSerializer:
    """
    Serializes data to canonical JSON format.
    
    Requirements:
    - Sorted keys (alphabetical)
    - No whitespace
    - UTF-8 encoding
    - Deterministic float formatting
    """
    
    EXCLUDED_FIELDS = {"evidence_id", "created_at", "scan_timestamp", "finding_id"}
    
    @staticmethod
    def serialize(data: Dict[str, Any]) -> str:
        """
        Serialize data to canonical JSON.
        
        Args:
            data: Dictionary to serialize
            
        Returns:
            Canonical JSON string (no whitespace, sorted keys)
        """
        # Remove runtime-only fields
        cleaned = CanonicalSerializer._clean_data(data)
        
        # Sort keys recursively and serialize
        canonical_json = json.dumps(
            cleaned,
            sort_keys=True,
            separators=(',', ':'),  # No spaces
            ensure_ascii=False,
            default=CanonicalSerializer._json_serializer
        )
        
        return canonical_json
    
    @staticmethod
    def serialize_to_bytes(data: Dict[str, Any]) -> bytes:
        """
        Serialize to canonical JSON bytes (UTF-8).
        
        Args:
            data: Dictionary to serialize
            
        Returns:
            UTF-8 encoded bytes
        """
        canonical_str = CanonicalSerializer.serialize(data)
        return canonical_str.encode('utf-8')
    
    @staticmethod
    def _clean_data(obj: Any) -> Any:
        """Recursively remove excluded fields."""
        if isinstance(obj, dict):
            return {
                k: CanonicalSerializer._clean_data(v)
                for k, v in obj.items()
                if k not in CanonicalSerializer.EXCLUDED_FIELDS
            }
        elif isinstance(obj, list):
            return [CanonicalSerializer._clean_data(item) for item in obj]
        else:
            return obj
    
    @staticmethod
    def _json_serializer(obj: Any) -> str:
        """Handle non-JSON-serializable objects."""
        if hasattr(obj, '__dict__'):
            return CanonicalSerializer._clean_data(obj.__dict__)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")