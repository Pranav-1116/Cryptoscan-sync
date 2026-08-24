"""
Fallback handler for unknown algorithms.
"""
from typing import Dict, Any
from ..models.normalized_crypto import NormalizedCrypto


class FallbackHandler:
    """
    Handles algorithms that don't match any normalization rules.
    
    Creates UNKNOWN normalized crypto objects for manual review.
    """
    
    def handle_unknown(
        self,
        raw_algorithm: str,
        context: Dict[str, Any]
    ) -> NormalizedCrypto:
        """
        Create normalized crypto object for unknown algorithm.
        
        Args:
            raw_algorithm: Raw algorithm string
            context: Additional context from scanner
            
        Returns:
            NormalizedCrypto marked as UNKNOWN
        """
        return NormalizedCrypto(
            algorithm='UNKNOWN',
            algorithm_family='unknown',
            standard_name=raw_algorithm,
            mode=context.get('mode'),
            padding=context.get('padding'),
            key_size=context.get('key_size'),
            purpose=context.get('purpose'),
            raw_input=raw_algorithm,
            requires_manual_review=True,
        )