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
    
    def handle(self, raw_algorithm: str, context: Dict[str, Any] | None = None, **kwargs) -> NormalizedCrypto:
        ctx = dict(context or {})
        if kwargs.get("purpose") is not None:
            ctx["purpose"] = kwargs["purpose"]
        if kwargs.get("key_size") is not None:
            ctx["key_size"] = kwargs["key_size"]
        result = self.handle_unknown(raw_algorithm, ctx)
        if kwargs.get("normalization_version"):
            result.normalization_version = kwargs["normalization_version"]
        if kwargs.get("timestamp"):
            result.normalization_timestamp = kwargs["timestamp"]
        return result

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
            normalization_confidence="LOW",
            needs_human_review=True,
            review_reason="No normalization rule matched",
        )