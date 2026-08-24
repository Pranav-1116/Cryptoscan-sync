"""
Exact match normalization matcher.
"""
from typing import Optional, List
from ..models.normalization_rule import NormalizationRule
from ..models.normalized_crypto import NormalizedCrypto


class ExactMatcher:
    """
    Performs exact string matching for normalization.
    
    Fast O(1) lookup using dictionary.
    """
    
    def __init__(self, rules: List[NormalizationRule]):
        """
        Initialize exact matcher.
        
        Args:
            rules: List of normalization rules
        """
        # Build lookup dictionary for O(1) access
        self.rule_map = {
            rule.pattern.upper(): rule
            for rule in rules
        }
    
    def match(self, raw_algorithm: str) -> Optional[NormalizedCrypto]:
        """
        Attempt exact match normalization.
        
        Args:
            raw_algorithm: Raw algorithm string
            
        Returns:
            NormalizedCrypto if exact match found, None otherwise
        """
        # Case-insensitive lookup
        key = raw_algorithm.upper()
        
        rule = self.rule_map.get(key)
        
        if rule:
            return NormalizedCrypto(**rule.output)
        
        return None