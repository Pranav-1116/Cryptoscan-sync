"""
Main normalization engine.
Orchestrates normalization of evidence records.
"""
import logging
from typing import List, Dict, Any
from ..rules.rule_loader import RuleLoader
from ..matchers.exact_matcher import ExactMatcher
from ..matchers.pattern_matcher import PatternMatcher
from ..matchers.fallback_handler import FallbackHandler
from ..enrichers.nist_enricher import NISTEnricher
from ..enrichers.iana_enricher import IANAEnricher
from ..enrichers.cbom_enricher import CBOMEnricher
from ..enrichers.family_enricher import FamilyEnricher
from ..models.normalized_crypto import NormalizedCrypto

logger = logging.getLogger(__name__)


class NormalizationEngine:
    """
    Main normalization engine.
    
    Converts raw algorithm names to canonical CBOM format with enrichment.
    """
    
    def __init__(self, rules_directory: str):
        """
        Initialize normalization engine.
        
        Args:
            rules_directory: Path to YAML rule definitions
        """
        self.rule_loader = RuleLoader(rules_directory)
        self.rules = self.rule_loader.load_all_rules()
        
        # Matchers
        self.exact_matcher = ExactMatcher(self.rules)
        self.pattern_matcher = PatternMatcher()
        self.fallback_handler = FallbackHandler()
        
        # Enrichers
        self.nist_enricher = NISTEnricher()
        self.iana_enricher = IANAEnricher()
        self.cbom_enricher = CBOMEnricher()
        self.family_enricher = FamilyEnricher()
        
        logger.info(f"Loaded {len(self.rules)} normalization rules")
    
    def normalize(self, raw_algorithm: str, context: Dict[str, Any] = None) -> NormalizedCrypto:
        """
        Normalize a raw algorithm string.
        
        Args:
            raw_algorithm: Raw algorithm name (e.g., "DES", "AES/GCM/NoPadding")
            context: Additional context (mode, key_size from scanner)
            
        Returns:
            NormalizedCrypto object with canonical representation
        """
        context = context or {}
        
        logger.debug(f"Normalizing algorithm: {raw_algorithm}")
        
        # Step 1: Try exact match
        normalized = self.exact_matcher.match(raw_algorithm)
        
        if normalized:
            logger.debug(f"Exact match found for {raw_algorithm}")
            confidence = "HIGH"
        else:
            # Step 2: Try pattern matching
            normalized = self.pattern_matcher.match(raw_algorithm)
            
            if normalized:
                logger.debug(f"Pattern match found for {raw_algorithm}")
                confidence = "MEDIUM"
            else:
                # Step 3: Fallback to UNKNOWN
                logger.warning(f"No normalization rule for {raw_algorithm}")
                normalized = self.fallback_handler.handle_unknown(raw_algorithm, context)
                confidence = "LOW"
        
        # Step 4: Enrich with additional metadata
        normalized = self._enrich(normalized)
        
        # Step 5: Add normalization metadata
        normalized.normalization_confidence = confidence
        normalized.normalization_version = "1.0"
        normalized.raw_input = raw_algorithm
        
        return normalized
    
    def _enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        """
        Enrich normalized crypto with additional metadata.
        
        Args:
            normalized: Base normalized crypto object
            
        Returns:
            Enriched object
        """
        # Add NIST designation
        normalized = self.nist_enricher.enrich(normalized)
        
        # Add IANA ID
        normalized = self.iana_enricher.enrich(normalized)
        
        # Add CBOM fields
        normalized = self.cbom_enricher.enrich(normalized)
        
        # Add algorithm family
        normalized = self.family_enricher.enrich(normalized)
        
        return normalized
    
    def normalize_batch(
        self,
        evidence_records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Normalize multiple evidence records in batch.
        
        Args:
            evidence_records: List of evidence record dictionaries
            
        Returns:
            Updated evidence records with normalized_crypto field
        """
        logger.info(f"Normalizing {len(evidence_records)} evidence records")
        
        for record in evidence_records:
            finding = record.get('finding', {})
            crypto = finding.get('crypto', {})
            raw_algorithm = crypto.get('algorithm', 'UNKNOWN')
            
            # Normalize
            normalized = self.normalize(
                raw_algorithm,
                context={
                    'mode': crypto.get('mode'),
                    'key_size': crypto.get('key_size'),
                    'padding': crypto.get('padding'),
                    'purpose': crypto.get('purpose'),
                }
            )
            
            # Add to record
            record['normalized_crypto'] = normalized.to_dict()
        
        return evidence_records