"""
CBOM (Cryptography Bill of Materials) enricher.
Adds CycloneDX CBOM-specific fields.
"""
from ..models.normalized_crypto import NormalizedCrypto


class CBOMEnricher:
    """
    Enriches normalized crypto with CycloneDX CBOM fields.
    
    Based on CycloneDX CBOM specification:
    https://cyclonedx.org/capabilities/cbom/
    """
    
    def enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        """
        Add CBOM fields to normalized crypto.
        
        Args:
            normalized: Base normalized crypto object
            
        Returns:
            Enriched object with CBOM fields
        """
        if not normalized.cbom_component_type:
            normalized.cbom_component_type = 'cryptographic-asset'
        if not normalized.cbom_algorithm_ref:
            normalized.cbom_algorithm_ref = self._generate_cbom_urn(normalized)
        
        return normalized
    
    def _generate_cbom_urn(self, normalized: NormalizedCrypto) -> str:
        """
        Generate CBOM URN for algorithm.
        
        Format: urn:ietf:crypto:<algorithm>:<mode>:<keysize>
        """
        parts = ['urn', 'ietf', 'crypto']
        
        if normalized.algorithm:
            parts.append(normalized.algorithm.lower())
        
        if normalized.mode:
            parts.append(normalized.mode.lower())
        
        if normalized.key_size:
            parts.append(str(normalized.key_size))
        
        return ':'.join(parts)


CbomEnricher = CBOMEnricher