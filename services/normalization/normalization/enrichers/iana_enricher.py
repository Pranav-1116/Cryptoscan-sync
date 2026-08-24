"""
IANA algorithm ID enricher.
Adds IANA registry identifiers to normalized crypto.
"""
from ..models.normalized_crypto import NormalizedCrypto


class IANAEnricher:
    """
    Enriches normalized crypto with IANA algorithm identifiers.
    
    Based on IANA TLS Cipher Suite Registry:
    https://www.iana.org/assignments/tls-parameters/
    """
    
    # IANA ID mappings (subset for common algorithms)
    IANA_MAPPINGS = {
        ('AES', 'GCM', 128): 'aes128-gcm',
        ('AES', 'GCM', 256): 'aes256-gcm',
        ('AES', 'CBC', 128): 'aes128-cbc',
        ('AES', 'CBC', 256): 'aes256-cbc',
        ('CHACHA20', 'POLY1305', 256): 'chacha20-poly1305',
        ('3DES', 'EDE', 168): '3des-ede-cbc',
    }
    
    def enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        """
        Add IANA ID to normalized crypto.
        
        Args:
            normalized: Base normalized crypto object
            
        Returns:
            Enriched object with IANA ID
        """
        if normalized.iana_id:
            return normalized

        # Create lookup key
        key = (
            normalized.algorithm.upper() if normalized.algorithm else None,
            normalized.mode.upper() if normalized.mode else None,
            normalized.key_size
        )
        
        # Lookup IANA ID
        iana_id = self.IANA_MAPPINGS.get(key)
        
        if iana_id:
            normalized.iana_id = iana_id
        else:
            # Generate synthetic ID
            normalized.iana_id = self._generate_synthetic_id(normalized)
        
        return normalized
    
    def _generate_synthetic_id(self, normalized: NormalizedCrypto) -> str:
        """Generate synthetic IANA-style ID for algorithms not in registry."""
        parts = [normalized.algorithm.lower() if normalized.algorithm else 'unknown']
        
        if normalized.key_size:
            parts.append(str(normalized.key_size))
        
        if normalized.mode:
            parts.append(normalized.mode.lower())
        
        return '-'.join(parts)


IanaEnricher = IANAEnricher