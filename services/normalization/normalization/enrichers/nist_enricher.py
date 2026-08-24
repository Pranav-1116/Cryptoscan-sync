"""
NIST designation enricher.
Adds NIST approval status to normalized crypto.
"""
import logging
from ..models.normalized_crypto import NormalizedCrypto

logger = logging.getLogger(__name__)


class NISTEnricher:
    """
    Enriches normalized crypto with NIST designation.
    
    Based on:
    - NIST SP 800-131A (Transitioning the Use of Cryptographic Algorithms)
    - NIST SP 800-57 (Key Management)
    """
    
    # NIST designation mappings
    NIST_APPROVED = {
        'AES', 'SHA-256', 'SHA-384', 'SHA-512', 
        'SHA3-256', 'SHA3-384', 'SHA3-512',
        'HMAC', 'ECDSA', 'ECDH',
    }
    
    NIST_DEPRECATED = {
        'DES', '3DES', 'MD5', 'SHA-1', 'RC4',
    }
    
    NIST_ALLOWED_LEGACY = {
        'RSA-2048',  # Allowed until 2030
    }
    
    NIST_DISALLOWED = {
        'DES', 'RC4', 'MD5', 'MD4', 'MD2',
    }
    
    def enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        """
        Add NIST designation to normalized crypto.
        
        Args:
            normalized: Base normalized crypto object
            
        Returns:
            Enriched object with NIST designation
        """
        algorithm = normalized.algorithm.upper()
        
        # Determine NIST status
        if algorithm in self.NIST_DISALLOWED:
            nist_designation = 'DISALLOWED'
        elif algorithm in self.NIST_DEPRECATED:
            nist_designation = 'DEPRECATED'
        elif algorithm in self.NIST_ALLOWED_LEGACY:
            nist_designation = 'ALLOWED_LEGACY'
        elif algorithm in self.NIST_APPROVED:
            nist_designation = 'APPROVED'
        else:
            nist_designation = 'UNKNOWN'
        
        # Special case: RSA key size matters
        if algorithm == 'RSA' and normalized.key_size:
            if normalized.key_size < 2048:
                nist_designation = 'DISALLOWED'
            elif normalized.key_size == 2048:
                nist_designation = 'ALLOWED_LEGACY'
            else:
                nist_designation = 'APPROVED'
        
        normalized.nist_designation = nist_designation
        
        # Add FIPS status
        if nist_designation in ('APPROVED', 'ALLOWED_LEGACY'):
            normalized.fips_status = self._get_fips_standard(algorithm)
        
        return normalized
    
    def _get_fips_standard(self, algorithm: str) -> str:
        """Get FIPS standard reference for algorithm."""
        fips_mapping = {
            'AES': 'FIPS-197',
            'SHA-256': 'FIPS-180-4',
            'SHA-384': 'FIPS-180-4',
            'SHA-512': 'FIPS-180-4',
            'RSA': 'FIPS-186-4',
            'ECDSA': 'FIPS-186-4',
            'HMAC': 'FIPS-198-1',
        }
        
        return fips_mapping.get(algorithm.upper(), 'N/A')