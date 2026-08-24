"""
Algorithm family classifier.
"""
from ..models.normalized_crypto import NormalizedCrypto


class FamilyEnricher:
    """
    Enriches normalized crypto with algorithm family classification.
    
    Families: symmetric, asymmetric, hash, mac, kdf, pqc
    """
    
    SYMMETRIC_ALGORITHMS = {
        'AES', 'DES', '3DES', 'RC4', 'CHACHA20', 'BLOWFISH', 'TWOFISH'
    }
    
    ASYMMETRIC_ALGORITHMS = {
        'RSA', 'DSA', 'ECDSA', 'ECDH', 'DH', 'EC', 'ELGAMAL'
    }
    
    HASH_ALGORITHMS = {
        'MD5', 'MD4', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512',
        'SHA3-256', 'SHA3-384', 'SHA3-512', 'BLAKE2', 'BLAKE3'
    }
    
    MAC_ALGORITHMS = {
        'HMAC', 'CMAC', 'GMAC', 'POLY1305'
    }
    
    KDF_ALGORITHMS = {
        'PBKDF2', 'HKDF', 'SCRYPT', 'ARGON2', 'BCRYPT'
    }
    
    PQC_ALGORITHMS = {
        'CRYSTALS-KYBER', 'CRYSTALS-DILITHIUM', 'FALCON', 'SPHINCS+'
    }
    
    def enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        """
        Add algorithm family classification.
        
        Args:
            normalized: Base normalized crypto object
            
        Returns:
            Enriched object with family classification
        """
        if not normalized.algorithm:
            normalized.algorithm_family = 'unknown'
            return normalized
        
        algorithm = normalized.algorithm.upper()
        
        # Classify by algorithm
        if algorithm in self.SYMMETRIC_ALGORITHMS:
            family = 'symmetric'
        elif algorithm in self.ASYMMETRIC_ALGORITHMS:
            family = 'asymmetric'
        elif algorithm in self.HASH_ALGORITHMS:
            family = 'hash'
        elif algorithm in self.MAC_ALGORITHMS:
            family = 'mac'
        elif algorithm in self.KDF_ALGORITHMS:
            family = 'kdf'
        elif algorithm in self.PQC_ALGORITHMS:
            family = 'pqc'
        else:
            # Check for common patterns
            if 'SHA' in algorithm or 'MD' in algorithm:
                family = 'hash'
            elif 'HMAC' in algorithm:
                family = 'mac'
            else:
                family = 'unknown'
        
        normalized.algorithm_family = family
        
        return normalized