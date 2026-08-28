"""
Algorithm family classifier (registry-first).
"""
from ..core.registry_bridge import model_family
from ..models.normalized_crypto import NormalizedCrypto


class FamilyEnricher:
    """
    Enriches normalized crypto with algorithm family classification.
    
    Families: symmetric, asymmetric, hash, mac, kdf, key-agreement,
    signature — the model-allowed vocabulary. The registry decides;
    the legacy tables below only cover names the registry misses.
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
    
    # Pre-standard PQC project names -> model-allowed families (the old
    # 'pqc' value was never in the model's allowed set)
    PQC_KEM_ALGORITHMS = {
        'CRYSTALS-KYBER', 'KYBER', 'NEWHOPE', 'SABER', 'NTRU'
    }
    PQC_SIGNATURE_ALGORITHMS = {
        'CRYSTALS-DILITHIUM', 'DILITHIUM', 'FALCON', 'SPHINCS+', 'SPHINCS'
    }
    
    def enrich(self, normalized: NormalizedCrypto) -> NormalizedCrypto:
        """
        Add algorithm family classification.
        
        Args:
            normalized: Base normalized crypto object
            
        Returns:
            Enriched object with family classification
        """
        if normalized.algorithm_family and normalized.algorithm_family != "unknown":
            return normalized

        if not normalized.algorithm:
            normalized.algorithm_family = 'unknown'
            return normalized
        
        algorithm = normalized.algorithm.upper()

        # Registry-first: canonical family for anything it knows
        family = model_family(normalized.algorithm)
        if not family:
            # Legacy tables for names the registry does not recognize
            if algorithm in self.SYMMETRIC_ALGORITHMS:
                family = 'symmetric'
            elif algorithm in self.ASYMMETRIC_ALGORITHMS:
                family = 'asymmetric'
            elif algorithm in self.MAC_ALGORITHMS or 'HMAC' in algorithm:
                family = 'mac'
            elif algorithm in self.KDF_ALGORITHMS:
                family = 'kdf'
            elif algorithm in self.PQC_KEM_ALGORITHMS:
                family = 'key-agreement'
            elif algorithm in self.PQC_SIGNATURE_ALGORITHMS:
                family = 'signature'
            elif algorithm in self.HASH_ALGORITHMS:
                family = 'hash'
            elif 'SHA' in algorithm or 'MD' in algorithm:
                family = 'hash'
            else:
                family = 'unknown'
        
        normalized.algorithm_family = family
        
        return normalized
