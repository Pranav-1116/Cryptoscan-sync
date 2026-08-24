"""
Pattern-based normalization matcher.
Handles transformation strings like "AES/GCM/NoPadding".
"""
import re
from typing import Optional
from ..models.normalized_crypto import NormalizedCrypto


class PatternMatcher:
    """
    Matches and parses algorithm transformation strings.
    
    Format: "Algorithm/Mode/Padding"
    Examples:
    - "AES/GCM/NoPadding" -> {algorithm: AES, mode: GCM, padding: none}
    - "DES/ECB/PKCS5Padding" -> {algorithm: DES, mode: ECB, padding: PKCS5}
    """
    
    # Pattern for "Algorithm/Mode/Padding"
    TRANSFORMATION_PATTERN = re.compile(r'^([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)$')
    
    # Pattern for "Algorithm/Mode" (no padding)
    MODE_PATTERN = re.compile(r'^([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)$')
    
    def match(self, raw_algorithm: str) -> Optional[NormalizedCrypto]:
        """
        Attempt pattern-based normalization.
        
        Args:
            raw_algorithm: Raw algorithm string
            
        Returns:
            NormalizedCrypto if pattern matched, None otherwise
        """
        # Try full transformation pattern first
        match = self.TRANSFORMATION_PATTERN.match(raw_algorithm)
        
        if match:
            algorithm, mode, padding = match.groups()
            
            return NormalizedCrypto(
                algorithm=self._normalize_algorithm_name(algorithm),
                mode=self._normalize_mode(mode),
                padding=self._normalize_padding(padding),
                algorithm_family=self._infer_family(algorithm),
                standard_name=raw_algorithm,
            )
        
        # Try algorithm/mode pattern
        match = self.MODE_PATTERN.match(raw_algorithm)
        
        if match:
            algorithm, mode = match.groups()
            
            return NormalizedCrypto(
                algorithm=self._normalize_algorithm_name(algorithm),
                mode=self._normalize_mode(mode),
                padding=None,
                algorithm_family=self._infer_family(algorithm),
                standard_name=raw_algorithm,
            )
        
        return None
    
    def _normalize_algorithm_name(self, algorithm: str) -> str:
        """Normalize algorithm name to canonical form."""
        # Convert to uppercase for consistency
        normalized = algorithm.upper()
        
        # Handle common aliases
        aliases = {
            'TRIPLEDES': '3DES',
            'DESEDE': '3DES',
            'ARCFOUR': 'RC4',
        }
        
        return aliases.get(normalized, normalized)
    
    def _normalize_mode(self, mode: str) -> str:
        """Normalize mode name to canonical form."""
        return mode.upper()
    
    def _normalize_padding(self, padding: str) -> Optional[str]:
        """Normalize padding name to canonical form."""
        normalized = padding.upper()
        
        # Handle "NoPadding" special case
        if normalized == 'NOPADDING':
            return None  # Explicitly no padding
        
        # Remove "Padding" suffix if present
        if normalized.endswith('PADDING'):
            normalized = normalized[:-7]
        
        return normalized
    
    def _infer_family(self, algorithm: str) -> str:
        """Infer algorithm family from algorithm name."""
        algorithm_upper = algorithm.upper()
        
        # Symmetric algorithms
        symmetric = {'AES', 'DES', '3DES', 'DESEDE', 'RC4', 'CHACHA20', 'BLOWFISH'}
        if algorithm_upper in symmetric:
            return 'symmetric'
        
        # Asymmetric algorithms
        asymmetric = {'RSA', 'DSA', 'ECDSA', 'ECDH', 'DH', 'EC'}
        if algorithm_upper in asymmetric:
            return 'asymmetric'
        
        # Hash functions
        hashing = {'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512'}
        if algorithm_upper in hashing or 'SHA' in algorithm_upper or 'MD' in algorithm_upper:
            return 'hash'
        
        return 'unknown'