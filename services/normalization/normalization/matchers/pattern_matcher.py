"""
Pattern-based normalization matcher.
Handles transformation strings like "AES/GCM/NoPadding" and compound names
like "AES-256-GCM" / "AES_128_CBC".
"""
import re
from typing import Optional
from ..core.registry_bridge import canonical_name, model_family, name_key_size
from ..models.normalized_crypto import NormalizedCrypto


class PatternMatcher:
    def __init__(self, registry=None):
        self._registry = registry

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

    # Compound names: "AES-256-GCM", "AES_128_CBC", "RSA-2048", "AES128"
    COMPOUND_PATTERN = re.compile(r'^([A-Za-z]+)[-_]?(\d{2,4})?(?:[-_]+([A-Za-z0-9]+))?$')
    
    def match(self, raw_algorithm: str) -> Optional[NormalizedCrypto]:
        """
        Attempt pattern-based normalization.
        
        Args:
            raw_algorithm: Raw algorithm string
            
        Returns:
            NormalizedCrypto if pattern matched, None otherwise
        """
        if not raw_algorithm or not str(raw_algorithm).strip():
            return None
        raw = str(raw_algorithm).strip()
        
        # Try full transformation pattern first
        match = self.TRANSFORMATION_PATTERN.match(raw)
        
        if match:
            algorithm, mode, padding = match.groups()
            
            return NormalizedCrypto(
                algorithm=self._normalize_algorithm_name(algorithm),
                mode=self._normalize_mode(mode),
                padding=self._normalize_padding(padding),
                algorithm_family=self._infer_family(algorithm),
                standard_name=raw,
                key_size=name_key_size(raw) or name_key_size(algorithm),
                normalization_confidence="MEDIUM",
                raw_input=raw,
            )
        
        # Try algorithm/mode pattern
        match = self.MODE_PATTERN.match(raw)
        
        if match:
            algorithm, mode = match.groups()
            
            return NormalizedCrypto(
                algorithm=self._normalize_algorithm_name(algorithm),
                mode=self._normalize_mode(mode),
                padding=None,
                algorithm_family=self._infer_family(algorithm),
                standard_name=raw,
                key_size=name_key_size(raw) or name_key_size(algorithm),
                normalization_confidence="MEDIUM",
                raw_input=raw,
            )

        # Try compound names ("AES-256-GCM", "AES_128_CBC", "RSA-2048").
        # Previously these fell through to UNKNOWN unless an exact rule
        # happened to spell them identically. Only registry-recognized
        # algorithms qualify — an unrecognized token stays UNKNOWN and
        # goes to human review rather than gaining false confidence.
        match = self.COMPOUND_PATTERN.match(raw)
        if match and (match.group(2) or match.group(3)):
            algorithm, size, tail = match.groups()
            full_raw = canonical_name(raw)  # registry may parse it whole
            token = canonical_name(algorithm) or (
                algorithm.upper() if algorithm.upper() in {"TRIPLEDES", "DESEDE", "ARCFOUR"} else None
            )
            recognized = full_raw or token
            if recognized:
                return NormalizedCrypto(
                    algorithm=self._normalize_algorithm_name(algorithm) if not full_raw else full_raw,
                    mode=self._normalize_mode(tail) if tail else None,
                    padding=None,
                    algorithm_family=self._infer_family(recognized),
                    standard_name=raw,
                    key_size=int(size) if size else name_key_size(raw),
                    normalization_confidence="MEDIUM",
                    raw_input=raw,
                )

        # Compound split failed but the registry knows the whole string
        # (e.g. "DES-EDE3-CBC" -> 3DES): accept without a mode rather
        # than dropping real recognition.
        full_raw = canonical_name(raw)
        if full_raw:
            return NormalizedCrypto(
                algorithm=full_raw,
                algorithm_family=self._infer_family(raw),
                standard_name=raw,
                key_size=name_key_size(raw),
                normalization_confidence="MEDIUM",
                raw_input=raw,
            )
        
        return None
    
    def _normalize_algorithm_name(self, algorithm: str) -> str:
        """Normalize algorithm name to canonical form (registry-first)."""
        canonical = canonical_name(algorithm)
        if canonical:
            return canonical
        # Legacy aliases kept only for names the registry does not know
        aliases = {
            'TRIPLEDES': '3DES',
            'DESEDE': '3DES',
            'ARCFOUR': 'RC4',
        }
        return aliases.get(algorithm.upper(), algorithm.upper())
    
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
        """Infer algorithm family (registry-first, legacy fallback)."""
        family = model_family(algorithm)
        if family:
            return family
        
        algorithm_upper = algorithm.upper()
        symmetric = {'AES', 'DES', '3DES', 'DESEDE', 'RC4', 'CHACHA20', 'BLOWFISH', 'TWOFISH'}
        if algorithm_upper in symmetric:
            return 'symmetric'
        asymmetric = {'RSA', 'DSA', 'ECDSA', 'ECDH', 'DH', 'EC'}
        if algorithm_upper in asymmetric:
            return 'asymmetric'
        # MAC before hash: "HMACSHA256" contains "SHA" but is a MAC
        if 'HMAC' in algorithm_upper:
            return 'mac'
        hashing = {'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512'}
        if algorithm_upper in hashing or 'SHA' in algorithm_upper or 'MD' in algorithm_upper:
            return 'hash'
        return 'unknown'
