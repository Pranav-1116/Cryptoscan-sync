"""
Algorithm string parser for Java crypto transformation strings.

Handles formats like:
  - "AES"
  - "AES/GCM/NoPadding"  
  - "DES/ECB/PKCS5Padding"
  - "SHA-256"
  - "SHA256withRSA"
  - "HmacSHA256"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedAlgorithm:
    """Result of parsing a Java crypto transformation string."""
    raw_input: str
    algorithm: Optional[str]
    mode: Optional[str]
    padding: Optional[str]
    hash_algorithm: Optional[str]   # For signature algorithms like SHA256withRSA
    signing_algorithm: Optional[str]  # For signature algorithms
    is_signature_combo: bool = False
    is_mac: bool = False


# Known algorithm normalizations (raw -> canonical)
ALGORITHM_ALIASES: dict[str, str] = {
    "AES": "AES",
    "DES": "DES",
    "DESEDE": "3DES",
    "3DES": "3DES",
    "TRIPLEDES": "3DES",
    "RSA": "RSA",
    "EC": "EC",
    "DSA": "DSA",
    "ECDSA": "ECDSA",
    "ECDH": "ECDH",
    "DIFFIEHELLMAN": "DH",
    "DH": "DH",
    "RC4": "RC4",
    "ARCFOUR": "RC4",
    "RC2": "RC2",
    "BLOWFISH": "BLOWFISH",
    "CHACHA20": "ChaCha20",
    "CHACHA20-POLY1305": "ChaCha20-Poly1305",
    "SHA": "SHA-1",
    "SHA1": "SHA-1",
    "SHA-1": "SHA-1",
    "SHA-224": "SHA-224",
    "SHA-256": "SHA-256",
    "SHA-384": "SHA-384",
    "SHA-512": "SHA-512",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "MD5": "MD5",
    "MD2": "MD2",
    "HMACSHA1": "HmacSHA1",
    "HMACSHA256": "HmacSHA256",
    "HMACSHA384": "HmacSHA384",
    "HMACSHA512": "HmacSHA512",
    "HMACMD5": "HmacMD5",
}

MODE_ALIASES: dict[str, str] = {
    "ECB": "ECB",
    "CBC": "CBC",
    "CFB": "CFB",
    "CFB8": "CFB8",
    "OFB": "OFB",
    "CTR": "CTR",
    "GCM": "GCM",
    "CCM": "CCM",
    "SIV": "SIV",
    "NONE": "NONE",
}

PADDING_ALIASES: dict[str, str] = {
    "NOPADDING": "NoPadding",
    "PKCS5PADDING": "PKCS5Padding",
    "PKCS1PADDING": "PKCS1Padding",
    "OAEPWITHSHA-1ANDMGF1PADDING": "OAEPWithSHA-1AndMGF1Padding",
    "OAEPWITHSHA-256ANDMGF1PADDING": "OAEPWithSHA-256AndMGF1Padding",
    "OAEPWITHSHA1ANDMGF1PADDING": "OAEPWithSHA-1AndMGF1Padding",
    "OAEPWITHSHA256ANDMGF1PADDING": "OAEPWithSHA-256AndMGF1Padding",
    "ISO10126PADDING": "ISO10126Padding",
}

# Signature algorithm pattern: "SHA256withRSA", "SHA1withDSA", etc.
SIGNATURE_PATTERN = re.compile(
    r"^(SHA[\d-]*|MD5|SHA\d+)with(RSA|DSA|ECDSA|EC)$",
    re.IGNORECASE
)

# HMAC pattern
HMAC_PATTERN = re.compile(r"^Hmac(.+)$", re.IGNORECASE)


_PBE_PATTERN = re.compile(
    r"^(PBE|PBKDF2)With((?:Hmac|HMAC)?(?:SHA-?(?:1|224|256|384|512)|MD5|MD2))?(?:And((?:AES|DES(?:ede)?|TripleDES|RC2|RC4|Blowfish|IDEA|Twofish|Camellia)(?:_(?:128|192|256))?)(?:/([A-Za-z0-9]+))?)?",
    re.IGNORECASE,
)


def parse_transformation(raw: str) -> ParsedAlgorithm:
    """
    Parse a Java crypto transformation string into its components.
    
    Handles:
    - Simple: "AES", "DES", "SHA-256"  
    - Compound: "AES/GCM/NoPadding"
    - Signature: "SHA256withRSA"
    - HMAC: "HmacSHA256"
    
    Args:
        raw: Raw transformation string from source code
        
    Returns:
        ParsedAlgorithm with normalized components
    """
    if not raw:
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm=None,
            mode=None,
            padding=None,
            hash_algorithm=None,
            signing_algorithm=None,
        )

    stripped = raw.strip()

    # Check for signature algorithm (e.g., SHA256withRSA)
    sig_match = SIGNATURE_PATTERN.match(stripped)
    if sig_match:
        hash_algo = _normalize_algorithm(sig_match.group(1))
        signing_algo = _normalize_algorithm(sig_match.group(2))
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm=signing_algo,
            mode=None,
            padding=None,
            hash_algorithm=hash_algo,
            signing_algorithm=signing_algo,
            is_signature_combo=True,
        )

    # PBE / PBKDF2 transformations: "PBEWithHMACSHA512AndAES_256", "PBEWithMD5AndDES",
    # "PBKDF2WithHmacSHA256". The cipher after "And" is the algorithm in use; the
    # PRF/digest is recorded as hash_algorithm so callers can emit it separately.
    pbe_match = _PBE_PATTERN.match(stripped)
    if pbe_match:
        kind, prf, cipher = pbe_match.group(1), pbe_match.group(2), pbe_match.group(3)
        digest = _normalize_algorithm(prf.replace("Hmac", "").replace("HMAC", "")) if prf else None
        if cipher:
            cipher_norm = _normalize_algorithm(cipher.split("_")[0])
            return ParsedAlgorithm(
                raw_input=raw,
                algorithm=cipher_norm,
                mode=_normalize_mode(pbe_match.group(4)) if pbe_match.group(4) else ("CBC" if cipher_norm in {"AES", "DES", "DESede", "3DES", "RC2", "RC4"} else None),
                padding=None,
                hash_algorithm=digest,
                signing_algorithm=None,
            )
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm="PBKDF2",
            mode=None,
            padding=None,
            hash_algorithm=digest,
            signing_algorithm=None,
        )

    # Check for HMAC (e.g., HmacSHA256)
    hmac_match = HMAC_PATTERN.match(stripped)
    if hmac_match:
        hash_part = hmac_match.group(1)
        normalized_hash = _normalize_algorithm(hash_part)
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm=f"Hmac{normalized_hash}",
            mode=None,
            padding=None,
            hash_algorithm=normalized_hash,
            signing_algorithm=None,
            is_mac=True,
        )

    # Check for compound format: Algorithm/Mode/Padding
    if "/" in stripped:
        parts = stripped.split("/")
        algorithm = _normalize_algorithm(parts[0]) if len(parts) > 0 else None
        mode = _normalize_mode(parts[1]) if len(parts) > 1 else None
        padding = _normalize_padding(parts[2]) if len(parts) > 2 else None
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm=algorithm,
            mode=mode,
            padding=padding,
            hash_algorithm=None,
            signing_algorithm=None,
        )

    # Simple algorithm
    algorithm = _normalize_algorithm(stripped)
    return ParsedAlgorithm(
        raw_input=raw,
        algorithm=algorithm,
        mode=None,
        padding=None,
        hash_algorithm=None,
        signing_algorithm=None,
    )


def _normalize_algorithm(raw: str) -> Optional[str]:
    """Normalize algorithm name to canonical form."""
    if not raw:
        return None
    upper = raw.upper().strip()
    return ALGORITHM_ALIASES.get(upper, raw.strip())


def _normalize_mode(raw: str) -> Optional[str]:
    """Normalize mode string to canonical form."""
    if not raw:
        return None
    upper = raw.upper().strip()
    return MODE_ALIASES.get(upper, raw.strip())


def _normalize_padding(raw: str) -> Optional[str]:
    """Normalize padding string to canonical form."""
    if not raw:
        return None
    upper = raw.upper().replace(" ", "").replace("-", "")
    return PADDING_ALIASES.get(upper, raw.strip())