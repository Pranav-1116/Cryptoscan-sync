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
    r"^((?:SHA(?:-?(?:1|224|256|384|512)|3-?(?:224|256|384|512))|MD5))"
    r"with(RSA|DSA|ECDSA|EC)$",
    re.IGNORECASE
)

# HMAC transformations are emitted with all of these separator/casing forms
# by Java, .NET, and configuration scanners: HmacSHA256, HMAC-SHA256, and
# HMAC_SHA256 are the same algorithm, not three different names.
HMAC_PATTERN = re.compile(r"^Hmac[-_]?(.+)$", re.IGNORECASE)


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

    # Interpolation / format placeholders that survived desugaring ("SHA-$bits", "%s/CBC/NoPadding",
    # "${alg}", "{0}"): the algorithm is a runtime value. Keep mode/padding if present, never coin a name.
    if re.search(r"\$\{?\w|%[sd]|\{\d*\}|#\{", stripped):
        parts = stripped.split("/")
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm="UNKNOWN",
            mode=_normalize_mode(parts[1]) if len(parts) > 1 else None,
            padding=_normalize_padding(parts[2]) if len(parts) > 2 else None,
            hash_algorithm=None,
            signing_algorithm=None,
        )

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
        # group(1) is PBE-vs-PBKDF2; the cipher and PRF are what callers need.
        _kind, prf, cipher = pbe_match.group(1), pbe_match.group(2), pbe_match.group(3)
        digest = _normalize_algorithm(prf.replace("Hmac", "").replace("HMAC", "")) if prf else None
        if cipher:
            cipher_norm = _normalize_algorithm(cipher.split("_")[0])
            return ParsedAlgorithm(
                raw_input=raw,
                algorithm=cipher_norm,
                # PBE names identify a KDF/PRF and sometimes a cipher, but
                # do not state a block mode. Never infer CBC from a provider
                # default: the provider/configuration must supply that evidence.
                mode=_normalize_mode(pbe_match.group(4)) if pbe_match.group(4) else None,
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
        hash_part = hmac_match.group(1).lstrip("-_ ")
        normalized_hash = _normalize_algorithm(hash_part)
        return ParsedAlgorithm(
            raw_input=raw,
            algorithm=f"HMAC-{normalized_hash}",
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
        # s"$algorithmName/ECB/PKCS5Padding", "%s/CBC/NoPadding", "" + algo + "/GCM/NoPadding": the
        # algorithm is a runtime value — keep mode/padding (ECB is still a finding) but do not
        # invent an algorithm name from interpolation syntax.
        if algorithm and (algorithm.startswith(("$", "%", "{", "#", "+")) or "${" in parts[0] or parts[0].strip() == ""):
            algorithm = "UNKNOWN"
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

# These are scanner vocabulary items rather than entries in the shared algorithm
# catalog.  Keep them exact: canonicalising ``RS256`` to ``RSA`` loses the fact
# that the evidence is a JOSE algorithm identifier, while canonicalising
# ``TLS1.2`` to ``TLS 1.2`` breaks the scanner's stable protocol labels.
_SCANNER_EXACT_ALIASES = {
    "TLS": "TLS",
    "TLS10": "TLS1.0",
    "TLS11": "TLS1.1",
    "TLS12": "TLS1.2",
    "TLS13": "TLS1.3",
    "SSLV2": "SSLv2",
    "SSLV3": "SSLv3",
    "X509": "X509",
    "DPAPI": "DPAPI",
    "JWT": "JWT",
    "CSPRNG": "CSPRNG",
    "PRNG": "PRNG",
    "RNG": "RNG",
    "SECURERANDOM": "CSPRNG",
    "SHA1PRNG": "PRNG",
    "SHA3": "SHA3",
    # JOSE names identify a protocol-level signing/MAC choice, not merely the
    # underlying RSA, EC, or HMAC primitive.
    "HS256": "HS256", "HS384": "HS384", "HS512": "HS512",
    "RS256": "RS256", "RS384": "RS384", "RS512": "RS512",
    "PS256": "PS256", "PS384": "PS384", "PS512": "PS512",
    "ES256": "ES256", "ES384": "ES384", "ES512": "ES512",
    "ES256K": "ES256K", "EDDSA": "EdDSA",
}


def known_algorithm_or_unknown(name: str | None) -> str:
    """Return a catalog canonical name, or ``UNKNOWN`` without guessing.

    This is a boundary between parser text and inventory data. Prefix heuristics
    such as ``name.startswith("AES")`` are unsafe: ``AESX`` and
    ``SHA256FOO`` are ordinary identifiers, not algorithms. Reuse the shared
    registry's exact/tolerant parser and retain only explicit scanner vocabulary
    that is deliberately outside (or more specific than) that catalog.
    """
    if not name or str(name).strip().upper() == "UNKNOWN":
        return "UNKNOWN"
    text = str(name).strip()
    normalized = re.sub(r"[^A-Z0-9]", "", text.upper())
    if normalized in _SCANNER_EXACT_ALIASES:
        return _SCANNER_EXACT_ALIASES[normalized]
    try:
        from shared_models.algorithm_registry import parse_algorithm

        parsed = parse_algorithm(text)
        if parsed.recognized and parsed.canonical:
            return parsed.canonical
    except (ImportError, AttributeError, TypeError, ValueError):
        # The scanner can be used without the optional shared-model package;
        # fall through to the local exact aliases rather than inventing a name.
        pass
    return "UNKNOWN"
