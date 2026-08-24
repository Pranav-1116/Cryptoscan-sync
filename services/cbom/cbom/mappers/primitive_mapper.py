"""Map algorithms / purposes to CycloneDX crypto primitives."""

from __future__ import annotations

PRIMITIVES = {
    "AES": "block-cipher",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "RC2": "block-cipher",
    "RC4": "stream-cipher",
    "CHACHA20": "stream-cipher",
    "CHACHA20-POLY1305": "aead",
    "SHA-1": "hash",
    "SHA-256": "hash",
    "SHA-384": "hash",
    "SHA-512": "hash",
    "SHA3-256": "hash",
    "MD5": "hash",
    "HMAC-SHA256": "mac",
    "HMAC-SHA1": "mac",
    "HMAC-SHA384": "mac",
    "HMAC-SHA512": "mac",
    "HMACSHA256": "mac",
    "RSA": "pke",
    "ECDSA": "signature",
    "DSA": "signature",
    "ECDH": "key-agree",
    "PBKDF2": "kdf",
    "BCRYPT": "kdf",
    "SCRYPT": "kdf",
    "ARGON2": "kdf",
}

PURPOSE_PRIMITIVES = {
    "ENCRYPTION": "enc",
    "DECRYPTION": "enc",
    "SIGNING": "signature",
    "VERIFICATION": "signature",
    "HASHING": "hash",
    "KEY_EXCHANGE": "kem",
    "KEY_AGREEMENT": "dh",
    "PASSWORD_HASHING": "kdf",
    "MAC_GENERATION": "mac",
}


def map_primitive(algorithm: str | None, purpose: str | None = None) -> str:
    if algorithm:
        key = str(algorithm).upper()
        if key in PRIMITIVES:
            return PRIMITIVES[key]
    if purpose:
        return PURPOSE_PRIMITIVES.get(str(purpose).upper(), "unknown")
    return "unknown"
