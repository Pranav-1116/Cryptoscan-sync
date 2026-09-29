"""Algorithm registry — every algorithm the product knows, with its key.

Single source of truth for parsing, canonicalizing and classifying
cryptographic algorithm names from any source (code, cloud APIs, TLS
suites, JOSE headers, SSH config, OpenSSL names):

    "AES-256"            -> AES, key 256 bits, ALLOWED
    "aes_128_gcm"        -> AES-GCM, key 128 bits, ALLOWED
    "DES"                -> DES, key 56 bits, DISALLOWED
    "des-ede3-cbc"       -> 3DES, key 168 bits, DEPRECATED
    "SHA-256"            -> SHA-256, digest 256 bits, ALLOWED
    "SHA256withRSA"      -> RSA signature over SHA-256
    "RS256" / "ES384"    -> JOSE names
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" -> full suite breakdown
    "chacha20-poly1305@openssh.com"         -> SSH name

Every parse returns :class:`AlgorithmInfo` with the canonical name, key
size in bits (or digest size for hashes / curve size for ECC), primitive
family, NIST status and quantum impact. Unknown names degrade gracefully
to ``status="UNKNOWN"`` — never to silence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# --------------------------------------------------------------------------- #
# catalog entries
# --------------------------------------------------------------------------- #


def _norm_key(key: str) -> str:
    """Catalog keys are stored separator-free upper-case for tolerant lookup."""
    return "".join(ch for ch in key.upper() if ch.isalnum())



#: status values (aligned with the CBOM assessment penalties)
DISALLOWED = "DISALLOWED"
DEPRECATED = "DEPRECATED"
RESTRICTED = "RESTRICTED"
ALLOWED = "ALLOWED"
UNKNOWN = "UNKNOWN"

#: how the "size" number should be interpreted
KEY_BITS = "key_bits"
DIGEST_BITS = "digest_bits"
CURVE_BITS = "curve_bits"


@dataclass(frozen=True)
class AlgorithmInfo:
    """Parsed algorithm with key/size information and verdict."""

    raw: str
    canonical: str
    family: str  # block-cipher / stream-cipher / aead / hash / mac / pke / signature / key-agree / kdf
    status: str = UNKNOWN
    key_size: int | None = None
    parameter_kind: str | None = None  # key_bits / digest_bits / curve_bits
    mode: str | None = None
    allowed_key_sizes: tuple[int, ...] = ()
    min_key_size: int | None = None
    quantum_impact: str | None = None  # "shor" (breaks) / "grover" (halves security)
    notes: str = ""
    components: tuple[dict[str, Any], ...] = ()  # for cipher suites
    recognized: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "algorithm": self.canonical,
            "family": self.family,
            "status": self.status,
            "key_size": self.key_size,
            "parameter_kind": self.parameter_kind,
            "mode": self.mode,
            "allowed_key_sizes": list(self.allowed_key_sizes),
            "min_key_size": self.min_key_size,
            "quantum_impact": self.quantum_impact,
            "quantum_vulnerable": self.quantum_impact == "shor",
            "notes": self.notes,
            "components": [dict(c) for c in self.components],
            "recognized": self.recognized,
        }


@dataclass(frozen=True)
class _Family:
    canonical: str
    family: str
    status: str
    key_size: int | None = None
    parameter_kind: str | None = None
    allowed_key_sizes: tuple[int, ...] = ()
    min_key_size: int | None = None
    quantum_impact: str | None = None
    notes: str = ""


# Base catalog: canonical upper-case name -> family record.
# Key sizes embedded in the input (AES-256, RSA2048) override key_size.
_FAMILIES: dict[str, _Family] = {
    # -- symmetric ciphers ------------------------------------------------ #
    "AES": _Family("AES", "block-cipher", ALLOWED, allowed_key_sizes=(128, 192, 256), min_key_size=128, quantum_impact="grover", notes="AES; sizes 128/192/256 bits"),
    "AES-GCM": _Family("AES-GCM", "aead", ALLOWED, allowed_key_sizes=(128, 192, 256), min_key_size=128, quantum_impact="grover", notes="AES in GCM mode (AEAD)"),
    "AES-XTS": _Family("AES-XTS", "aead", RESTRICTED, allowed_key_sizes=(128, 256), quantum_impact="grover", notes="storage encryption; 256-bit XTS keys = 2x128"),
    "DES": _Family("DES", "block-cipher", DISALLOWED, key_size=56, parameter_kind=KEY_BITS, notes="56-bit key — broken; NIST disallowed"),
    "3DES": _Family("3DES", "block-cipher", DEPRECATED, key_size=168, parameter_kind=KEY_BITS, allowed_key_sizes=(112, 168), notes="64-bit block; deprecated (SP 800-131A rev2)"),
    "DESX": _Family("DESX", "block-cipher", DISALLOWED, key_size=184, parameter_kind=KEY_BITS),
    "RC2": _Family("RC2", "block-cipher", DISALLOWED, notes="variable 40-128 bit keys; disallowed"),
    "RC4": _Family("RC4", "stream-cipher", DISALLOWED, notes="biases break WEP/TLS; disallowed"),
    "RC5": _Family("RC5", "block-cipher", DISALLOWED, notes="patented, weak parameters"),
    "RC6": _Family("RC6", "block-cipher", RESTRICTED, notes="not NIST-approved"),
    "BLOWFISH": _Family("Blowfish", "block-cipher", RESTRICTED, notes="64-bit block; not for new use"),
    "TWOFISH": _Family("Twofish", "block-cipher", ALLOWED, allowed_key_sizes=(128, 192, 256), quantum_impact="grover"),
    "SERPENT": _Family("Serpent", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), quantum_impact="grover", notes="AES finalist; no current standardization"),
    "DSTU7624": _Family("Kalyna", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 256, 512), quantum_impact="grover", notes="Ukrainian national standard DSTU 7624:2014 (Kalyna)"),
    "CAMELLIA": _Family("Camellia", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), notes="not FIPS-approved"),
    "ARIA": _Family("ARIA", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256)),
    "SEED": _Family("SEED", "block-cipher", DEPRECATED, key_size=128, parameter_kind=KEY_BITS),
    "IDEA": _Family("IDEA", "block-cipher", DEPRECATED, key_size=128, parameter_kind=KEY_BITS, notes="64-bit block"),
    "CAST5": _Family("CAST5", "block-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS),
    "CAST128": _Family("CAST5", "block-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS),
    "GOST28147": _Family("GOST 28147-89", "block-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS),
    "CHACHA20": _Family("ChaCha20", "stream-cipher", ALLOWED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover"),
    "CHACHA20-POLY1305": _Family("ChaCha20-Poly1305", "aead", ALLOWED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover"),
    "SALSA20": _Family("Salsa20", "stream-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS),
    # -- hashes ------------------------------------------------------------ #
    "MD2": _Family("MD2", "hash", DISALLOWED, key_size=128, parameter_kind=DIGEST_BITS),
    "MD4": _Family("MD4", "hash", DISALLOWED, key_size=128, parameter_kind=DIGEST_BITS),
    "MD5": _Family("MD5", "hash", DISALLOWED, key_size=128, parameter_kind=DIGEST_BITS, notes="collisions practical"),
    "SHA-1": _Family("SHA-1", "hash", DEPRECATED, key_size=160, parameter_kind=DIGEST_BITS, notes="collision-broken (SHA-1); disallowed for signatures"),
    "SHA-224": _Family("SHA-224", "hash", ALLOWED, key_size=224, parameter_kind=DIGEST_BITS, quantum_impact="grover"),
    "SHA-256": _Family("SHA-256", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS, quantum_impact="grover"),
    "SHA-384": _Family("SHA-384", "hash", ALLOWED, key_size=384, parameter_kind=DIGEST_BITS, quantum_impact="grover"),
    "SHA-512": _Family("SHA-512", "hash", ALLOWED, key_size=512, parameter_kind=DIGEST_BITS, quantum_impact="grover"),
    "SHA-512/224": _Family("SHA-512/224", "hash", ALLOWED, key_size=224, parameter_kind=DIGEST_BITS),
    "SHA-512/256": _Family("SHA-512/256", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS),
    "SHA3-224": _Family("SHA3-224", "hash", ALLOWED, key_size=224, parameter_kind=DIGEST_BITS),
    "SHA3-256": _Family("SHA3-256", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS),
    "SHA3-384": _Family("SHA3-384", "hash", ALLOWED, key_size=384, parameter_kind=DIGEST_BITS),
    "SHA3-512": _Family("SHA3-512", "hash", ALLOWED, key_size=512, parameter_kind=DIGEST_BITS),
    "SHAKE128": _Family("SHAKE128", "xof", ALLOWED, key_size=128, parameter_kind=DIGEST_BITS),
    "SHAKE256": _Family("SHAKE256", "xof", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS),
    "RIPEMD160": _Family("RIPEMD-160", "hash", RESTRICTED, key_size=160, parameter_kind=DIGEST_BITS),
    "WHIRLPOOL": _Family("Whirlpool", "hash", RESTRICTED, key_size=512, parameter_kind=DIGEST_BITS),
    # -- MAC / KDF --------------------------------------------------------- #
    "HMAC": _Family("HMAC", "mac", ALLOWED, notes="key size = hash output size by default"),
    "HMAC-MD5": _Family("HMAC-MD5", "mac", DISALLOWED, key_size=128, parameter_kind=KEY_BITS),
    "HMAC-SHA-1": _Family("HMAC-SHA-1", "mac", RESTRICTED, key_size=160, parameter_kind=KEY_BITS, notes="allowed only for legacy verification"),
    "HMAC-SHA-224": _Family("HMAC-SHA-224", "mac", ALLOWED, key_size=224, parameter_kind=KEY_BITS),
    "HMAC-SHA-256": _Family("HMAC-SHA-256", "mac", ALLOWED, key_size=256, parameter_kind=KEY_BITS),
    "HMAC-SHA-384": _Family("HMAC-SHA-384", "mac", ALLOWED, key_size=384, parameter_kind=KEY_BITS),
    "HMAC-SHA-512": _Family("HMAC-SHA-512", "mac", ALLOWED, key_size=512, parameter_kind=KEY_BITS),
    "CMAC": _Family("CMAC", "mac", ALLOWED, key_size=128, parameter_kind=KEY_BITS),
    "GMAC": _Family("GMAC", "mac", ALLOWED, key_size=128, parameter_kind=KEY_BITS),
    "PBKDF2": _Family("PBKDF2", "kdf", RESTRICTED, notes="password KDF; use high iteration counts"),
    "BCRYPT": _Family("bcrypt", "kdf", ALLOWED, notes="password KDF"),
    "SCRYPT": _Family("scrypt", "kdf", ALLOWED, notes="memory-hard password KDF"),
    "ARGON2": _Family("Argon2", "kdf", ALLOWED, notes="memory-hard password KDF (PHC winner)"),
    "HKDF": _Family("HKDF", "kdf", ALLOWED),
    # -- public key / signatures ------------------------------------------- #
    "RSA": _Family("RSA", "pke", ALLOWED, min_key_size=2048, quantum_impact="shor", notes="<2048 disallowed; Shor breaks RSA entirely"),
    "RSA-PSS": _Family("RSA-PSS", "signature", ALLOWED, min_key_size=2048, quantum_impact="shor"),
    "RSA-OAEP": _Family("RSA-OAEP", "pke", ALLOWED, min_key_size=2048, quantum_impact="shor", notes="only recommended RSA encryption padding"),
    "RSA-PKCS1V15": _Family("RSA-PKCS1v1.5", "pke", DISALLOWED, quantum_impact="shor", notes="Bleichenbacher padding oracle"),
    "DSA": _Family("DSA", "signature", DEPRECATED, min_key_size=2048, quantum_impact="shor", notes="deprecated (SP 800-131A); Shor breaks"),
    "ECDSA": _Family("ECDSA", "signature", ALLOWED, min_key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "EC": _Family("ECDSA", "signature", ALLOWED, min_key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "ECDH": _Family("ECDH", "key-agree", ALLOWED, min_key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "ECDH-ES": _Family("ECDH-ES", "key-agree", ALLOWED, min_key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="JOSE ephemeral-static ECDH (RFC 7518)"),
    # JOSE "alg" values that name no algorithm. They must still resolve: the
    # parsers already emit them (see java_rules jjwt/jose4j tables), and an
    # unrecognized token reaches policy as UNKNOWN -- which for "none" means
    # the single most serious JWT finding there is would arrive unclassified.
    "NONE": _Family("none", "jose-unsecured", DISALLOWED, notes="RFC 7518 unsecured JWS: signature not verified, token forgeable by anyone"),
    "DIR": _Family("dir", "key-management", ALLOWED, notes="JOSE direct use of a shared symmetric key (RFC 7518); no key wrapping"),
    "DH": _Family("DH", "key-agree", RESTRICTED, min_key_size=2048, quantum_impact="shor", notes="finite-field DH >=2048 bits; legacy groups weaker"),
    "ED25519": _Family("Ed25519", "signature", ALLOWED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "ED448": _Family("Ed448", "signature", ALLOWED, key_size=456, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "X25519": _Family("X25519", "key-agree", ALLOWED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "X448": _Family("X448", "key-agree", ALLOWED, key_size=448, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    # -- post-quantum ------------------------------------------------------- #
    "ML-KEM-512": _Family("ML-KEM-512", "kem-pqc", ALLOWED, key_size=800, parameter_kind=KEY_BITS, notes="FIPS 203 (Kyber) level 1"),
    "ML-KEM-768": _Family("ML-KEM-768", "kem-pqc", ALLOWED, key_size=1184, parameter_kind=KEY_BITS, notes="FIPS 203 level 3"),
    "ML-KEM-1024": _Family("ML-KEM-1024", "kem-pqc", ALLOWED, key_size=1568, parameter_kind=KEY_BITS, notes="FIPS 203 level 5"),
    "ML-DSA-44": _Family("ML-DSA-44", "signature-pqc", ALLOWED, key_size=1312, parameter_kind=KEY_BITS, notes="FIPS 204 (Dilithium) level 2"),
    "ML-DSA-65": _Family("ML-DSA-65", "signature-pqc", ALLOWED, key_size=1952, parameter_kind=KEY_BITS, notes="FIPS 204 level 3"),
    "ML-DSA-87": _Family("ML-DSA-87", "signature-pqc", ALLOWED, key_size=2592, parameter_kind=KEY_BITS, notes="FIPS 204 level 5"),
    "SLH-DSA-128S": _Family("SLH-DSA-128S", "signature-pqc", ALLOWED, key_size=64, parameter_kind=KEY_BITS, notes="FIPS 205 (SPHINCS+)"),
    "KYBER": _Family("Kyber", "kem-pqc", RESTRICTED, notes="pre-standardization name — prefer ML-KEM"),
    # -- protocol versions (SP 800-52r2) ---------------------------------- #
    "TLS 1.0": _Family("TLS 1.0", "protocol", DISALLOWED, notes="disallowed protocol version (SP 800-52r2)"),
    "TLS 1.1": _Family("TLS 1.1", "protocol", DISALLOWED, notes="disallowed protocol version (SP 800-52r2)"),
    "TLS 1.2": _Family("TLS 1.2", "protocol", DEPRECATED, notes="allowed today; prefer TLS 1.3"),
    "TLS 1.3": _Family("TLS 1.3", "protocol", ALLOWED, notes="preferred protocol version"),
    "SSL 3.0": _Family("SSL 3.0", "protocol", DISALLOWED, notes="broken (POODLE)"),
    "SSL 2.0": _Family("SSL 2.0", "protocol", DISALLOWED, notes="broken (DROWN); prohibited by RFC 6176"),
    "DTLS 1.0": _Family("DTLS 1.0", "protocol", DISALLOWED, notes="disallowed protocol version"),
    "DTLS 1.2": _Family("DTLS 1.2", "protocol", DEPRECATED, notes="allowed today; prefer DTLS 1.3"),
    "DILITHIUM": _Family("Dilithium", "signature-pqc", RESTRICTED, notes="pre-standardization name — prefer ML-DSA"),
    # -- curves (key_size = curve bits) ------------------------------------- #
    "P-256": _Family("P-256", "ec-curve", ALLOWED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "P-384": _Family("P-384", "ec-curve", ALLOWED, key_size=384, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "P-521": _Family("P-521", "ec-curve", ALLOWED, key_size=521, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "SECP256K1": _Family("secp256k1", "ec-curve", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="non-NIST curve"),
    "BRAINPOOLP256R1": _Family("brainpoolP256r1", "ec-curve", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "CURVE25519": _Family("Curve25519", "ec-curve", ALLOWED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    # -- additional symmetric / stream ciphers ----------------------------- #
    "XSALSA20": _Family("XSalsa20", "stream-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS),
    "XCHACHA20": _Family("XChaCha20", "stream-cipher", ALLOWED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover"),
    "XCHACHA20-POLY1305": _Family("XChaCha20-Poly1305", "aead", ALLOWED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover"),
    # -- Chinese national (GM/T) algorithms -------------------------------- #
    "SM4": _Family("SM4", "block-cipher", ALLOWED, allowed_key_sizes=(128,), min_key_size=128, quantum_impact="grover", notes="Chinese GM/T block cipher (GB/T 32907)"),
    "SM3": _Family("SM3", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="Chinese GM/T hash (GB/T 32905)"),
    "SM2": _Family("SM2", "signature", ALLOWED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="Chinese GM/T ECC signature/key-exchange (GB/T 32918); Shor breaks"),
    "SM9": _Family("SM9", "signature", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="Chinese identity-based (pairing) cryptography; Shor breaks"),
    "ZUC": _Family("ZUC", "stream-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="3GPP LTE/5G confidentiality/integrity stream cipher"),
    # -- Russian GOST algorithms ------------------------------------------- #
    "KUZNYECHIK": _Family("Kuznyechik", "block-cipher", ALLOWED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover", notes="GOST R 34.12-2015 block cipher (aka Grasshopper)"),
    "MAGMA": _Family("Magma", "block-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover", notes="GOST R 34.12-2015 legacy block cipher (formerly GOST 28147)"),
    "STREEBOG": _Family("Streebog", "hash", RESTRICTED, allowed_key_sizes=(256, 512), parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="GOST R 34.11-2012 hash"),
    "GOST3411-94": _Family("GOST R 34.11-94", "hash", DEPRECATED, key_size=256, parameter_kind=DIGEST_BITS, notes="superseded GOST hash; weaknesses"),
    # -- Korean / additional block ciphers --------------------------------- #
    "LEA": _Family("LEA", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), quantum_impact="grover", notes="Korean lightweight block cipher"),
    "HIGHT": _Family("HIGHT", "block-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, notes="Korean lightweight 64-bit block cipher"),
    # -- lightweight / embedded / NIST LWC --------------------------------- #
    "ASCON": _Family("Ascon", "aead", ALLOWED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="NIST lightweight crypto (LWC) winner; AEAD + hash"),
    # The four functions NIST SP 800-232 actually standardises, as spelled in
    # the IANA TLS registry (TLS_ASCONAEAD128_*). The bare "ASCON" above stays
    # as the family catch-all for code that just names the primitive.
    "ASCON-AEAD128": _Family("Ascon-AEAD128", "aead", ALLOWED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="NIST SP 800-232 AEAD"),
    "ASCON-HASH256": _Family("Ascon-Hash256", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="NIST SP 800-232 hash"),
    "ASCON-XOF128": _Family("Ascon-XOF128", "xof", ALLOWED, key_size=128, parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="NIST SP 800-232 extendable-output function"),
    "ASCON-CXOF128": _Family("Ascon-CXOF128", "xof", ALLOWED, key_size=128, parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="NIST SP 800-232 customised XOF"),
    "PRESENT": _Family("PRESENT", "block-cipher", RESTRICTED, allowed_key_sizes=(80, 128), notes="ultra-lightweight block cipher"),
    "CLEFIA": _Family("CLEFIA", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), notes="Sony lightweight block cipher"),
    "GRAIN": _Family("Grain", "stream-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, notes="lightweight stream cipher (Grain-128)"),
    "TRIVIUM": _Family("Trivium", "stream-cipher", RESTRICTED, key_size=80, parameter_kind=KEY_BITS, notes="lightweight stream cipher"),
    "SIMON": _Family("Simon", "block-cipher", RESTRICTED, notes="NSA lightweight block cipher family"),
    "SPECK": _Family("Speck", "block-cipher", RESTRICTED, notes="NSA lightweight block cipher family"),
    # -- legacy / mobile telephony (broken or restricted) ------------------ #
    "KASUMI": _Family("KASUMI", "block-cipher", DISALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="3G A5/3; practical attacks; disallowed"),
    "MISTY1": _Family("MISTY1", "block-cipher", DISALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="broken (Leuven attack); disallowed"),
    "SNOW3G": _Family("SNOW 3G", "stream-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, notes="3G/4G/5G confidentiality stream cipher"),
    "A5-1": _Family("A5/1", "stream-cipher", DISALLOWED, key_size=64, parameter_kind=KEY_BITS, notes="GSM cipher; broken — disallowed"),
    "A5-2": _Family("A5/2", "stream-cipher", DISALLOWED, key_size=64, parameter_kind=KEY_BITS, notes="GSM export cipher; deliberately weak — disallowed"),
    "XTEA": _Family("XTEA", "block-cipher", DISALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="related-key weaknesses; disallowed"),
    "SKIPJACK": _Family("Skipjack", "block-cipher", DISALLOWED, key_size=80, parameter_kind=KEY_BITS, notes="NSA Clipper cipher; 80-bit; disallowed"),
    "SHACAL2": _Family("SHACAL-2", "block-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS),
    # -- additional hashes / XOFs ------------------------------------------ #
    "BLAKE2B": _Family("BLAKE2b", "hash", ALLOWED, allowed_key_sizes=(256, 512), parameter_kind=DIGEST_BITS, quantum_impact="grover"),
    "BLAKE2S": _Family("BLAKE2s", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS, quantum_impact="grover"),
    "BLAKE3": _Family("BLAKE3", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="modern fast hash/XOF"),
    "KMAC": _Family("KMAC", "mac", ALLOWED, allowed_key_sizes=(128, 256), parameter_kind=KEY_BITS, notes="SHA-3 derived MAC (SP 800-185)"),
    "SKEIN": _Family("Skein", "hash", RESTRICTED, allowed_key_sizes=(256, 512, 1024), parameter_kind=DIGEST_BITS),
    "TIGER": _Family("Tiger", "hash", RESTRICTED, key_size=192, parameter_kind=DIGEST_BITS),
    # -- additional MACs / KDFs -------------------------------------------- #
    "POLY1305": _Family("Poly1305", "mac", ALLOWED, key_size=256, parameter_kind=KEY_BITS, notes="one-time AEAD authenticator (with ChaCha20/AES)"),
    "SIPHASH": _Family("SipHash", "mac", ALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="fast PRF/MAC for hash tables"),
    # -- additional asymmetric --------------------------------------------- #
    "MQV": _Family("MQV", "key-agree", DISALLOWED, min_key_size=2048, quantum_impact="shor", notes="key agreement; not recommended (use ECDHE)"),
    "SRP": _Family("SRP", "key-agree", RESTRICTED, min_key_size=2048, quantum_impact="shor", notes="password-authenticated key exchange; Shor applies"),
    "ELGAMAL": _Family("ElGamal", "pke", DEPRECATED, min_key_size=2048, quantum_impact="shor", notes="legacy; use ECIES/RSA-OAEP"),
    # -- additional curves -------------------------------------------------- #
    "P-224": _Family("P-224", "ec-curve", RESTRICTED, key_size=224, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "BRAINPOOLP384R1": _Family("brainpoolP384r1", "ec-curve", RESTRICTED, key_size=384, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "FRP256V1": _Family("FRP256v1", "ec-curve", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="French ANSSI curve"),
    # -- additional post-quantum (NIST FIPS 203/204/205 + candidates) ----- #
    "FN-DSA": _Family("FN-DSA (Falcon)", "signature-pqc", ALLOWED, notes="FIPS 206 / Falcon lattice signature (draft)"),
    "SLH-DSA": _Family("SLH-DSA", "signature-pqc", ALLOWED, notes="FIPS 205 (SPHINCS+) stateless hash-based signature family"),
    # parameter-set-less family names are what scanners emit for most call sites (KEM.getInstance("ML-KEM"), MLKem.GenerateKey(...))
    "ML-KEM": _Family("ML-KEM", "kem-pqc", ALLOWED, notes="FIPS 203 (Kyber) key-encapsulation family"),
    "ML-DSA": _Family("ML-DSA", "signature-pqc", ALLOWED, notes="FIPS 204 (Dilithium) signature family"),
    "FALCON": _Family("FN-DSA (Falcon)", "signature-pqc", RESTRICTED, notes="FIPS 206 draft (FN-DSA); not yet final"),
    "MCELIECE": _Family("Classic McEliece", "kem-pqc", ALLOWED, notes="NIST PQC round-4 KEM (code-based)"),
    "HQC-128": _Family("HQC-128", "kem-pqc", RESTRICTED, key_size=3626, parameter_kind=KEY_BITS, notes="NIST-selected code-based KEM (2025), level 1"),
    "HQC-192": _Family("HQC-192", "kem-pqc", RESTRICTED, key_size=7242, parameter_kind=KEY_BITS, notes="NIST-selected code-based KEM (2025), level 3"),
    "HQC-256": _Family("HQC-256", "kem-pqc", RESTRICTED, key_size=14434, parameter_kind=KEY_BITS, notes="NIST-selected code-based KEM (2025), level 5"),
    "BIKE": _Family("BIKE", "kem-pqc", RESTRICTED, notes="NIST PQC round-4 KEM (code-based)"),
    "FRODOKEM": _Family("FrodoKEM", "kem-pqc", RESTRICTED, notes="conservative lattice KEM (high bandwidth)"),
    "NTRU": _Family("NTRU", "kem-pqc", RESTRICTED, notes="lattice KEM (legacy/commercial)"),
    # -- additional AEAD / cipher modes ------------------------------------ #
    "AES-CCM": _Family("AES-CCM", "aead", ALLOWED, allowed_key_sizes=(128, 192, 256), min_key_size=128, quantum_impact="grover", notes="AES in CCM mode (AEAD), RFC 3610/4309"),
    "AES-SIV": _Family("AES-SIV", "aead", RESTRICTED, allowed_key_sizes=(256, 512), quantum_impact="grover", notes="misuse-resistant AEAD, RFC 5297 (256/512 = SIV key)"),
    "AEGIS": _Family("AEGIS", "aead", ALLOWED, allowed_key_sizes=(128, 256), quantum_impact="grover", notes="high-performance AEAD (AEGIS-128L, RFC 8452)"),
    "ACORN": _Family("Acorn", "aead", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="CAESAR lightweight AEAD winner"),
    "XOODYAK": _Family("Xoodyak", "aead", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="NIST LWC finalist (Xoodyak)"),
    "ELEPHANT": _Family("Elephant", "aead", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="NIST LWC finalist (Elephant)"),
    "SCHWAEMM": _Family("Schwaemm", "aead", RESTRICTED, allowed_key_sizes=(128, 256), quantum_impact="grover", notes="SPARKLE AEAD (NIST LWC finalist; with Esch hash)"),
    # -- additional block / stream ciphers --------------------------------- #
    "BELT": _Family("BelT", "block-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover", notes="Belarusian STB 34.101.31 block cipher"),
    "TEA": _Family("TEA", "block-cipher", DISALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="Tiny Encryption Algorithm; weak — disallowed"),
    "XXTEA": _Family("XXTEA", "block-cipher", DISALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="Corrected Block TEA; related-key weaknesses"),
    "MARS": _Family("MARS", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), quantum_impact="grover", notes="IBM AES finalist"),
    "NOEKEON": _Family("Noekeon", "block-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="NESSIE block cipher"),
    "SNOW-V": _Family("SNOW-V", "stream-cipher", RESTRICTED, key_size=256, parameter_kind=KEY_BITS, quantum_impact="grover", notes="5G high-speed stream cipher (SNOW-V / SNOW-Vi)"),
    "E0": _Family("E0", "stream-cipher", DISALLOWED, key_size=128, parameter_kind=KEY_BITS, notes="Bluetooth classic stream cipher; practical attacks — disallowed"),
    "MUGI": _Family("MUGI", "stream-cipher", RESTRICTED, key_size=128, parameter_kind=KEY_BITS, quantum_impact="grover", notes="PANAMA-derived 128-bit stream cipher"),
    # -- additional hashes -------------------------------------------------- #
    "KECCAK-256": _Family("Keccak-256", "hash", ALLOWED, key_size=256, parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="pre-FIPS Keccak (Ethereum); distinct padding from SHA3-256"),
    "HAS-160": _Family("HAS-160", "hash", DISALLOWED, key_size=160, parameter_kind=DIGEST_BITS, notes="Korean legacy hash; collision weaknesses — disallowed"),
    "LSH": _Family("LSH", "hash", RESTRICTED, allowed_key_sizes=(256, 512), parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="Korean lightweight hash (LSH-256/512)"),
    "KUPYNA": _Family("Kupyna", "hash", RESTRICTED, allowed_key_sizes=(256, 512), parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="Ukrainian DSTU 7564 hash"),
    "ESCH": _Family("Esch", "hash", RESTRICTED, allowed_key_sizes=(256, 384), parameter_kind=DIGEST_BITS, quantum_impact="grover", notes="SPARKLE hash (NIST LWC finalist; Esch256/384)"),
    # -- additional asymmetric / signature / key agreement ----------------- #
    "ECIES": _Family("ECIES", "pke", RESTRICTED, min_key_size=256, quantum_impact="shor", notes="Elliptic Curve Integrated Encryption Scheme; Shor applies"),
    "BLS": _Family("BLS", "signature", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="Boneh-Lynn-Shacham pairing signature (blockchain)"),
    "GOST3410-2012": _Family("GOST R 34.10-2012", "signature", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="Russian GOST elliptic-curve signature; Shor applies"),
    "DSTU4145": _Family("DSTU 4145", "signature", RESTRICTED, key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="Ukrainian DSTU 4145 elliptic-curve signature; Shor applies"),
    "KCDSA": _Family("KCDSA", "signature", RESTRICTED, key_size=2048, parameter_kind=KEY_BITS, quantum_impact="shor", notes="Korean Certificate-based Digital Signature Algorithm"),
    "ECGDSA": _Family("ECGDSA", "signature", RESTRICTED, min_key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="German EC-GDSA (ECDSA variant over brainpool/secp curves)"),
    "HMQV": _Family("HMQV", "key-agree", RESTRICTED, min_key_size=256, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="hashed MQV authenticated key agreement; Shor applies"),
    "RABIN": _Family("Rabin", "pke", DEPRECATED, min_key_size=2048, quantum_impact="shor", notes="Rabin cryptosystem (factoring-based); legacy"),
    # -- password-authenticated key exchange (aPAKE/PAKE) ----------------- #
    "OPAQUE": _Family("OPAQUE", "key-agree", ALLOWED, quantum_impact="shor", notes="asymmetric PAKE (RFC 9380); Shor applies to the AKE group"),
    "CPACE": _Family("CPace", "key-agree", ALLOWED, quantum_impact="shor", notes="balanced PAKE (RFC 9382); Shor applies to the AKE group"),
    "JPAKE": _Family("J-PAKE", "key-agree", RESTRICTED, quantum_impact="shor", notes="Password Authenticated Key Exchange by Juggling"),
    # -- additional curves (incl. pairing / blockchain) -------------------- #
    "P-192": _Family("P-192", "ec-curve", DISALLOWED, key_size=192, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="secp192r1; ~96-bit security — disallowed"),
    "BRAINPOOLP224R1": _Family("brainpoolP224r1", "ec-curve", RESTRICTED, key_size=224, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "BRAINPOOLP512R1": _Family("brainpoolP512r1", "ec-curve", RESTRICTED, key_size=512, parameter_kind=CURVE_BITS, quantum_impact="shor"),
    "BN254": _Family("BN254", "ec-curve", RESTRICTED, key_size=254, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="alt_bn128 pairing curve (~100-bit security; blockchain)"),
    "BLS12-381": _Family("BLS12-381", "ec-curve", ALLOWED, key_size=381, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="pairing-friendly curve (BLS/Zcash/Ethereum)"),
    "BLS12-377": _Family("BLS12-377", "ec-curve", RESTRICTED, key_size=377, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="pairing-friendly curve"),
    "BW6-761": _Family("BW6-761", "ec-curve", RESTRICTED, key_size=761, parameter_kind=CURVE_BITS, quantum_impact="shor", notes="pairing-friendly curve (two-layer proof systems)"),
    # -- post-quantum KEMs (broken / superseded / not-selected) ----------- #
    "SIKE": _Family("SIKE", "kem-pqc", DISALLOWED, notes="Supersingular Isogeny KEM — broken by Castryck-Decru (2022); disallowed"),
    "SIDH": _Family("SIDH", "kem-pqc", DISALLOWED, notes="Supersingular Isogeny DH — broken (2022); disallowed"),
    "NEWHOPE": _Family("NewHope", "kem-pqc", DEPRECATED, notes="early lattice KEM; superseded by ML-KEM (Kyber)"),
    "SABER": _Family("SABER", "kem-pqc", RESTRICTED, notes="NIST PQC round-3 finalist (module LWR); not standardized"),
    "NTRUPRIME": _Family("NTRU-Prime", "kem-pqc", RESTRICTED, notes="Streamlined NTRU Prime (sntrup761/1277); round-3 candidate"),
    # -- post-quantum signatures (broken / stateful hash-based) ----------- #
    "RAINBOW": _Family("Rainbow", "signature-pqc", DISALLOWED, notes="multivariate signature — broken by Ward-Beullens (2022); disallowed"),
    "GEMSS": _Family("GeMSS", "signature-pqc", RESTRICTED, notes="multivariate (HFEv-) signature candidate; not standardized"),
    "XMSS": _Family("XMSS", "signature-pqc", ALLOWED, notes="stateful hash-based signature (RFC 8391, NIST SP 800-208); quantum-safe"),
    "LMS": _Family("LMS", "signature-pqc", ALLOWED, notes="Leighton-Micali stateful hash-based signature (RFC 8554, SP 800-208); quantum-safe"),
    # -- random number generators / DRBG ---------------------------------- #
    "DUAL-EC-DRBG": _Family("Dual-EC-DRBG", "rng", DISALLOWED, notes="NSA-backdoored DRBG (NIST SP 800-90A); never use — disallowed"),
    "HMAC-DRBG": _Family("HMAC-DRBG", "rng", ALLOWED, notes="NIST SP 800-90A HMAC-based DRBG"),
    "CTR-DRBG": _Family("CTR-DRBG", "rng", ALLOWED, notes="NIST SP 800-90A CTR-mode DRBG"),
    "HASH-DRBG": _Family("Hash-DRBG", "rng", ALLOWED, notes="NIST SP 800-90A hash-based DRBG"),
    # -- format-preserving encryption -------------------------------------- #
    "FF1": _Family("FF1", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), quantum_impact="grover", notes="NIST SP 800-38Gr2 format-preserving encryption (AES-based)"),
    "FF3-1": _Family("FF3-1", "block-cipher", RESTRICTED, allowed_key_sizes=(128, 192, 256), quantum_impact="grover", notes="NIST SP 800-38Gr2 format-preserving encryption"),
}

# Aliases: normalized (upper, separators stripped) -> canonical family key.
_ALIASES: dict[str, str] = {
    "AES128": "AES", "AES192": "AES", "AES256": "AES",
    "AESGCM": "AES-GCM", "AESCCM": "AES-CCM", "AESSIV": "AES-SIV",
    "AESKW": "AES", "AES128KW": "AES", "AES256KW": "AES",
    "CCM": "AES-CCM",
    "AESXTS": "AES-XTS",
    "DESEDE": "3DES", "TRIPLEDES": "3DES", "3KEYTRIPLEDES": "3DES", "DESEDE3": "3DES",
    "ARCFOUR": "RC4", "RC4MD5": "RC4",
    "BF": "BLOWFISH", "BLOWFISH2": "BLOWFISH",
    "CAST": "CAST5",
    "SHA": "SHA-1", "SHA1": "SHA-1",
    "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "SHA512224": "SHA-512/224", "SHA512256": "SHA-512/256",
    "SHA3224": "SHA3-224", "SHA3256": "SHA3-256", "SHA3384": "SHA3-384", "SHA3512": "SHA3-512",
    "KECCAK256": "KECCAK-256", "KECCAK": "KECCAK-256", "KECCAK-256": "KECCAK-256",
    "RIPEMD": "RIPEMD160", "RIPEMD128": "RIPEMD160",
    "HMACSHA1": "HMAC-SHA-1", "HMACSHA224": "HMAC-SHA-224", "HMACSHA256": "HMAC-SHA-256",
    "HMACSHA384": "HMAC-SHA-384", "HMACSHA512": "HMAC-SHA-512", "HMACMD5": "HMAC-MD5",
    "HMACSHA2256": "HMAC-SHA-256", "HMACSHA2512": "HMAC-SHA-512",
    "RSASSAPSS": "RSA-PSS", "RSAPSS": "RSA-PSS",
    "RSAPKCS1": "RSA-PKCS1V15", "RSA1_5": "RSA-PKCS1V15",
    "DIFFIEHELLMAN": "DH", "MODP": "DH",
    "ECIES": "ECIES",
    "EDDSA": "ED25519",
    "PRIME256V1": "P-256", "SECP256R1": "P-256", "NISTP256": "P-256",
    "SECP384R1": "P-384", "NISTP384": "P-384", "SECP521R1": "P-521", "NISTP521": "P-521",
    "BRAINPOOLP320R1": "BRAINPOOLP384R1",
    # JOSE (RFC 7518)
    "HS256": "HMAC-SHA-256", "HS384": "HMAC-SHA-384", "HS512": "HMAC-SHA-512",
    "RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
    "PS256": "RSA-PSS", "PS384": "RSA-PSS", "PS512": "RSA-PSS",
    "ES256": "ECDSA", "ES384": "ECDSA", "ES512": "ECDSA",
    "ES256K": "SECP256K1",
    "A128GCM": "AES-GCM", "A192GCM": "AES-GCM", "A256GCM": "AES-GCM",
    "A128CBC": "AES", "A192CBC": "AES", "A256CBC": "AES",
    "A128CBCHS256": "AES", "A192CBCHS384": "AES", "A256CBCHS512": "AES",
    "A128KW": "AES", "A192KW": "AES", "A256KW": "AES",
    "A128CTR": "AES", "A192CTR": "AES", "A256CTR": "AES",
    # SHA-1 JOSE variants (RFC 8812). Deprecated, and they must resolve so the
    # policy layer sees SHA-1 rather than an unrecognized token.
    "RS1": "RSA", "HS1": "HMAC-SHA-1",
    # ECDH-ES key agreement, with and without the AES key-wrap suffix.
    "ECDHES": "ECDH-ES",
    "ECDHESA128KW": "ECDH-ES", "ECDHESA192KW": "ECDH-ES", "ECDHESA256KW": "ECDH-ES",
    "RSAOAEP": "RSA-OAEP", "RSAOAEP256": "RSA-OAEP",
    # PQC aliases
    "MLKEM512": "ML-KEM-512", "MLKEM768": "ML-KEM-768", "MLKEM1024": "ML-KEM-1024",
    "TLSV1.0": "TLS 1.0", "TLSV1": "TLS 1.0", "TLS10": "TLS 1.0",
    "TLSV1.1": "TLS 1.1", "TLSV11": "TLS 1.1",
    "TLSV1.2": "TLS 1.2", "TLSV12": "TLS 1.2",
    "TLSV1.3": "TLS 1.3", "TLSV13": "TLS 1.3",
    "SSLV3": "SSL 3.0", "SSL3": "SSL 3.0", "SSL30": "SSL 3.0",
    "SSLV2": "SSL 2.0", "SSL2": "SSL 2.0", "SSL20": "SSL 2.0",
    # scanner spellings seen across the accuracy corpus (normaliser→CBOM contract test)
    "ECDHE": "ECDH", "AESCMAC": "CMAC", "XSALSA20POLY1305": "XSALSA20",
    "DTLS1.0": "DTLS 1.0", "DTLS10": "DTLS 1.0",
    "DTLS1.2": "DTLS 1.2", "DTLS12": "DTLS 1.2",
    "KYBER512": "KYBER", "KYBER768": "KYBER", "KYBER1024": "KYBER",
    "MLDSA44": "ML-DSA-44", "MLDSA65": "ML-DSA-65", "MLDSA87": "ML-DSA-87",
    "DILITHIUM2": "DILITHIUM", "DILITHIUM3": "DILITHIUM", "DILITHIUM5": "DILITHIUM",
    "SPHINCS": "SLH-DSA", "SPHINCSPLUS": "SLH-DSA", "SLHDSA128S": "SLH-DSA-128S", "SLHDSASPHINCS": "SLH-DSA",
    "FNDSA": "FALCON", "FNDSAFALCON": "FALCON",
    # Chinese GM/T
    "SM2WITHSM3": "SM2", "SM2SIGN": "SM2", "SM2-256": "SM2",
    "SM3-256": "SM3", "SM4-128": "SM4", "SMS4": "SM4",
    # Russian GOST
    "GRASSHOPPER": "KUZNYECHIK", "GRASSHOPPER-M": "KUZNYECHIK",
    "GOST3412-2015-K": "KUZNYECHIK", "GOST-R-3412": "KUZNYECHIK",
    "GOST3412-2015-M": "MAGMA",
    "GOST3411-2012-256": "STREEBOG", "GOST3411-2012-512": "STREEBOG", "STREEBOG-256": "STREEBOG", "STREEBOG-512": "STREEBOG",
    "GOSTR341194": "GOST3411-94", "GOST94": "GOST3411-94",
    # hashes
    "BLAKE2B-512": "BLAKE2B", "BLAKE2S-256": "BLAKE2S", "BLAKE2": "BLAKE2B",
    # AEAD / lightweight / legacy
    "CHACHAPOLY": "CHACHA20-POLY1305", "CHACHA20POLY1305": "CHACHA20-POLY1305",
    "XCHACHAPOLY": "XCHACHA20-POLY1305",
    "POLY1305": "POLY1305",
    "A5/1": "A5-1", "A51": "A5-1", "A5/2": "A5-2", "A52": "A5-2",
    "SNOW3G": "SNOW3G", "SNOW-3G": "SNOW3G",
    # lightweight / code-based PQC name variants
    "PRESENT80": "PRESENT", "PRESENT128": "PRESENT",
    "GRAIN128": "GRAIN", "GRAIN128A": "GRAIN",
    "CLASSICMCELIECE": "MCELIECE", "MCELIECE348864": "MCELIECE",
    "KALYNA": "DSTU7624",
    "HQC": "HQC-128", "HQC128": "HQC-128", "HQC192": "HQC-192", "HQC256": "HQC-256",
    # AEAD / lightweight / CAESAR
    "AESCCM8": "AES-CCM", "AES-128-CCM": "AES-CCM", "AES-256-CCM": "AES-CCM",
    "GCM-SIV": "AES-SIV", "AESGCMSIV": "AES-SIV",
    "AEGIS128": "AEGIS", "AEGIS128L": "AEGIS", "AEGIS256": "AEGIS",
    # SP 800-232 / IANA spellings, which run the words together.
    "ASCONAEAD128": "ASCON-AEAD128", "ASCONHASH256": "ASCON-HASH256",
    "ASCONXOF128": "ASCON-XOF128", "ASCONCXOF128": "ASCON-CXOF128",
    "ASCONAEAD": "ASCON-AEAD128", "ASCONHASH": "ASCON-HASH256",
    "ACORN128": "ACORN", "XOOYAKAEAD": "XOODYAK", "XOOYAK": "XOODYAK", "XOODYAK": "XOODYAK",
    "A53": "KASUMI", "A5/3": "KASUMI", "A54": "KASUMI", "A5/4": "KASUMI", "F8": "KASUMI", "F9": "KASUMI",
    # additional ciphers
    "BELT-256": "BELT", "STB3410131": "BELT",
    "XXTEA": "XXTEA", "TEA": "TEA", "TINYENCRYPTION": "TEA",
    "SNOWV": "SNOW-V", "SNOWVI": "SNOW-V",
    "BLUETOOTHE0": "E0",
    # hashes
    "HAS160": "HAS-160", "LSH256": "LSH", "LSH512": "LSH",
    "KUPYNA-256": "KUPYNA", "KUPYNA-512": "KUPYNA", "DSTU7564": "KUPYNA",
    "ESCH256": "ESCH", "ESCH384": "ESCH", "SPARKLE": "ESCH",
    # asymmetric / pairing / blockchain
    "BLSSIGNATURE": "BLS", "BLSSIG": "BLS",
    "BLST": "BLS", "BN128": "BN254", "ALTBN128": "BN254",
    "BL12381": "BLS12-381", "BLS12381G1": "BLS12-381", "BLS12381G2": "BLS12-381",
    "BL12377": "BLS12-377", "BW6761": "BW6-761",
    "GOSTR34102012": "GOST3410-2012", "GOST3410": "GOST3410-2012",
    "GOST3410-2001": "GOST3410-2012", "GOST3410-94": "GOST3410-2012",
    "DSTU4145": "DSTU4145", "UKRSIGN": "DSTU4145",
    "EC-GDSA": "ECGDSA", "ECGDSA": "ECGDSA",
    "HMQV": "HMQV", "ECMQV": "MQV", "EC-MQV": "MQV",
    "RABINWILLIAMS": "RABIN",
    "KCDSA": "KCDSA",
    # PAKE
    "JPAKE": "JPAKE", "CPACE": "CPACE", "OPAQUE": "OPAQUE",
    # curves
    "SECP192R1": "P-192", "NISTP192": "P-192", "P192": "P-192",
    "BRAINPOOLP224R1": "BRAINPOOLP224R1", "BRAINPOOLP256R1": "BRAINPOOLP256R1",
    "BRAINPOOLP512R1": "BRAINPOOLP512R1",
    # PQC — broken / superseded / hash-based stateful
    "SIKEP434": "SIKE", "SIKECMP": "SIKE", "CSIDH": "SIKE",
    "NEWHOPE512": "NEWHOPE", "NEWHOPE1024": "NEWHOPE",
    "SABER": "SABER", "LIGHTSABER": "SABER", "FIRESABER": "SABER",
    "NTRUPRIME": "NTRUPRIME", "SNTRUP761": "NTRUPRIME", "SNTRUP1277": "NTRUPRIME", "SNTRUP": "NTRUPRIME",
    "RAINBOW": "RAINBOW", "RAINBOW-I": "RAINBOW",
    "GEMSS": "GEMSS", "GEMSS128": "GEMSS",
    "XMSS": "XMSS", "XMSSMT": "XMSS",
    "LMS": "LMS", "HSS": "LMS", "LEIGHTONMICALI": "LMS",
    # DRBG / RNG
    "DUALECDRBG": "DUAL-EC-DRBG", "DUALEC": "DUAL-EC-DRBG", "DUAL_EC": "DUAL-EC-DRBG",
    "HMACDRBG": "HMAC-DRBG", "CTRDRBG": "CTR-DRBG", "HASHDRBG": "HASH-DRBG",
    # FPE
    "FF1": "FF1", "FPE-AES": "FF1", "FF31": "FF3-1", "FF3": "FF3-1",
}

# JOSE aliases carry an implied size — map alias -> (family key, bits)
_JOSE_SIZES: dict[str, int] = {
    "HS256": 256, "HS384": 384, "HS512": 512,
    "RS256": 2048, "RS384": 3072, "RS512": 4096,
    "PS256": 2048, "PS384": 3072, "PS512": 4096,
    "ES256": 256, "ES384": 384, "ES512": 521,
    "A128GCM": 128, "A192GCM": 192, "A256GCM": 256,
    "A128CBC": 128, "A192CBC": 192, "A256CBC": 256,
    "A128KW": 128, "A192KW": 192, "A256KW": 256,
    "RSAOAEP": 2048, "RSAOAEP256": 2048,
}

# sizes that may appear embedded in names: AES-256, RSA2048, SHA512, P-384
_EMBEDDED_SIZE = re.compile(r"(\d{3,4})")
_CURVE_SIZE = re.compile(r"(?:P|NISTP|SECP\d*)(?:-)?(256|384|521)", re.IGNORECASE)
_VALID_SIZES = {56, 64, 80, 112, 128, 160, 168, 192, 224, 256, 384, 512, 521, 1024, 1536, 2048, 3072, 4096, 7680, 8192, 15360}

# families where an embedded number is a KEY size
_KEYED = {"AES", "AES-GCM", "AES-XTS", "CAMELLIA", "ARIA", "SEED", "RC2", "RC5", "RC6", "BLOWFISH", "TWOFISH", "CAST5", "RSA", "RSA-PSS", "RSA-OAEP", "DSA", "DH", "DES", "3DES", "CHACHA20"}
_HASHED = {"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256", "MD5", "MD2", "MD4", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "HMAC-SHA-1", "HMAC-SHA-224", "HMAC-SHA-256", "HMAC-SHA-384", "HMAC-SHA-512", "HMAC-MD5"}

# TLS suite markers (checked on the separator-stripped upper name)
_TLS_DISALLOWED_MARKERS = ("WITHNULL", "EXPORT", "WITHDES", "WITH3DES", "WITHRC4", "WITHIDEA", "WITHSEED", "WITHCAMELLIA40")
_TLS_WEAK_HASH = ("SHA1", "MD5")
_TLS_CHACHA = ("WITHCHACHA20POLY1305",)

# key-exchange prefix -> structured parts
_TLS_KX_PARTS = {
    "ECDHEECDSA": ("ECDH", "ECDSA"),
    "ECDHERSA": ("ECDH", "RSA"),
    "ECDHEED25519": ("ECDH", "Ed25519"),
    "DHERSA": ("DH", "RSA"),
    "DHEDSS": ("DH", "DSA"),
    "ECDHANON": ("ECDH",),
    "DHANON": ("DH",),
    "RSA": ("RSA",),
    "PSK": (),
}


# -- normalize every catalog/alias/set key to stripped alnum-upper form --- #
_FAMILIES = {_norm_key(k): v for k, v in _FAMILIES.items()}
_ALIASES = {_norm_key(k): _norm_key(v) for k, v in _ALIASES.items()}
_JOSE_SIZES = {_norm_key(k): v for k, v in _JOSE_SIZES.items()}
_KEYED = {_norm_key(k) for k in _KEYED}
_HASHED = {_norm_key(k) for k in _HASHED}


def _strip(raw: str) -> str:
    text = raw.strip().upper()
    # drop @openssh.com / @libssh.org suffixes and size hints like (256)
    text = text.split("@", 1)[0]
    return "".join(ch for ch in text if ch.isalnum())


def _mode_of(stripped: str) -> str | None:
    for token, mode in (
        ("GCM", "GCM"), ("CCM", "CCM"), ("SIV", "SIV"), ("XTS", "XTS"),
        ("CBC", "CBC"), ("CFB", "CFB"), ("OFB", "OFB"), ("CTR", "CTR"), ("ECB", "ECB"),
    ):
        if token in stripped:
            return mode
    return None


#: Every TLS suite IANA registers without a ``_WITH_`` segment, i.e. the
#: TLS 1.3 naming shape (tls-parameters-4, snapshot in
#: shared_models/data/iana_tls_parameters.csv; the completeness test asserts
#: this table covers all of them).
#:
#: ``(bulk_cipher, key_bits, mac, status, note)``. Status is carried per-suite
#: rather than assumed ALLOWED: two of these encrypt nothing at all.
_TLS13_SUITES = {
    "TLSAES128GCMSHA256": ("AES-128-GCM", 128, "SHA-256", ALLOWED, ""),
    "TLSAES256GCMSHA384": ("AES-256-GCM", 256, "SHA-384", ALLOWED, ""),
    "TLSCHACHA20POLY1305SHA256": ("ChaCha20-Poly1305", 256, "SHA-256", ALLOWED, ""),
    "TLSAES128CCMSHA256": ("AES-128-CCM", 128, "SHA-256", ALLOWED, ""),
    "TLSAES128CCM8SHA256": ("AES-128-CCM8", 128, "SHA-256", RESTRICTED,
                            "8-octet tag: not Recommended by IANA"),
    # RFC 8998 — ShangMi suites for TLS 1.3 (Chinese national algorithms).
    "TLSSM4GCMSM3": ("SM4-GCM", 128, "SM3", RESTRICTED,
                     "RFC 8998 ShangMi; not IANA-Recommended outside GB/T deployments"),
    "TLSSM4CCMSM3": ("SM4-CCM", 128, "SM3", RESTRICTED,
                     "RFC 8998 ShangMi; not IANA-Recommended outside GB/T deployments"),
    # draft-irtf-cfrg-aegis-aead
    "TLSAEGIS256SHA512": ("AEGIS-256", 256, "SHA-512", RESTRICTED, "AEGIS draft suite"),
    "TLSAEGIS128LSHA256": ("AEGIS-128L", 128, "SHA-256", RESTRICTED, "AEGIS draft suite"),
    # NIST SP 800-232 / RFC 9846 — Ascon lightweight suites.
    "TLSASCONAEAD128ASCONHASH256": ("Ascon-AEAD128", 128, "Ascon-Hash256", RESTRICTED,
                                    "NIST SP 800-232 lightweight suite"),
    "TLSASCONAEAD128SHA256": ("Ascon-AEAD128", 128, "SHA-256", RESTRICTED,
                              "NIST SP 800-232 lightweight suite"),
    "TLSAES128GCMASCONHASH256": ("AES-128-GCM", 128, "Ascon-Hash256", RESTRICTED,
                                 "NIST SP 800-232 lightweight suite"),
    "TLSAES128CCMASCONHASH256": ("AES-128-CCM", 128, "Ascon-Hash256", RESTRICTED,
                                 "NIST SP 800-232 lightweight suite"),
    # RFC 9150 — integrity-only. These negotiate NO ENCRYPTION: the record
    # protocol authenticates and sends plaintext. Parsing them as their hash
    # (which is what the bare name looks like) hides exactly that, so they are
    # DISALLOWED here and say so in the note.
    "TLSSHA256SHA256": (None, None, "SHA-256", DISALLOWED,
                        "RFC 9150 integrity-only: NO ENCRYPTION, plaintext on the wire"),
    "TLSSHA384SHA384": (None, None, "SHA-384", DISALLOWED,
                        "RFC 9150 integrity-only: NO ENCRYPTION, plaintext on the wire"),
}

#: Signalling Cipher Suite Values: negotiation signals that occupy cipher-suite
#: code points but name no algorithm. Recognised so a scan reports them as what
#: they are instead of leaving them as unparsed noise.
_TLS_SCSV = {
    "TLSEMPTYRENEGOTIATIONINFOSCSV": (
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        "RFC 5746 secure-renegotiation signal (not a cipher suite)",
    ),
    "TLSFALLBACKSCSV": (
        "TLS_FALLBACK_SCSV",
        "RFC 7507 downgrade-protection signal (not a cipher suite)",
    ),
}


def _looks_like_tls_suite(stripped: str) -> bool:
    if stripped in _TLS13_SUITES or stripped in _TLS_SCSV:
        return True
    return stripped.startswith("TLS") and "WITH" in stripped


def _parse_tls_suite(raw: str, stripped: str) -> AlgorithmInfo:
    """Break a TLS cipher suite into components with an overall verdict."""
    components: list[dict[str, Any]] = []

    def add(part: str, role: str) -> None:
        entry = parse_algorithm(part).to_dict()
        entry["role"] = role
        components.append(entry)

    if stripped in _TLS_SCSV:
        canonical, note = _TLS_SCSV[stripped]
        return AlgorithmInfo(
            raw=raw,
            canonical=canonical,
            family="tls-signalling",
            status=ALLOWED,
            notes=note,
        )

    if stripped in _TLS13_SUITES:
        cipher, bits, mac, status, note = _TLS13_SUITES[stripped]
        if cipher is not None:
            add(cipher, "bulk_cipher")
        add(mac, "mac")
        detail = f"TLS 1.3 suite ({cipher})" if cipher else "TLS 1.3 suite (no bulk cipher)"
        return AlgorithmInfo(
            raw=raw,
            canonical=raw.strip(),
            family="tls-suite",
            status=status,
            key_size=bits,
            parameter_kind=KEY_BITS if bits else None,
            mode=("GCM" if cipher and "GCM" in cipher
                  else "CCM" if cipher and "CCM" in cipher else None),
            quantum_impact="grover",
            notes=f"{detail} — {note}" if note else detail,
            components=tuple(components),
        )

    for kx, parts in _TLS_KX_PARTS.items():
        if stripped.startswith("TLS" + kx) or ("_" + kx + "_") in raw.upper() or kx in stripped[len("TLS"): len("TLS") + len(kx) + 1]:
            for part in parts:
                add(part, "key_exchange" if part in {"ECDH", "DH"} else "signature")
            break

    cipher_part = None
    for marker in ("WITHAES128", "WITHAES256", "WITHAES", "WITH3DES", "WITHDES", "WITHRC4", "WITHCHACHA20POLY1305", "WITHCAMELLIA", "WITHARIA", "WITHSEED", "WITHIDEA", "WITHNULL"):
        if marker in stripped:
            cipher_part = marker[len("WITH"):]
            break
    if cipher_part == "CHACHA20POLY1305":
        add("ChaCha20-Poly1305", "bulk_cipher")
    elif cipher_part and cipher_part != "NULL":
        suffix = "GCM" if "GCM" in stripped else ("CCM" if "CCM" in stripped else "CBC")
        add(cipher_part + suffix, "bulk_cipher")

    if "SHA384" in stripped:
        add("SHA-384", "mac")
    elif "SHA256" in stripped:
        add("SHA-256", "mac")
    elif "SHA1" in stripped or stripped.endswith("SHA"):
        add("SHA-1", "mac")
    if "MD5" in stripped:
        add("MD5", "mac")

    status = ALLOWED
    notes = ""
    if any(m in stripped for m in _TLS_DISALLOWED_MARKERS):
        status = DISALLOWED
        notes = "NULL/EXPORT/DES/RC4-class cipher suite"
    elif any(m in stripped for m in _TLS_WEAK_HASH):
        status = DEPRECATED
        notes = "SHA-1/MD5 MAC"
    elif "3DES" in stripped or "CAMELLIA" in stripped or "ARIA" in stripped or "SEED" in stripped or "IDEA" in stripped:
        status = RESTRICTED
        notes = "legacy bulk cipher"
    elif "CBC" in stripped:
        status = RESTRICTED
        notes = "CBC mode — prefer AEAD suites"
    elif any(m in stripped for m in _TLS_CHACHA) or "WITHAES" in stripped:
        status = ALLOWED

    key_size = None
    if "AES128" in stripped or "CHACHA20" in stripped or "RC4" in stripped or "SEED" in stripped or "IDEA" in stripped:
        key_size = 128
    elif "AES256" in stripped or "CAMELLIA256" in stripped or "ARIA256" in stripped:
        key_size = 256
    elif "3DES" in stripped or "DESEDE" in stripped:
        key_size = 168
    elif "WITHDES" in stripped:
        key_size = 56
    elif "CAMELLIA128" in stripped or "ARIA128" in stripped:
        key_size = 128

    return AlgorithmInfo(
        raw=raw,
        canonical=raw.strip(),
        family="tls-suite",
        status=status,
        key_size=key_size,
        parameter_kind=KEY_BITS if key_size else None,
        mode=_mode_of(stripped),
        quantum_impact="shor" if any(c.get("quantum_impact") == "shor" for c in components) else None,
        notes=notes or "TLS cipher suite",
        components=tuple(components),
    )


def parse_algorithm(raw: str) -> AlgorithmInfo:
    """Parse any algorithm name into canonical + key-size + verdict."""
    if not raw or not str(raw).strip():
        return AlgorithmInfo(raw=str(raw or ""), canonical="", family="unknown", status=UNKNOWN, recognized=False)

    text = str(raw).strip()
    stripped = _strip(text)
    components: list[dict[str, Any]] = []

    # TLS suites get component-level treatment
    if _looks_like_tls_suite(stripped):
        return _parse_tls_suite(text, stripped)

    # -- 1) JCA signature combos: SHA256withRSA, MD5withRSA --------- #
    combo = re.fullmatch(r"(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)WITH(RSA|DSA|ECDSA|EC)(\d{3,4})?", stripped)
    if combo:
        hash_raw, sig_raw, size = combo.group(1), combo.group(2), combo.group(3)
        hash_key = _ALIASES.get(hash_raw, hash_raw)
        sig_key = _ALIASES.get(sig_raw, sig_raw)
        hash_fam = _FAMILIES.get(hash_key)
        sig_fam = _FAMILIES.get(sig_key)
        if hash_fam and sig_fam:
            for fam, role in ((hash_fam, "hash"), (sig_fam, "signature")):
                entry = AlgorithmInfo(
                    raw=fam.canonical, canonical=fam.canonical, family=fam.family, status=fam.status,
                    key_size=fam.key_size, parameter_kind=fam.parameter_kind,
                    allowed_key_sizes=fam.allowed_key_sizes, min_key_size=fam.min_key_size,
                    quantum_impact=fam.quantum_impact, notes=fam.notes,
                ).to_dict()
                entry["role"] = role
                components.append(entry)
            bits = int(size) if size else None
            if sig_fam.canonical == "RSA" and bits is None:
                bits = 2048  # JCA default
            status = ALLOWED
            if hash_fam.status == DISALLOWED:
                status = DISALLOWED
                notes = f"{hash_fam.canonical} digest — broken for signatures"
            elif hash_fam.status == DEPRECATED:
                status = DEPRECATED
                notes = f"{hash_fam.canonical} digest deprecated for signatures"
            else:
                notes = f"{hash_fam.canonical} with {sig_fam.canonical}"
            if bits and sig_fam.min_key_size and bits < sig_fam.min_key_size:
                status = DISALLOWED
                notes = f"{sig_fam.canonical} {bits} bits below {sig_fam.min_key_size}"
            return AlgorithmInfo(
                raw=text, canonical=sig_fam.canonical, family=sig_fam.family, status=status,
                key_size=bits, parameter_kind=KEY_BITS if bits else None, mode=None,
                allowed_key_sizes=sig_fam.allowed_key_sizes, min_key_size=sig_fam.min_key_size,
                quantum_impact=sig_fam.quantum_impact, notes=notes, components=tuple(components),
            )

    # -- 2) KDF with PRF: PBKDF2WithHmacSHA256 ----------------------- #
    kdf = re.fullmatch(r"(PBKDF2|SCRYPT|ARGON2|BCRYPT|HKDF)(WITHHMAC)?(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)?", stripped)
    if kdf:
        kdf_key = _ALIASES.get(kdf.group(1), kdf.group(1))
        fam = _FAMILIES.get(kdf_key)
        if fam:
            if kdf.group(3):
                prf = _FAMILIES.get(_ALIASES.get(kdf.group(3), kdf.group(3)))
                if prf:
                    entry = AlgorithmInfo(
                        raw=prf.canonical, canonical=prf.canonical, family=prf.family, status=prf.status,
                        key_size=prf.key_size, parameter_kind=prf.parameter_kind,
                        quantum_impact=prf.quantum_impact, notes=prf.notes,
                    ).to_dict()
                    entry["role"] = "prf"
                    components.append(entry)
            return AlgorithmInfo(
                raw=text, canonical=fam.canonical, family=fam.family, status=fam.status,
                key_size=None, parameter_kind=None, allowed_key_sizes=fam.allowed_key_sizes,
                min_key_size=fam.min_key_size, quantum_impact=fam.quantum_impact,
                notes=fam.notes, components=tuple(components),
            )

    # -- 3) DH groups / MODP names ----------------------------------- #
    grp = re.search(r"(?:DIFFIEHELLMAN|DH)?GROUP(\d+)", stripped)
    modp = re.search(r"MODP(\d{3,4})", stripped)
    if grp or modp or stripped.startswith("DIFFIEHELLMAN"):
        if modp:
            bits = int(modp.group(1))
            label = f"DH {bits}"
        else:
            bits = {"1": 1024, "2": 1024, "5": 1536, "14": 2048, "15": 3072, "16": 4096, "17": 6144, "18": 8192}.get(grp.group(1) if grp else "", None)
            label = f"DH group-{grp.group(1)}" if grp else "DH"
        if bits is None:
            m = _EMBEDDED_SIZE.search(stripped)
            bits = int(m.group(1)) if m and int(m.group(1)) in _VALID_SIZES else None
        status = DISALLOWED if bits and bits < 2048 else RESTRICTED
        return AlgorithmInfo(
            raw=text, canonical=label, family="key-agree", status=status, key_size=bits,
            parameter_kind=KEY_BITS if bits else None, min_key_size=2048, quantum_impact="shor",
            notes="finite-field DH" + (" (<2048)" if bits and bits < 2048 else ""),
        )

    # -- 4) elliptic-curve names: nistp256 / ECDSA-P384 / prime256v1 - #
    curve = re.fullmatch(r"P(256|384|521)", stripped)
    curveish = (
        curve
        or "NISTP" in stripped
        or "SECP" in stripped
        or "PRIME" in stripped
        or re.search(r"ECDSAP?(256|384|521)$", stripped)
        or re.search(r"ECDHP?(256|384|521)$", stripped)
    )
    if curveish and stripped not in _FAMILIES and stripped not in _ALIASES:
        m_curve = re.search(r"(256|384|521)", stripped)
        bits = int(m_curve.group(1)) if m_curve else 256
        is_dh = "ECDH" in stripped or "X25519" in stripped
        fam = _FAMILIES.get("ECDH" if is_dh else "ECDSA")
        return AlgorithmInfo(
            raw=text, canonical=fam.canonical, family=fam.family, status=ALLOWED, key_size=bits,
            parameter_kind=CURVE_BITS, min_key_size=fam.min_key_size, quantum_impact="shor",
            notes=f"{'ECDH' if is_dh else 'ECDSA'} on P-{bits}",
        )

    # -- 5) SSH names ------------------------------------------------- #
    if stripped.startswith("SSH"):
        if "ED25519" in stripped:
            return _info(text, "ED25519")
        if "ECDSA" in stripped:
            m = re.search(r"(256|384|521)", stripped)
            return _info(text, f"P-{m.group(1)}" if m else "P-256")
        if "RSA" in stripped:
            return AlgorithmInfo(
                raw=text, canonical="ssh-rsa", family="signature", status=DEPRECATED,
                key_size=None, min_key_size=2048, quantum_impact="shor",
                notes="OpenSSH rsa-sha2-* required; ssh-rsa implies SHA-1",
            )
        return AlgorithmInfo(raw=text, canonical=text, family="signature", status=UNKNOWN, recognized=False)

    # -- 6) tolerant family resolution -------------------------------- #
    family_key = _resolve_family(stripped)
    if family_key is None:
        m2 = _EMBEDDED_SIZE.search(stripped)
        size = int(m2.group(1)) if m2 and int(m2.group(1)) in _VALID_SIZES else None
        return AlgorithmInfo(
            raw=text, canonical=text, family="unknown", status=UNKNOWN,
            key_size=size, parameter_kind=KEY_BITS if size else None,
            recognized=False, notes="no catalog match — needs human review",
        )

    mode = _mode_of(stripped)
    # AES + GCM/XTS token => the AEAD families
    if family_key == "AES" and mode == "GCM" and "GCM" in stripped:
        family_key = "AESGCM"
    elif family_key == "AES" and mode == "XTS" and "XTS" in stripped:
        family_key = "AESXTS"

    family = _FAMILIES[family_key]
    bits = family.key_size
    kind = family.parameter_kind

    # embedded size overrides default (AES-256, RSA-2048, ...)
    m = _EMBEDDED_SIZE.search(stripped)
    if m and int(m.group(1)) in _VALID_SIZES and (family_key in _KEYED or family_key in _HASHED):
        bits = int(m.group(1))
        kind = family.parameter_kind or (KEY_BITS if family_key in _KEYED else DIGEST_BITS)
    # JOSE implied sizes
    if stripped in _JOSE_SIZES:
        bits = _JOSE_SIZES[stripped]
        kind = CURVE_BITS if family.family in {"signature", "key-agree", "ec-curve"} and family_key.startswith("ES") else KEY_BITS
    if family.parameter_kind == CURVE_BITS or family_key in {"ED25519", "X25519", "ED448", "X448"}:
        kind = CURVE_BITS

    # -- 7) size-dependent status ------------------------------------- #
    status = family.status
    notes = family.notes
    if family_key in {"RSA", "RSAPSS", "RSAOAEP"} and bits:
        if bits < 2048:
            status, notes = DISALLOWED, f"RSA {bits} bits — below 2048 minimum (SP 800-131A)"
    elif family_key in {"AES", "AESGCM", "AESXTS"} and bits and bits not in family.allowed_key_sizes:
        status, notes = UNKNOWN, f"non-standard {family.canonical} key size {bits}"
    if mode == "ECB" and family_key in _KEYED:
        status, notes = DISALLOWED, "ECB mode — deterministic, leaks patterns"

    return AlgorithmInfo(
        raw=text,
        canonical=family.canonical,
        family=family.family,
        status=status,
        key_size=bits,
        parameter_kind=kind,
        mode=mode,
        allowed_key_sizes=family.allowed_key_sizes,
        min_key_size=family.min_key_size,
        quantum_impact=family.quantum_impact,
        notes=notes,
    )


# padding / trailing tokens stripped when resolving a family name
_STRIP_SUFFIXES = (
    "NOPADDING", "PKCS5PADDING", "PKCS1PADDING", "PKCS7PADDING", "ISO10126PADDING", "SSL3PADDING",
    "OAEPPADDING", "WITHRSAANDMGF1", "WITHMGF1", "USEDSRONLY",
)
_MODE_TOKENS = ("CFB8", "GCM", "CCM", "SIV", "XTS", "CBC", "CFB", "OFB", "CTR", "ECB")


def _resolve_family(stripped: str) -> str | None:
    """Resolve a stripped name to a family key, tolerating sizes, paddings
    and mode tokens anywhere in the string."""
    if stripped in _FAMILIES:
        return stripped
    if stripped in _ALIASES:
        return _ALIASES[stripped]

    # strip padding-ish suffixes, then retry (incl. embedded-size split)
    candidate = stripped
    for suffix in _STRIP_SUFFIXES:
        if candidate.endswith(suffix):
            candidate = candidate[: -len(suffix)]
            break
    if candidate != stripped:
        direct = _resolve_family(candidate)
        if direct:
            return direct

    # embedded size: AES256 -> AES, RSA2048 -> RSA, SHA3256 -> SHA3-256
    m = _EMBEDDED_SIZE.search(stripped)
    if m:
        head = stripped[: m.start()]
        tail = stripped[m.end():]
        for option in (head, head + tail, tail):
            if option in _FAMILIES:
                return option
            if option in _ALIASES:
                return _ALIASES[option]

    # mode token: AESECB -> AES, AES256GCM -> AES (mode recorded separately)
    for token in _MODE_TOKENS:
        if token in stripped:
            reduced = stripped.replace(token, "", 1)
            if reduced:
                direct = _resolve_family(reduced)
                if direct:
                    return direct
    return None


def _info(raw: str, family_key: str) -> AlgorithmInfo:
    base = parse_algorithm(family_key) if family_key in _FAMILIES else None
    if base is None:
        return AlgorithmInfo(raw=raw, canonical=family_key, family="unknown", status=UNKNOWN, recognized=False)
    return AlgorithmInfo(
        raw=raw, canonical=base.canonical, family=base.family, status=base.status,
        key_size=base.key_size, parameter_kind=base.parameter_kind, mode=base.mode,
        allowed_key_sizes=base.allowed_key_sizes, min_key_size=base.min_key_size,
        quantum_impact=base.quantum_impact, notes=base.notes,
    )


def catalog() -> list[dict[str, Any]]:
    """The full algorithm catalog (for the /algorithms API)."""
    entries: dict[str, dict[str, Any]] = {}
    for key, family in _FAMILIES.items():
        if family.canonical in entries:
            continue
        entries[family.canonical] = AlgorithmInfo(
            raw=family.canonical, canonical=family.canonical, family=family.family,
            status=family.status, key_size=family.key_size, parameter_kind=family.parameter_kind,
            allowed_key_sizes=family.allowed_key_sizes, min_key_size=family.min_key_size,
            quantum_impact=family.quantum_impact, notes=family.notes,
        ).to_dict()
    return sorted(entries.values(), key=lambda e: (e["family"], e["algorithm"]))


def infer_key_size(algorithm: str | None) -> int | None:
    """Best-effort key size for an algorithm string (None when unknown)."""
    if not algorithm:
        return None
    info = parse_algorithm(str(algorithm))
    if not info.recognized:
        return info.key_size  # embedded size even if family unknown
    if info.family in {"hash", "xof"}:
        return info.key_size  # digest size
    return info.key_size
