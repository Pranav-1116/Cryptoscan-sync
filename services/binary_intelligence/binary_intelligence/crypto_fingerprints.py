"""Version-controlled cryptographic fingerprint catalogue (§2, §4, §10).

This database is ZELNX-owned IP: function indicators, library
fingerprints and algorithm normalizations. Detection through these
tables never concludes more than the evidence supports — a function
reference is an indicator, not proof of runtime use (§5).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

#: the signature database version recorded on every finding (§7)
FINGERPRINT_DB_VERSION = "cryptoscan-crypto-fingerprints/1.0.0"


@dataclass(frozen=True)
class FunctionIndicator:
    symbol: str
    library: str
    algorithm_family: str
    algorithm_variant: str          # "" = variant not established
    operation: str
    mode_or_padding: str            # "" = not established
    key_size_bits: Optional[int]    # None = unknown, never guessed
    quantum_vulnerable: bool
    pqc_family: bool


#: §4 Stage 4 table + the §5 algorithm-detail discipline. A field that
#: the indicator cannot establish stays "" / None — key_size_bits is
#: None unless the indicator itself names the size.
FUNCTION_INDICATORS: Tuple[FunctionIndicator, ...] = (
    # OpenSSL ecosystem
    FunctionIndicator("EVP_aes_128_gcm", "OpenSSL", "AES", "AES-128-GCM",
                      "encryption", "GCM", 128, False, False),
    FunctionIndicator("EVP_aes_256_gcm", "OpenSSL", "AES", "AES-256-GCM",
                      "encryption", "GCM", 256, False, False),
    FunctionIndicator("EVP_aes_256_cbc", "OpenSSL", "AES", "AES-256-CBC",
                      "encryption", "CBC", 256, False, False),
    FunctionIndicator("EVP_aes_128_ccm", "OpenSSL", "AES", "AES-128-CCM",
                      "encryption", "CCM", 128, False, False),
    FunctionIndicator("EVP_chacha20_poly1305", "OpenSSL", "ChaCha20",
                      "ChaCha20-Poly1305", "encryption", "Poly1305",
                      None, False, False),
    FunctionIndicator("RSA_generate_key_ex", "OpenSSL", "RSA", "",
                      "key_generation", "", None, True, False),
    FunctionIndicator("RSA_new", "OpenSSL", "RSA", "", "key_management",
                      "", None, True, False),
    FunctionIndicator("EVP_PKEY_sign", "OpenSSL", "RSA", "",
                      "digital_signature", "", None, True, False),
    FunctionIndicator("EVP_PKEY_verify", "OpenSSL", "RSA", "",
                      "signature_verification", "", None, True, False),
    FunctionIndicator("EVP_sha1", "OpenSSL", "SHA-1", "SHA-1", "hashing",
                      "", None, False, False),
    FunctionIndicator("EVP_sha256", "OpenSSL", "SHA-2", "SHA-256",
                      "hashing", "", None, False, False),
    FunctionIndicator("EVP_sha384", "OpenSSL", "SHA-2", "SHA-384",
                      "hashing", "", None, False, False),
    FunctionIndicator("EVP_sha512", "OpenSSL", "SHA-2", "SHA-512",
                      "hashing", "", None, False, False),
    FunctionIndicator("EVP_MD_CTX_new", "OpenSSL", "HASH", "", "hashing",
                      "", None, False, False),
    FunctionIndicator("HMAC", "OpenSSL", "HMAC", "", "mac", "",
                      None, False, False),
    FunctionIndicator("PKCS5_PBKDF2_HMAC", "OpenSSL", "PBKDF2", "",
                      "key_derivation", "", None, False, False),
    FunctionIndicator("HKDF_extract", "OpenSSL", "HKDF", "",
                      "key_derivation", "", None, False, False),
    FunctionIndicator("EVP_PKEY_CTX_new_id", "OpenSSL", "KEY_EXCHANGE",
                      "", "key_exchange", "", None, True, False),
    FunctionIndicator("EVP_PKEY_derive", "OpenSSL", "ECDH", "",
                      "key_exchange", "", None, True, False),
    FunctionIndicator("EVP_PKEY_keygen", "OpenSSL", "KEY_GENERATION", "",
                      "key_generation", "", None, True, False),
    FunctionIndicator("RAND_bytes", "OpenSSL", "CSPRNG", "",
                      "random_generation", "", None, False, False),
    FunctionIndicator("TLS_method", "OpenSSL", "TLS", "", "protocol", "",
                      None, True, False),
    FunctionIndicator("SSL_CTX_new", "OpenSSL", "TLS", "", "protocol", "",
                      None, True, False),
    # PQC (OpenSSL 3.x / OQS-style indicators)
    FunctionIndicator("OSSL_PROVIDER_load", "OpenSSL", "PROVIDER", "",
                      "provider_loading", "", None, False, False),
    FunctionIndicator("EVP_PKEY_ML_KEM", "OpenSSL", "ML-KEM", "",
                      "key_exchange", "", None, False, True),
    FunctionIndicator("EVP_PKEY_ML_DSA", "OpenSSL", "ML-DSA", "",
                      "digital_signature", "", None, False, True),
    FunctionIndicator("EVP_PKEY_SLH_DSA", "OpenSSL", "SLH-DSA", "",
                      "digital_signature", "", None, False, True),
    FunctionIndicator("ml_kem_keygen", "liboqs", "ML-KEM", "",
                      "key_generation", "", None, False, True),
    FunctionIndicator("ml_dsa_keygen", "liboqs", "ML-DSA", "",
                      "key_generation", "", None, False, True),
    # libsodium
    FunctionIndicator("crypto_sign_ed25519", "libsodium", "Ed25519", "",
                      "digital_signature", "", None, True, False),
    FunctionIndicator("crypto_sign_ed25519_verify_detached", "libsodium",
                      "Ed25519", "", "signature_verification", "",
                      None, True, False),
    FunctionIndicator("crypto_aead_aes256gcm_encrypt", "libsodium", "AES",
                      "AES-256-GCM", "encryption", "GCM", 256,
                      False, False),
    FunctionIndicator("crypto_scalarmult_curve25519", "libsodium", "X25519",
                      "", "key_exchange", "", None, True, False),
    FunctionIndicator("crypto_kdf_hkdf_sha256", "libsodium", "HKDF", "",
                      "key_derivation", "", None, False, False),
    FunctionIndicator("randombytes_buf", "libsodium", "CSPRNG", "",
                      "random_generation", "", None, False, False),
    # Windows CNG / CryptoAPI
    FunctionIndicator("BCryptGenerateKeyPair", "Windows CNG", "KEY_GENERATION",
                      "", "key_generation", "", None, True, False),
    FunctionIndicator("BCryptEncrypt", "Windows CNG", "ENCRYPTION", "",
                      "encryption", "", None, False, False),
    FunctionIndicator("BCryptDecrypt", "Windows CNG", "DECRYPTION", "",
                      "decryption", "", None, False, False),
    FunctionIndicator("BCryptSignHash", "Windows CNG", "SIGNATURE", "",
                      "digital_signature", "", None, True, False),
    FunctionIndicator("BCryptVerifySignature", "Windows CNG", "SIGNATURE",
                      "", "signature_verification", "", None, True, False),
    FunctionIndicator("BCryptOpenAlgorithmProvider", "Windows CNG",
                      "ALGORITHM_PROVIDER", "", "provider_selection", "",
                      None, False, False),
    FunctionIndicator("NCryptOpenStorageProvider", "Windows CNG", "KMS",
                      "", "key_management", "", None, False, False),
    # PKCS#11 / HSM
    FunctionIndicator("C_Initialize", "PKCS#11", "HSM", "", "hsm_session",
                      "", None, False, False),
    FunctionIndicator("C_SignInit", "PKCS#11", "HSM", "", "digital_signature",
                      "", None, False, False),
    FunctionIndicator("C_Sign", "PKCS#11", "HSM", "", "digital_signature",
                      "", None, False, False),
    FunctionIndicator("C_DecryptInit", "PKCS#11", "HSM", "", "decryption",
                      "", None, False, False),
    FunctionIndicator("C_GenerateKeyPair", "PKCS#11", "HSM", "",
                      "key_generation", "", None, False, False),
    FunctionIndicator("C_VerifyInit", "PKCS#11", "HSM", "",
                      "signature_verification", "", None, False, False),
    # mbedTLS / wolfSSL / Botan / GnuTLS / NSS
    FunctionIndicator("mbedtls_cipher_init", "mbedTLS", "CIPHER", "",
                      "encryption", "", None, False, False),
    FunctionIndicator("mbedtls_aes_setkey_enc", "mbedTLS", "AES", "",
                      "encryption", "", None, False, False),
    FunctionIndicator("mbedtls_ssl_handshake", "mbedTLS", "TLS", "",
                      "protocol", "", None, True, False),
    FunctionIndicator("mbedtls_pkcs12_pbe", "mbedTLS", "PBKDF", "",
                      "key_derivation", "", None, False, False),
    FunctionIndicator("wc_AesGcmEncrypt", "wolfSSL", "AES", "AES-GCM",
                      "encryption", "GCM", None, False, False),
    FunctionIndicator("wc_Sha256Hash", "wolfSSL", "SHA-2", "SHA-256",
                      "hashing", "", None, False, False),
    FunctionIndicator("wc_MakeRsaKey", "wolfSSL", "RSA", "",
                      "key_generation", "", None, True, False),
    FunctionIndicator("Botan_PBKDF2", "Botan", "PBKDF2", "",
                      "key_derivation", "", None, False, False),
    FunctionIndicator("gnutls_pubkey_encrypt", "GnuTLS", "RSA", "",
                      "encryption", "", None, True, False),
    FunctionIndicator("PK11_GenerateKeyPair", "NSS", "KEY_GENERATION", "",
                      "key_generation", "", None, True, False),
    # Java JCA / Bouncy Castle
    FunctionIndicator("javax.crypto.Cipher.getInstance", "Java JCA", "CIPHER",
                      "", "encryption", "", None, False, False),
    FunctionIndicator("javax.crypto.KeyGenerator.getInstance", "Java JCA",
                      "KEY_GENERATION", "", "key_generation", "",
                      None, False, False),
    FunctionIndicator("java.security.Signature.getInstance", "Java JCA",
                      "SIGNATURE", "", "digital_signature", "",
                      None, False, False),
    FunctionIndicator("javax.crypto.Mac.getInstance", "Java JCA", "MAC", "",
                      "mac", "", None, False, False),
    FunctionIndicator("org.bouncycastle.crypto.engines.AESEngine",
                      "Bouncy Castle", "AES", "", "encryption", "",
                      None, False, False),
    FunctionIndicator("org.bouncycastle.pqc.crypto.mldsa.MLDSASigner",
                      "Bouncy Castle", "ML-DSA", "", "digital_signature",
                      "", None, False, True),
    FunctionIndicator("org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor",
                      "Bouncy Castle", "ML-KEM", "", "key_exchange",
                      "", None, False, True),
    # Go / Rust
    FunctionIndicator("crypto/aes.NewCipher", "Go", "AES", "",
                      "encryption", "", None, False, False),
    FunctionIndicator("crypto/rsa.GenerateKey", "Go", "RSA", "",
                      "key_generation", "", None, True, False),
    FunctionIndicator("crypto/sha256.Sum256", "Go", "SHA-2", "SHA-256",
                      "hashing", "", None, False, False),
    FunctionIndicator("crypto/tls.Client", "Go", "TLS", "", "protocol", "",
                      None, True, False),
    FunctionIndicator("crypto/ecdh.X25519", "Go", "X25519", "",
                      "key_exchange", "", None, True, False),
    FunctionIndicator("ring::signature", "Rust ring", "SIGNATURE", "",
                      "digital_signature", "", None, True, False),
    FunctionIndicator("aes_gcm::Aes256Gcm", "RustCrypto", "AES",
                      "AES-256-GCM", "encryption", "GCM", 256,
                      False, False),
)

BY_SYMBOL: Dict[str, FunctionIndicator] = {
    indicator.symbol: indicator for indicator in FUNCTION_INDICATORS
}


@dataclass(frozen=True)
class LibraryFingerprint:
    library: str
    indicator: str
    kind: str            # "version_string" | "symbol_prefix" | "dependency"
    note: str = ""


#: library identification through several techniques (§2: "multiple
#: detection techniques rather than relying on exported library names")
LIBRARY_FINGERPRINTS: Tuple[LibraryFingerprint, ...] = (
    LibraryFingerprint("OpenSSL", "OpenSSL ", "version_string",
                       "e.g. 'OpenSSL 3.0.11' — version stated by the library"),
    LibraryFingerprint("BoringSSL", "BoringSSL", "version_string"),
    LibraryFingerprint("LibreSSL", "LibreSSL", "version_string"),
    LibraryFingerprint("mbedTLS", "mbedTLS", "version_string"),
    LibraryFingerprint("wolfSSL", "wolfSSL", "version_string"),
    LibraryFingerprint("libsodium", "libsodium", "version_string"),
    LibraryFingerprint("Bouncy Castle", "Bouncy-Castle", "version_string"),
    LibraryFingerprint("PKCS#11", "PKCS#11", "symbol_prefix"),
    LibraryFingerprint("Windows CNG", "bcrypt.dll", "dependency"),
    LibraryFingerprint("Windows CryptoAPI", "advapi32.dll", "dependency"),
    LibraryFingerprint("CommonCrypto", "libcommonCrypto", "dependency"),
    LibraryFingerprint("Go runtime", "go.buildid", "version_string"),
)

DEPENDENCY_LIBRARY_MAP: Dict[str, str] = {
    "libcrypto.so": "OpenSSL",
    "libssl.so": "OpenSSL",
    "libcrypto.so.1.1": "OpenSSL",
    "libcrypto.so.3": "OpenSSL",
    "libssl.so.1.1": "OpenSSL",
    "libssl.so.3": "OpenSSL",
    "libboringssl": "BoringSSL",
    "libmbedcrypto": "mbedTLS",
    "libmbedtls": "mbedTLS",
    "libwolfssl": "wolfSSL",
    "libsodium": "libsodium",
    "libpcsclite": "PKCS#11",
    "bcrypt.dll": "Windows CNG",
    "advapi32.dll": "Windows CryptoAPI",
    "ncrypt.dll": "Windows CNG",
    "crypt32.dll": "Windows CryptoAPI",
    "libgnutls": "GnuTLS",
    "libnss3": "NSS",
    "libbotan": "Botan",
}


def library_from_dependency(dep: str) -> Optional[str]:
    lowered = dep.lower()
    for needle, library in DEPENDENCY_LIBRARY_MAP.items():
        if lowered.startswith(needle.lower()):
            return library
    return None
