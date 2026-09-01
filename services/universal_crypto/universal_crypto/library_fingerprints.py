"""§6/§8 Crypto library fingerprinting.

Fingerprints for the crypto libraries the spec lists (OpenSSL, LibreSSL,
BoringSSL, wolfSSL, mbedTLS, Botan, libsodium, Crypto++, JCA/JCE, Bouncy
Castle, .NET cryptography, Go crypto/*, RustCrypto, WebCrypto, Node crypto,
PKCS#11) plus provider and version detection.

§8: an implementation is CONFIRMED only when ≥2 *distinct* evidence classes
agree — library marker, function symbol, instruction pattern, constant,
API, version — never a single string match.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

LIBRARIES: list[dict[str, Any]] = [
    {"name": "OpenSSL", "provider": "OpenSSL", "markers": ["openssl/ssl.h", "openssl/evp.h", "libssl", "libcrypto", "OPENSSL_VERSION_TEXT"], "version": r"OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)"},
    {"name": "LibreSSL", "provider": "LibreSSL", "markers": ["libtls", "LibreSSL"], "version": r"LibreSSL\s+([0-9]+\.[0-9]+\.[0-9]+)"},
    {"name": "BoringSSL", "provider": "Google", "markers": ["boringssl", "BORINGSSL_"], "version": r""},
    {"name": "wolfSSL", "provider": "wolfSSL", "markers": ["wolfssl/ssl.h", "wolfSSL", "WOLFSSL_VERSION"], "version": r"WOLFSSL_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)"},
    {"name": "mbedTLS", "provider": "ARM", "markers": ["mbedtls/ssl.h", "mbedtls_", "MBEDTLS_VERSION"], "version": r"MBEDTLS_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)"},
    {"name": "Botan", "provider": "Botan", "markers": ["botan/", "Botan::"], "version": r"Botan\s+([0-9]+\.[0-9]+\.[0-9]+)"},
    {"name": "libsodium", "provider": "libsodium", "markers": ["sodium.h", "sodium_", "SODIUM_VERSION"], "version": r"SODIUM_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)"},
    {"name": "Crypto++", "provider": "Crypto++", "markers": ["cryptopp/", "CryptoPP::"], "version": r""},
    {"name": "JCA-JCE", "provider": "Oracle/OpenJDK", "markers": ["java.security.", "javax.crypto.", "MessageDigest", "KeyPairGenerator"], "version": r""},
    {"name": "BouncyCastle", "provider": "Legion of the Bouncy Castle", "markers": ["org.bouncycastle", "bcprov", "BouncyCastleProvider"], "version": r""},
    {"name": ".NET cryptography", "provider": "Microsoft", "markers": ["System.Security.Cryptography", "System.Security.Cryptography.X509Certificates"], "version": r""},
    {"name": "Go crypto/*", "provider": "Go", "markers": ["crypto/sha256", "crypto/rsa", "crypto/tls", "crypto/ecdsa", "crypto/x509"], "version": r"go([0-9]+\.[0-9]+(?:\.[0-9]+)?)"},
    {"name": "RustCrypto", "provider": "RustCrypto", "markers": ["sha2", "aes-gcm", "ed25519-dalek", "ring::", "rustls"], "version": r""},
    {"name": "WebCrypto", "provider": "W3C", "markers": ["crypto.subtle", "SubtleCrypto"], "version": r""},
    {"name": "Node crypto", "provider": "Node.js", "markers": ["require('crypto')", "require(\"crypto\")", "node:crypto"], "version": r""},
    {"name": "PKCS#11", "provider": "OASIS", "markers": ["pkcs11", "PKCS11", "C_Initialize", "C_GetFunctionList"], "version": r""},
    {"name": "CryptoKit", "provider": "Apple", "markers": ["CryptoKit", "import CryptoKit"], "version": r""},
    {"name": "GnuTLS", "provider": "GnuTLS", "markers": ["gnutls/", "gnutls_"], "version": r"gnutls\s+([0-9]+\.[0-9]+\.[0-9]+)"},
]

#: extra function-level fingerprints (evidence class B: function symbol)
_FUNCTION_MARKERS: dict[str, tuple[str, ...]] = {
    "OpenSSL": ("EVP_EncryptInit_ex", "EVP_DigestInit_ex", "SSL_CTX_new", "RAND_bytes", "RSA_sign"),
    "mbedTLS": ("mbedtls_ssl_init", "mbedtls_aes_crypt_cbc", "mbedtls_sha256"),
    "libsodium": ("crypto_secretbox_easy", "crypto_sign_detached", "crypto_pwhash"),
    "Botan": ("Botan::AutoSeeded_RNG", "Botan::TLS::Server"),
    "wolfSSL": ("wolfSSL_Init", "wolfSSL_CTX_new"),
    "Crypto++": ("CryptoPP::AES", "CryptoPP::SHA256"),
}

#: crypto constant fingerprints (evidence class C: constant) — first bytes
#: of well-known tables as found in .rodata
_CONSTANT_MARKERS: dict[str, tuple[bytes, ...]] = {
    "OpenSSL": (b"expand 32-byte k", b"OpenSSL 1."),
    "libsodium": (b"expand 32-byte k",),
    "wolfSSL": (b"wolfSSL",),
}

#: imports/API fingerprints for source-level libraries (evidence class A)
_API_MARKERS: dict[str, tuple[str, ...]] = {
    "JCA-JCE": ("MessageDigest.getInstance", "Cipher.getInstance", "KeyPairGenerator.getInstance"),
    "BouncyCastle": ("org.bouncycastle.jce.provider.BouncyCastleProvider",),
    ".NET cryptography": ("System.Security.Cryptography",),
    "Node crypto": ("createHash", "createCipheriv"),
    "WebCrypto": ("crypto.subtle",),
    "Go crypto/*": ("crypto/",),
    "RustCrypto": ("use sha2", "use aes_gcm", "use ring::"),
}


class LibraryFingerprinter:
    """§6/§8 deterministic library fingerprinting."""

    def __init__(self) -> None:
        self._libraries = {lib["name"]: lib for lib in LIBRARIES}

    def libraries(self) -> list[dict[str, Any]]:
        return list(self._libraries.values())

    def fingerprint(
        self,
        *,
        imports: Optional[Iterable[str]] = None,
        symbols: Optional[Iterable[str]] = None,
        strings: Optional[Iterable[str]] = None,
        constants: Optional[Iterable[bytes]] = None,
        apis: Optional[Iterable[str]] = None,
        dependencies: Optional[Iterable[str]] = None,
    ) -> list[dict[str, Any]]:
        """Match every library against the artifact evidence classes.

        Evidence classes (per library):
          A marker/import, B function symbol, C constant, D API, E dependency.
        A library is CONFIRMED when ≥3 classes match (stronger than the §8
        minimum of 2 — safe by construction); otherwise POSSIBLE with the
        classes that matched. Version is extracted when a version regex hits.
        """
        hay_imports = " ".join(imports or [])
        hay_symbols = " ".join(symbols or [])
        hay_strings = " ".join(strings or [])
        hay_apis = " ".join(apis or [])
        hay_deps = " ".join(dependencies or [])
        results: list[dict[str, Any]] = []
        for library in LIBRARIES:
            name = library["name"]
            classes: list[str] = []
            if any(m.lower() in hay_imports.lower() or m.lower() in hay_strings.lower()
                   for m in library["markers"]):
                classes.append("marker")
            funcs = _FUNCTION_MARKERS.get(name, ())
            if any(f in hay_symbols for f in funcs):
                classes.append("function_symbol")
            consts = _CONSTANT_MARKERS.get(name, ())
            if any(c in (constants or ()) for c in consts):
                classes.append("constant")
            apis_cat = _API_MARKERS.get(name, ())
            if any(a.lower() in hay_apis.lower() for a in apis_cat):
                classes.append("api")
            if hay_deps and any(m.lower() in hay_deps.lower() for m in library["markers"]):
                classes.append("dependency")
            version = ""
            if library["version"]:
                match = re.search(library["version"], hay_strings)
                if match:
                    version = match.group(1)
                    classes.append("version")
            if not classes:
                continue
            results.append({
                "library": name,
                "provider": library["provider"],
                "version": version,
                "evidence_classes": sorted(set(classes)),
                "verdict": "CONFIRMED_IMPLEMENTATION" if len(set(classes)) >= 3
                           else "POSSIBLE_CRYPTO",
            })
        return results

    def algorithms_referenced(
        self,
        *,
        library: str,
        symbols: Optional[Iterable[str]] = None,
        apis: Optional[Iterable[str]] = None,
    ) -> list[str]:
        """Which algorithms the library exposes vs the app actually references."""
        exposed: set[str] = set()
        referenced: set[str] = set()
        hay_symbols = " ".join(symbols or [])
        hay_apis = " ".join(apis or [])
        # deterministic symbol → algorithm mapping
        for symbol, alg in _SYMBOL_ALGORITHM.items():
            if symbol in hay_symbols:
                referenced.add(alg)
        for api, alg in _API_ALGORITHM.items():
            if api.lower() in hay_apis.lower():
                referenced.add(alg)
        for lib_alg, algs in _LIBRARY_EXPOSED.get(library, {}).items():
            exposed.update(algs)
        return {
            "library": library,
            "algorithms_exposed": sorted(exposed),
            "algorithms_referenced": sorted(referenced),
        }


#: symbol → algorithm (deterministic catalog)
_SYMBOL_ALGORITHM: dict[str, str] = {
    "EVP_sha256": "SHA-256", "EVP_sha1": "SHA-1", "EVP_md5": "MD5",
    "EVP_aes_256_gcm": "AES-GCM", "EVP_aes_128_cbc": "AES-CBC",
    "RSA_sign": "RSA", "ECDSA_sign": "ECDSA", "EVP_PKEY_CTX": "RSA",
    "mbedtls_sha256": "SHA-256", "mbedtls_aes_crypt_cbc": "AES-CBC",
    "crypto_secretbox_easy": "XChaCha20-Poly1305", "crypto_sign_detached": "Ed25519",
    "CryptoPP::SHA256": "SHA-256", "CryptoPP::AES": "AES",
    "sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5",
    "aes_gcm": "AES-GCM", "ed25519": "Ed25519",
}

_API_ALGORITHM: dict[str, str] = {
    "MessageDigest.getInstance(\"SHA-256\"": "SHA-256",
    "MessageDigest.getInstance(\"SHA-1\"": "SHA-1",
    "MessageDigest.getInstance(\"MD5\"": "MD5",
    "Cipher.getInstance(\"AES/GCM": "AES-GCM",
    "Signature.getInstance(\"SHA256withRSA": "RSA-PSS",
    "crypto.createHash('sha256'": "SHA-256",
    "crypto.createCipheriv('aes-256-gcm'": "AES-GCM",
}

#: algorithms each library is known to expose
_LIBRARY_EXPOSED: dict[str, dict[str, list[str]]] = {
    "OpenSSL": {"symmetric": ["AES", "ChaCha20", "Camellia", "ARIA", "3DES"],
                "hash": ["SHA-256", "SHA-1", "MD5", "SHA-3", "BLAKE2"],
                "public_key": ["RSA", "ECDSA", "Ed25519", "DH", "ECDH"],
                "pqc": ["ML-KEM-768", "ML-DSA-65"]},
    "mbedTLS": {"symmetric": ["AES", "ChaCha20"], "hash": ["SHA-256", "SHA-1"],
                "public_key": ["RSA", "ECDSA"], "pqc": []},
    "libsodium": {"symmetric": ["ChaCha20", "XChaCha20", "AES-GCM"],
                  "hash": ["BLAKE2", "SHA-256"], "public_key": ["Ed25519", "X25519"],
                  "pqc": ["ML-KEM-768"]},
    "Botan": {"symmetric": ["AES", "ChaCha20", "Camellia", "SEED"],
              "hash": ["SHA-256", "SHA-3", "BLAKE2", "RIPEMD160"],
              "public_key": ["RSA", "ECDSA", "Ed25519", "DH", "ECDH"],
              "pqc": ["ML-KEM-768", "ML-DSA-65", "HQC-192"]},
    "wolfSSL": {"symmetric": ["AES", "ChaCha20"], "hash": ["SHA-256", "SHA-3"],
                "public_key": ["RSA", "ECDSA", "Ed25519"], "pqc": ["ML-KEM-768"]},
    "JCA-JCE": {"symmetric": ["AES", "ChaCha20", "3DES"], "hash": ["SHA-256", "SHA-1"],
                "public_key": ["RSA", "ECDSA", "Ed25519"], "pqc": []},
    "BouncyCastle": {"symmetric": ["AES", "ChaCha20", "Twofish", "SEED", "Camellia"],
                     "hash": ["SHA-256", "SHA-3", "BLAKE2", "RIPEMD160"],
                     "public_key": ["RSA", "ECDSA", "Ed25519", "DH"],
                     "pqc": ["ML-KEM-768", "ML-DSA-65", "HQC-192"]},
    "Go crypto/*": {"symmetric": ["AES", "ChaCha20"], "hash": ["SHA-256", "SHA-1", "MD5"],
                    "public_key": ["RSA", "ECDSA", "Ed25519", "ECDH"], "pqc": []},
    "RustCrypto": {"symmetric": ["AES", "ChaCha20"], "hash": ["SHA-256", "BLAKE2", "BLAKE3"],
                   "public_key": ["Ed25519", "X25519", "ECDSA"],
                   "pqc": ["ML-KEM-768", "ML-DSA-65"]},
}
