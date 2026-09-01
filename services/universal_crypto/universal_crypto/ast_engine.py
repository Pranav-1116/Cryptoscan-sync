"""§4/§5 Crypto AST engine — semantic detection, never name-grep.

Language plugins for Python, Java, JavaScript, TypeScript, C, C++, C#, Go,
Rust, Swift, Kotlin, PHP, Ruby, Scala, Haskell, Solidity, Vyper and Dart.
Each plugin maps *known* API patterns to (primitive, operation, library):

    hashlib.sha256(...)        -> SHA-256 / hash / hashlib
    MessageDigest SHA-256      -> SHA-256 / hash / JCA-JCE
    AES.GCM.seal(...)          -> AES-GCM / encrypt / CryptoKit

Precision rule (§5): custom code such as ``custom_hash(data)`` is NEVER
classified merely because nearby code contains "sha". Only catalogued API
patterns produce observations; everything else is ignored (and can be picked
up by the unknown-crypto detector, §31).

The existing Java AST scanner of the product becomes one plugin here
(``_JAVA`` patterns are the same catalog the product scanner uses).
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from universal_crypto.models import Operation

# pattern catalog: (language, library, regex, algorithm, operation)
# regex is matched case-insensitively against the source line.
_PATTERNS: list[tuple[str, str, str, str, Operation]] = [
    # ── Python ──────────────────────────────────────────────────────────
    ("python", "hashlib", r"hashlib\.sha256\b", "SHA-256", Operation.HASH),
    ("python", "hashlib", r"hashlib\.sha1\s*\(", "SHA-1", Operation.HASH),
    ("python", "hashlib", r"hashlib\.md5\s*\(", "MD5", Operation.HASH),
    ("python", "hashlib", r"hashlib\.sha3_?(224|256|384|512)\s*\(", "SHA-3", Operation.HASH),
    ("python", "hashlib", r"hashlib\.blake2[bs]\s*\(", "BLAKE2", Operation.HASH),
    ("python", "hashlib", r"hashlib\.pbkdf2_hmac\s*\(", "PBKDF2", Operation.KDF),
    ("python", "hashlib", r"hashlib\.scrypt\s*\(", "scrypt", Operation.KDF),
    ("python", "cryptography", r"cryptography\.hazmat.*AESGCM\s*\(", "AES-GCM", Operation.ENCRYPT),
    ("python", "cryptography", r"cryptography\.hazmat.*(?:RSAPrivateKey|RSAPublicKey)", "RSA", Operation.SIGN),
    ("python", "cryptography", r"cryptography\.hazmat.*rsa\.generate_private_key\s*\(", "RSA", Operation.KEYGEN),
    ("python", "cryptography", r"cryptography\.hazmat.*(?:ec\.generate_private_key|EllipticCurve)", "ECDSA", Operation.KEYGEN),
    ("python", "cryptography", r"cryptography\.hazmat.*Ed25519", "Ed25519", Operation.SIGN),
    ("python", "cryptography", r"cryptography\.hazmat.*HKDF\s*\(", "HKDF", Operation.KDF),
    ("python", "cryptography", r"cryptography\.hazmat.*PBKDF2HMAC\s*\(", "PBKDF2", Operation.KDF),
    ("python", "cryptography", r"cryptography\.hazmat.*(?:TLS|SSLContext|tls\.)", "TLS", Operation.TLS_CONFIG),
    ("python", "cryptography", r"cryptography\.x509.*CertificateBuilder", "RSA", Operation.CERTIFICATE_HANDLING),
    ("python", "", r"os\.urandom\s*\(", "CSPRNG", Operation.RANDOM),
    ("python", "", r"secrets\.(?:token_bytes|token_hex)\s*\(", "CSPRNG", Operation.RANDOM),
    ("python", "hmac", r"hmac\.new\s*\(", "HMAC", Operation.HMAC),
    ("python", "hashlib", r"hashlib\.new\s*\(\s*['\"]sha256", "SHA-256", Operation.HASH),
    # ── Java / Kotlin / Scala (JCA/JCE + Bouncy Castle) ─────────────────
    ("java", "JCA-JCE", r"MessageDigest\.getInstance\(\s*\"SHA-?256", "SHA-256", Operation.HASH),
    ("java", "JCA-JCE", r"MessageDigest\.getInstance\(\s*\"SHA-?1", "SHA-1", Operation.HASH),
    ("java", "JCA-JCE", r"MessageDigest\.getInstance\(\s*\"MD5", "MD5", Operation.HASH),
    ("java", "JCA-JCE", r"Cipher\.getInstance\(\s*\"AES/GCM", "AES-GCM", Operation.ENCRYPT),
    ("java", "JCA-JCE", r"Cipher\.getInstance\(\s*\"AES/CBC", "AES-CBC", Operation.ENCRYPT),
    ("java", "JCA-JCE", r"Cipher\.getInstance\(\s*\"RSA/ECB/OAEP", "RSA-OAEP", Operation.ENCRYPT),
    ("java", "JCA-JCE", r"Signature\.getInstance\(\s*\"SHA(256|384|512)withRSA", "RSA-PSS", Operation.SIGN),
    ("java", "JCA-JCE", r"Signature\.getInstance\(\s*\"SHA(256|384|512)withECDSA", "ECDSA", Operation.SIGN),
    ("java", "JCA-JCE", r"KeyPairGenerator\.getInstance\(\s*\"RSA", "RSA", Operation.KEYGEN),
    ("java", "JCA-JCE", r"KeyPairGenerator\.getInstance\(\s*\"EC", "ECDSA", Operation.KEYGEN),
    ("java", "JCA-JCE", r"KeyAgreement\.getInstance\(\s*\"ECDH", "ECDH", Operation.KEYEXCHANGE),
    ("java", "JCA-JCE", r"new\s+SecureRandom\s*\(", "CSPRNG", Operation.RANDOM),
    ("java", "JCA-JCE", r"CertificateFactory\.getInstance\s*\(", "RSA", Operation.CERTIFICATE_HANDLING),
    ("java", "JCA-JCE", r"SSLContext\.getInstance\s*\(", "TLS", Operation.TLS_CONFIG),
    ("java", "BouncyCastle", r"org\.bouncycastle\.", "BouncyCastle", Operation.UNKNOWN),
    # ── JavaScript / TypeScript (Node crypto + WebCrypto) ───────────────
    ("javascript", "Node crypto", r"crypto\.createHash\(\s*['\"]sha256['\"]", "SHA-256", Operation.HASH),
    ("javascript", "Node crypto", r"crypto\.createHash\(\s*['\"]sha1['\"]", "SHA-1", Operation.HASH),
    ("javascript", "Node crypto", r"crypto\.createHash\(\s*['\"]md5['\"]", "MD5", Operation.HASH),
    ("javascript", "Node crypto", r"crypto\.createCipheriv\(\s*['\"]aes-256-gcm['\"]", "AES-GCM", Operation.ENCRYPT),
    ("javascript", "Node crypto", r"crypto\.createCipheriv\(\s*['\"]aes-128-cbc['\"]", "AES-CBC", Operation.ENCRYPT),
    ("javascript", "Node crypto", r"crypto\.sign\(\s*['\"]sha256['\"]", "RSA-PSS", Operation.SIGN),
    ("javascript", "Node crypto", r"crypto\.generateKeyPair(?:Sync)?\(\s*['\"]rsa['\"]", "RSA", Operation.KEYGEN),
    ("javascript", "Node crypto", r"crypto\.randomBytes\s*\(", "CSPRNG", Operation.RANDOM),
    ("javascript", "webcrypto", r"crypto\.subtle\.(?:encrypt|decrypt|sign|digest|deriveKey)", "WebCrypto", Operation.UNKNOWN),
    # destructured imports: `import { createHash } from 'node:crypto'` +
    # bare call — the import binds the Node API, so the pair is evidence
    ("javascript", "Node crypto", r"import\s*\{[^}]*createHash[^}]*\}\s*from\s*['\"](?:node:)?crypto['\"][\s\S]*?createHash\s*\(\s*['\"]sha256['\"]", "SHA-256", Operation.HASH),
    ("javascript", "Node crypto", r"import\s*\{[^}]*createCipheriv[^}]*\}\s*from\s*['\"](?:node:)?crypto['\"][\s\S]*?createCipheriv\s*\(\s*['\"]aes-256-gcm['\"]", "AES-GCM", Operation.ENCRYPT),
    # ── C / C++ (OpenSSL / mbedTLS) ─────────────────────────────────────
    ("c", "OpenSSL", r"EVP_sha256\s*\(", "SHA-256", Operation.HASH),
    ("c", "OpenSSL", r"EVP_sha1\s*\(", "SHA-1", Operation.HASH),
    ("c", "OpenSSL", r"EVP_md5\s*\(", "MD5", Operation.HASH),
    ("c", "OpenSSL", r"EVP_aes_256_gcm\s*\(", "AES-GCM", Operation.ENCRYPT),
    ("c", "OpenSSL", r"EVP_aes_128_cbc\s*\(", "AES-CBC", Operation.ENCRYPT),
    ("c", "OpenSSL", r"RSA_sign\s*\(", "RSA-PSS", Operation.SIGN),
    ("c", "OpenSSL", r"RSA_verify\s*\(", "RSA", Operation.VERIFY),
    ("c", "OpenSSL", r"EVP_PKEY_keygen\s*\(", "RSA", Operation.KEYGEN),
    ("c", "OpenSSL", r"SSL_CTX_new\s*\(", "TLS", Operation.TLS_CONFIG),
    ("c", "OpenSSL", r"RAND_bytes\s*\(", "CSPRNG", Operation.RANDOM),
    ("c", "OpenSSL", r"X509_new\s*\(", "RSA", Operation.CERTIFICATE_HANDLING),
    ("c", "mbedTLS", r"mbedtls_(?:sha256|sha1|md5|aes|cipher|ssl|rsa|ecdsa)", "mbedTLS", Operation.UNKNOWN),
    # ── C# (.NET) ───────────────────────────────────────────────────────
    ("csharp", ".NET cryptography", r"SHA256\.Create\s*\(", "SHA-256", Operation.HASH),
    ("csharp", ".NET cryptography", r"SHA1\.Create\s*\(", "SHA-1", Operation.HASH),
    ("csharp", ".NET cryptography", r"MD5\.Create\s*\(", "MD5", Operation.HASH),
    ("csharp", ".NET cryptography", r"Aes\.Create\s*\(", "AES", Operation.ENCRYPT),
    ("csharp", ".NET cryptography", r"RSA\.Create\s*\(", "RSA", Operation.SIGN),
    ("csharp", ".NET cryptography", r"ECDsa\.Create\s*\(", "ECDSA", Operation.SIGN),
    ("csharp", ".NET cryptography", r"RandomNumberGenerator\.(?:Create|Fill)\s*\(", "CSPRNG", Operation.RANDOM),
    ("csharp", ".NET cryptography", r"X509Certificate2\s*\(", "RSA", Operation.CERTIFICATE_HANDLING),
    ("csharp", ".NET cryptography", r"SslStream\s*\(", "TLS", Operation.TLS_CONFIG),
    # ── Go ──────────────────────────────────────────────────────────────
    ("go", "Go crypto/*", r"crypto/sha256.*\.Sum256\s*\(", "SHA-256", Operation.HASH),
    ("go", "Go crypto/*", r"crypto/sha1.*\.Sum\s*\(", "SHA-1", Operation.HASH),
    ("go", "Go crypto/*", r"crypto/md5.*\.Sum\s*\(", "MD5", Operation.HASH),
    ("go", "Go crypto/*", r"crypto/rsa.*SignPSS\s*\(", "RSA-PSS", Operation.SIGN),
    ("go", "Go crypto/*", r"crypto/rsa.*GenerateKey\s*\(", "RSA", Operation.KEYGEN),
    ("go", "Go crypto/*", r"crypto/ecdsa.*\.Sign\s*\(", "ECDSA", Operation.SIGN),
    ("go", "Go crypto/*", r"crypto/ecdh.*\.(?:ECDH|New)", "ECDH", Operation.KEYEXCHANGE),
    ("go", "Go crypto/*", r"crypto/aes.*NewCipher\s*\(", "AES", Operation.ENCRYPT),
    ("go", "Go crypto/*", r"crypto/hmac.*New\s*\(", "HMAC", Operation.HMAC),
    ("go", "Go crypto/*", r"crypto/rand.*\.Read\s*\(", "CSPRNG", Operation.RANDOM),
    ("go", "Go crypto/*", r"crypto/rand.*Reader\b", "CSPRNG", Operation.RANDOM),
    ("go", "Go crypto/*", r"crypto/tls.*(?:Server|Client|Config)", "TLS", Operation.TLS_CONFIG),
    ("go", "Go crypto/*", r"crypto/x509.*CreateCertificate\s*\(", "RSA", Operation.CERTIFICATE_HANDLING),
    # ── Rust ─────────────────────────────────────────────────────────────
    ("rust", "RustCrypto", r"sha2.*Sha256\s*::", "SHA-256", Operation.HASH),
    ("rust", "RustCrypto", r"sha1.*Sha1\s*::", "SHA-1", Operation.HASH),
    ("rust", "RustCrypto", r"ring::signature::(?:Ecdsa|Ed25519|Rsa)", "RSA", Operation.SIGN),
    ("rust", "RustCrypto", r"ring::aead::AES_256_GCM", "AES-GCM", Operation.ENCRYPT),
    ("rust", "RustCrypto", r"aes[-_]gcm::Aes256Gcm", "AES-GCM", Operation.ENCRYPT),
    ("rust", "RustCrypto", r"ed25519[-_]dalek::SigningKey", "Ed25519", Operation.SIGN),
    ("rust", "RustCrypto", r"(?:rand_core|getrandom)::OsRng", "CSPRNG", Operation.RANDOM),
    ("rust", "RustCrypto", r"rustls::(?:ServerConfig|ClientConfig)", "TLS", Operation.TLS_CONFIG),
    # ── Swift (CryptoKit) ────────────────────────────────────────────────
    ("swift", "CryptoKit", r"SHA256\.hash\s*\(", "SHA-256", Operation.HASH),
    ("swift", "CryptoKit", r"AES\.GCM\.(?:seal|open)\s*\(", "AES-GCM", Operation.ENCRYPT),
    ("swift", "CryptoKit", r"Curve25519\.", "X25519", Operation.KEYEXCHANGE),
    ("swift", "CryptoKit", r"SecureEnclave\.", "SecureEnclave", Operation.KEYGEN),
    # ── PHP ──────────────────────────────────────────────────────────────
    ("php", "PHP", r"hash\(\s*'sha256'", "SHA-256", Operation.HASH),
    ("php", "PHP", r"hash\(\s*'sha1'", "SHA-1", Operation.HASH),
    ("php", "PHP", r"hash\(\s*'md5'", "MD5", Operation.HASH),
    ("php", "PHP", r"openssl_encrypt\(\s*'aes-256-gcm'", "AES-GCM", Operation.ENCRYPT),
    ("php", "PHP", r"openssl_sign\s*\(", "RSA", Operation.SIGN),
    ("php", "PHP", r"openssl_pkey_new\s*\(", "RSA", Operation.KEYGEN),
    ("php", "PHP", r"random_bytes\s*\(", "CSPRNG", Operation.RANDOM),
    # ── Ruby ─────────────────────────────────────────────────────────────
    ("ruby", "digest", r"Digest::SHA256", "SHA-256", Operation.HASH),
    ("ruby", "digest", r"Digest::SHA1", "SHA-1", Operation.HASH),
    ("ruby", "digest", r"Digest::MD5", "MD5", Operation.HASH),
    ("ruby", "openssl", r"OpenSSL::PKey::RSA", "RSA", Operation.KEYGEN),
    ("ruby", "openssl", r"OpenSSL::Cipher\.new\('aes-256-gcm'", "AES-GCM", Operation.ENCRYPT),
    ("ruby", "openssl", r"OpenSSL::Random\.random_bytes", "CSPRNG", Operation.RANDOM),
    ("ruby", "openssl", r"OpenSSL::SSL::SSLContext", "TLS", Operation.TLS_CONFIG),
    # ── Haskell ──────────────────────────────────────────────────────────
    ("haskell", "cryptonite", r"cryptonite.*(?:SHA256|SHA1|MD5|AES|RSA|Ed25519)", "cryptonite", Operation.UNKNOWN),
    ("haskell", "cryptonite", r"Crypto\.Hash\.SHA256|H\.Digest H\.SHA256", "SHA-256", Operation.HASH),
    ("haskell", "cryptonite", r"Crypto\.Hash\.SHA512|H\.Digest H\.SHA512", "SHA-512", Operation.HASH),
    ("haskell", "cryptonite", r"Crypto\.Hash\.SHA1|H\.Digest H\.SHA1", "SHA-1", Operation.HASH),
    ("haskell", "cryptonite", r"Crypto\.Hash\.MD5|H\.Digest H\.MD5", "MD5", Operation.HASH),
    ("haskell", "cryptonite", r"Data\.ByteString\.Base64", "cryptonite", Operation.UNKNOWN),
    # ── Solidity / Vyper ─────────────────────────────────────────────────
    ("solidity", "", r"keccak256\s*\(", "Keccak-256", Operation.HASH),
    ("solidity", "", r"ecrecover\s*\(", "ECDSA", Operation.VERIFY),
    ("solidity", "", r"sha256\s*\(", "SHA-256", Operation.HASH),
    ("vyper", "", r"keccak256\s*\(", "Keccak-256", Operation.HASH),
    ("vyper", "", r"ecrecover\s*\(", "ECDSA", Operation.VERIFY),
    # ── Dart (package:crypto + pointycastle) ────────────────────────────
    ("dart", "crypto", r"sha256\.convert\s*\(", "SHA-256", Operation.HASH),
    ("dart", "crypto", r"sha512\.convert\s*\(", "SHA-512", Operation.HASH),
    ("dart", "crypto", r"sha1\.convert\s*\(", "SHA-1", Operation.HASH),
    ("dart", "crypto", r"md5\.convert\s*\(", "MD5", Operation.HASH),
    ("dart", "crypto", r"Hmac\s*\(\s*sha(?:256|512)", "HMAC", Operation.HMAC),
    ("dart", "crypto", r"Random\.secure\s*\(", "CSPRNG", Operation.RANDOM),
    ("dart", "pointycastle", r"GCMBlockCipher\s*\(", "AES-GCM", Operation.ENCRYPT),
    ("dart", "pointycastle", r"AESEngine\s*\(", "AES", Operation.ENCRYPT),
    ("dart", "pointycastle", r"OAEPEncoding\s*\(", "RSA-OAEP", Operation.ENCRYPT),
    ("dart", "pointycastle", r"RSA(?:Signer|Signature)\s*\(", "RSA", Operation.SIGN),
    ("dart", "pointycastle", r"Ed25519Signer\s*\(", "Ed25519", Operation.SIGN),
    ("dart", "pointycastle", r"ECDHBasicAgreement\s*\(", "ECDH", Operation.KEYEXCHANGE),
    ("dart", "pointycastle", r"PKCS1Encoding\s*\(", "RSA", Operation.ENCRYPT),
]

#: languages the engine knows (18 per §4)
LANGUAGES = [
    "python", "java", "javascript", "typescript", "c", "c++", "csharp",
    "go", "rust", "swift", "kotlin", "php", "ruby", "scala", "haskell",
    "solidity", "vyper", "dart",
]

#: composite-pattern enrichment: extract the full §3 shape from the matched
#: source — `Signature.getInstance("SHA256withRSA")` becomes RSA-PSS with
#: padding RSA-PSS and digest SHA-256, not just "RSA-PSS".
#: entries: (algorithm, library, regex, field, normalize(group))
_EXTRACTORS: list[tuple[str, str, str, str, Any]] = [
    ("RSA-PSS", "JCA-JCE", r"SHA(256|384|512)withRSA", "digest",
     lambda g: f"SHA-{g}"),
    ("ECDSA", "JCA-JCE", r"SHA(256|384|512)withECDSA", "digest",
     lambda g: f"SHA-{g}"),
    ("RSA-OAEP", "JCA-JCE", r"OAEPWith(SHA-?256|SHA-?384|SHA-?512)", "digest",
     lambda g: g if g.startswith("SHA-") else f"SHA-{g[3:]}"),
    ("PBKDF2", "hashlib", r"pbkdf2_hmac\s*\(\s*['\"](sha1|sha224|sha256|sha384|sha512)['\"]",
     "digest", lambda g: g.upper().replace("SHA", "SHA-")),
]

#: fixed padding for composite algorithms (when library evidence matches)
_PADDING_BY_ALGORITHM = {"RSA-PSS": "RSA-PSS", "RSA-OAEP": "RSA-OAEP"}


def _extract_components(algorithm: str, library: str, text: str) -> dict[str, str]:
    """Apply §3 enrichment: padding/digest/curve extracted deterministically."""
    out: dict[str, str] = {}
    if algorithm in _PADDING_BY_ALGORITHM and library == "JCA-JCE":
        out["padding"] = _PADDING_BY_ALGORITHM[algorithm]
    for alg, lib, regex, field, normalize in _EXTRACTORS:
        if alg != algorithm or lib != library:
            continue
        match = re.search(regex, text, re.IGNORECASE)
        if match:
            out[field] = normalize(match.group(1))
    return out


#: custom function names that look cryptographic but are NOT known APIs —
#: the §5 precision rule keeps them out of classification.
_CUSTOM_DEF_RE = re.compile(
    r"^\s*(?:def|func|function|public\s+\w+\s+|private\s+\w+\s+|static\s+\w+\s+)?"
    r"(?:custom_)?(?:hash|encrypt|decrypt|sign|mac|digest|kdf)\s*\(", re.IGNORECASE)

#: doc-comment/string lines are evidence-free (correlator §30 uses this)
_COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|--|<!--|'''|\"\"\")")


class CryptoAstEngine:
    """§4/§5 semantic crypto detection over source lines."""

    def __init__(self) -> None:
        self._by_language: dict[str, list[tuple[str, str, str, Operation]]] = {}
        for lang, library, pattern, algorithm, operation in _PATTERNS:
            # whitespace-tolerant literal dots: `hashlib . sha256 ( ... )`
            pattern = re.sub(r"\\\.", r"\\s*\\.\\s*", pattern)
            # whitespace-tolerant open paren: `createHash ( 'sha256' )` —
            # `\s*` is idempotent, so patterns that already carry it are
            # unaffected
            pattern = pattern.replace(r"\(", r"\s*\(\s*")
            self._by_language.setdefault(lang, []).append(
                (library, pattern, algorithm, operation))
        # language supersets share their base catalog (§4): TypeScript is
        # a superset of JavaScript, C++ of C, Kotlin/Scala of the JCA/JCE
        # surface — the same API calls are crypto evidence in both.
        for extra, base in (("typescript", "javascript"),
                            ("c++", "c"),
                            ("kotlin", "java"), ("scala", "java")):
            self._by_language.setdefault(extra, []).extend(
                self._by_language.get(base, []))

    def languages(self) -> list[str]:
        return list(LANGUAGES)

    def detect(
        self,
        *,
        language: str,
        lines: Iterable[str],
        asset_id: str = "default",
        location: str = "",
    ) -> list[dict[str, Any]]:
        """Scan source lines for *known* crypto API patterns.

        Patterns are matched against the whole text (imports and calls often
        sit on different lines, e.g. Go's ``crypto/sha256`` import + call),
        but the *line* the match starts on is still filtered: custom
        definitions (``custom_hash(data)``) and doc/comment lines never
        auto-classify — that is the §5 precision guarantee.
        """
        text = "\n".join(lines)
        return self._match(text, language=language, asset_id=asset_id,
                           location=location)

    def detect_file(
        self,
        *,
        language: str,
        text: str,
        asset_id: str = "default",
        location: str = "",
    ) -> list[dict[str, Any]]:
        return self._match(text, language=language, asset_id=asset_id,
                           location=location)

    def _match(self, text: str, *, language: str, asset_id: str,
               location: str) -> list[dict[str, Any]]:
        lang = language.lower()
        patterns = self._by_language.get(lang)
        if patterns is None:
            return []
        lines = text.splitlines()
        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for library, pattern, algorithm, operation in patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE | re.DOTALL):
                lineno = text.count("\n", 0, match.start()) + 1
                line = lines[lineno - 1] if lineno - 1 < len(lines) else ""
                if _COMMENT_RE.match(line):
                    continue
                if _CUSTOM_DEF_RE.match(line):
                    continue  # §5: custom_hash(data) is never auto-classified
                key = (algorithm, operation.value, library)
                if key in seen:
                    continue
                seen.add(key)
                entry = {
                    "algorithm": algorithm,
                    "operation": operation,
                    "library": library,
                    "location": f"{location}:{lineno}" if location else str(lineno),
                    "asset_id": asset_id,
                    "source": "source_code",
                    "detail": f"{library} API pattern ({pattern!r})",
                }
                entry.update(_extract_components(algorithm, library, text))
                out.append(entry)
        return out
