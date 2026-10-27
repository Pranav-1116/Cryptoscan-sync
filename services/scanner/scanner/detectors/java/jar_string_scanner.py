"""Bytecode-level crypto detection for JAR / WAR / EAR archives and loose ``.class`` files.

Banks ship decades of vendored JARs with no source. Rather than grepping for a
handful of ASCII tokens, this scanner parses every class file's **constant pool**
(JVM spec §4.4) and works from two precise signals:

* ``CONSTANT_Class`` / ``CONSTANT_Methodref`` entries — which crypto API classes
  the class actually references (``javax/crypto/Cipher``, ``java/security/Signature``,
  ``org/bouncycastle/...``, ``sun/security/pkcs11/SunPKCS11``, ``javax/net/ssl/SSLContext`` …).
* ``CONSTANT_String`` entries — the literal algorithm names passed to those APIs
  (``"AES/GCM/NoPadding"``, ``"SHA-256"``, ``"HmacSHA1"``, ``"PBKDF2WithHmacSHA256"``,
  ``"TLSv1"``, ``"SunPKCS11"``, cipher-suite names).

A string constant is only inventoried when the same class references a crypto API
(or the string is unambiguous, e.g. a JCE transformation with ``/`` or a TLS cipher
suite), which is what keeps ``"MD5"`` in a log-format string from becoming a finding.
Library attribution comes from ``META-INF/maven/*/pom.properties`` and the manifest.
Nested archives (``WEB-INF/lib/*.jar`` inside a WAR/EAR) are scanned recursively.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import io
import re
import struct
import zipfile
from pathlib import Path

from scanner.extractors.algorithm_extractor import known_algorithm_or_unknown, parse_transformation
from scanner.models.raw_finding import CryptoInfo, FindingMetadata, RawFinding, SourceLocation

SCANNER_ID = "static-jar-bytecode-scanner-v1.0"
ARCHIVE_SUFFIXES = (".jar", ".war", ".ear", ".rar", ".aar", ".zip", ".sar")

# api class prefix -> (api_type, purpose, library)
_API_CLASSES: tuple[tuple[str, str, str, str], ...] = (
    ("javax/crypto/Cipher", "CIPHER_INSTANCE", "ENCRYPTION", "JCE"),
    ("javax/crypto/Mac", "MAC", "MAC_GENERATION", "JCE"),
    ("javax/crypto/KeyGenerator", "KEY_GENERATOR", "KEY_GENERATION", "JCE"),
    ("javax/crypto/KeyAgreement", "KEY_AGREEMENT", "KEY_EXCHANGE", "JCE"),
    ("javax/crypto/SecretKeyFactory", "KEY_GENERATOR", "PASSWORD_HASHING", "JCE"),
    ("javax/crypto/spec/SecretKeySpec", "KEY_GENERATOR", "KEY_GENERATION", "JCE"),
    ("javax/crypto/spec/PBEKeySpec", "KEY_GENERATOR", "PASSWORD_HASHING", "JCE"),
    ("java/security/MessageDigest", "MESSAGE_DIGEST", "HASHING", "JCA"),
    ("java/security/Signature", "SIGNATURE", "SIGNING", "JCA"),
    ("java/security/KeyPairGenerator", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "JCA"),
    ("java/security/KeyFactory", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "JCA"),
    ("java/security/SecureRandom", "KEY_GENERATOR", "KEY_GENERATION", "JCA"),
    ("java/security/KeyStore", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "JCA"),
    ("javax/net/ssl/SSLContext", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "JSSE"),
    ("javax/net/ssl/SSLSocketFactory", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "JSSE"),
    ("javax/net/ssl/X509TrustManager", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "JSSE"),
    ("org/bouncycastle/", "CIPHER_INSTANCE", "ENCRYPTION", "BouncyCastle"),
    ("org/apache/commons/codec/digest/", "MESSAGE_DIGEST", "HASHING", "commons-codec"),
    ("org/apache/shiro/crypto/", "CIPHER_INSTANCE", "ENCRYPTION", "shiro"),
    ("org/jasypt/", "CIPHER_INSTANCE", "ENCRYPTION", "jasypt"),
    ("org/springframework/security/crypto/", "KEY_GENERATOR", "PASSWORD_HASHING", "spring-security-crypto"),
    ("com/nimbusds/jose/", "SIGNATURE", "SIGNING", "nimbus-jose-jwt"),
    ("io/jsonwebtoken/", "SIGNATURE", "SIGNING", "jjwt"),
    ("com/auth0/jwt/", "SIGNATURE", "SIGNING", "java-jwt"),
    ("sun/security/pkcs11/SunPKCS11", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "PKCS#11"),
    ("iaik/pkcs/pkcs11/", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "PKCS#11"),
    ("com/safenetinc/luna/", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "HSM/Luna"),
    ("com/ncipher/", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "HSM/nCipher"),
    ("com/amazonaws/cloudhsm/", "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "HSM/CloudHSM"),
    ("com/ibm/crypto/", "CIPHER_INSTANCE", "ENCRYPTION", "IBMJCE"),
    ("com/ibm/jsse2/", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "IBMJSSE2"),
    ("org/jpos/security/", "CIPHER_INSTANCE", "ENCRYPTION", "jPOS-security"),
    ("com/google/crypto/tink/", "CIPHER_INSTANCE", "ENCRYPTION", "tink"),
    ("org/mindrot/jbcrypt/", "KEY_GENERATOR", "PASSWORD_HASHING", "jbcrypt"),
    ("de/mkammerer/argon2/", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2-jvm"),
    ("com/lambdaworks/crypto/", "KEY_GENERATOR", "PASSWORD_HASHING", "scrypt"),
    ("org/bouncycastle/pqc/", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "BouncyCastle-PQC"),
    ("javax/security/cert/", "SIGNATURE", "SIGNING", "JCA"),
    ("org/apache/xml/security/", "SIGNATURE", "SIGNING", "santuario"),
)
_API_PREFIXES = tuple(p for p, *_ in _API_CLASSES)

# Class-name only families (no string needed) — the class itself names the algorithm.
_CLASS_ALGO: tuple[tuple[re.Pattern[str], str], ...] = tuple((re.compile(p), a) for p, a in (
    (r"org/bouncycastle/crypto/engines/AESEngine|org/bouncycastle/crypto/engines/AESFastEngine|org/bouncycastle/jcajce/provider/symmetric/AES", "AES"),
    (r"org/bouncycastle/crypto/engines/DESedeEngine", "3DES"),
    (r"org/bouncycastle/crypto/engines/DESEngine$", "DES"),
    (r"org/bouncycastle/crypto/engines/RC4Engine", "RC4"),
    (r"org/bouncycastle/crypto/engines/BlowfishEngine", "Blowfish"),
    (r"org/bouncycastle/crypto/engines/ChaCha7539Engine|org/bouncycastle/crypto/engines/ChaChaEngine", "ChaCha20"),
    (r"org/bouncycastle/crypto/engines/RSAEngine|org/bouncycastle/crypto/signers/RSADigestSigner|org/bouncycastle/crypto/encodings/OAEPEncoding", "RSA"),
    (r"org/bouncycastle/crypto/signers/ECDSASigner|org/bouncycastle/jce/spec/ECNamedCurveParameterSpec", "ECDSA"),
    (r"org/bouncycastle/crypto/signers/Ed25519Signer|org/bouncycastle/crypto/params/Ed25519", "Ed25519"),
    (r"org/bouncycastle/crypto/agreement/X25519Agreement|org/bouncycastle/crypto/params/X25519", "X25519"),
    (r"org/bouncycastle/crypto/agreement/ECDHBasicAgreement", "ECDH"),
    (r"org/bouncycastle/crypto/digests/MD5Digest", "MD5"),
    (r"org/bouncycastle/crypto/digests/SHA1Digest", "SHA-1"),
    (r"org/bouncycastle/crypto/digests/SHA256Digest", "SHA-256"),
    (r"org/bouncycastle/crypto/digests/SHA512Digest", "SHA-512"),
    (r"org/bouncycastle/crypto/digests/SHA3Digest", "SHA3-256"),
    (r"org/bouncycastle/crypto/generators/PKCS5S2ParametersGenerator", "PBKDF2"),
    (r"org/bouncycastle/crypto/generators/SCrypt", "scrypt"),
    (r"org/bouncycastle/crypto/generators/Argon2BytesGenerator", "Argon2"),
    (r"org/bouncycastle/crypto/generators/BCrypt|org/mindrot/jbcrypt/BCrypt|org/springframework/security/crypto/bcrypt/", "BCRYPT"),
    (r"org/bouncycastle/crypto/macs/HMac|org/bouncycastle/crypto/macs/CMac", "HMAC"),
    (r"org/bouncycastle/crypto/modes/GCMBlockCipher|org/bouncycastle/crypto/modes/CBCBlockCipher", "AES"),
    (r"org/bouncycastle/pqc/crypto/mlkem/|org/bouncycastle/pqc/crypto/crystals/kyber/", "ML-KEM"),
    (r"org/bouncycastle/pqc/crypto/mldsa/|org/bouncycastle/pqc/crypto/crystals/dilithium/", "ML-DSA"),
    (r"org/bouncycastle/crypto/fpe/FPEFF1Engine|org/bouncycastle/crypto/fpe/FPEFF3_1Engine", "AES"),
    (r"org/apache/commons/codec/digest/Md5Crypt", "MD5"),
    (r"org/apache/commons/codec/digest/Sha2Crypt", "SHA-512"),
    (r"org/springframework/security/crypto/argon2/", "Argon2"),
    (r"org/springframework/security/crypto/scrypt/", "scrypt"),
    (r"org/springframework/security/crypto/password/Pbkdf2PasswordEncoder", "PBKDF2"),
    (r"org/springframework/security/crypto/password/(?:NoOp|Standard|Md5|Ldap|Message)PasswordEncoder", "UNKNOWN"),
    (r"de/mkammerer/argon2/", "Argon2"),
    (r"com/lambdaworks/crypto/SCrypt", "scrypt"),
    (r"org/jpos/security/(?:EncryptedPIN|SecureDESKey|KeySerialNumber|jceadapter/JCESecurityModule)", "3DES"),
    (r"org/jpos/emv/cryptogram/", "3DES"),
    (r"org/bouncycastle/openpgp/", "PGP"),
    (r"sun/security/pkcs11/SunPKCS11|iaik/pkcs/pkcs11/|com/safenetinc/luna/|com/ncipher/|com/amazonaws/cloudhsm/", "UNKNOWN"),
    (r"javax/net/ssl/SSLContext|javax/net/ssl/SSLSocketFactory|javax/net/ssl/HttpsURLConnection|com/ibm/jsse2/", "TLS"),
    (r"java/security/KeyStore$|java/security/cert/X509Certificate|javax/security/cert/X509Certificate", "X509"),
    (r"java/security/SecureRandom", "CSPRNG"),
))

# Unambiguous string constants — inventoried even without an API-class reference.
_SUITE = re.compile(r"^(?:TLS|SSL)_[A-Z0-9_]+_WITH_[A-Z0-9_]+$|^TLS_(?:AES_(?:128|256)_GCM|CHACHA20_POLY1305)_SHA(?:256|384)$")
_TRANSFORM = re.compile(r"^(?:AES|DES|DESede|TripleDES|RSA|Blowfish|RC2|RC4|ARCFOUR|ChaCha20|ChaCha20-Poly1305|ECIES|Camellia|SM4|ARIA|SEED|CAST5|IDEA|Twofish|Serpent|AESWrap|AES_\d{3})(?:/[A-Za-z0-9_]+){1,2}$|^AES_\d{3}/[A-Za-z0-9]+/[A-Za-z0-9]+$")
_PROTOCOL = re.compile(r"^(?:SSLv2Hello|SSLv3|SSL|TLS|TLSv1|TLSv1\.[0-3]|DTLS|DTLSv1\.[02])$")
# Strings only meaningful when the class also touches a crypto API.
_ALGO_NAME = re.compile(
    r"^(?:AES|DES|DESede|TripleDES|3DES|RSA|DSA|EC|ECDSA|ECDH|ECDHE|XDH|X25519|X448|Ed25519|Ed448|EdDSA|DH|DiffieHellman|Blowfish|RC2|RC4|ARCFOUR|ChaCha20|ChaCha20-Poly1305|"
    r"MD2|MD4|MD5|SHA|SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|SHA-?512/(?:224|256)|SHA3-(?:224|256|384|512)|SHAKE128|SHAKE256|RIPEMD160|Whirlpool|BLAKE2[bs](?:-\d+)?|"
    r"Hmac(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3-\d+)|PBKDF2WithHmac(?:SHA1|SHA224|SHA256|SHA384|SHA512)|PBEWith[A-Za-z0-9]+(?:And[A-Za-z0-9_]+)?|"
    r"(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3-\d+|NONE)with(?:RSA|DSA|ECDSA|RSAandMGF1|RSA/PSS|ECDSAinP1363Format)|RSASSA-PSS|Ed25519|Ed448|ML-KEM(?:-\d+)?|ML-DSA(?:-\d+)?|SLH-DSA[A-Z0-9-]*|Kyber\d*|Dilithium\d*|"
    r"NativePRNG(?:Blocking|NonBlocking)?|SHA1PRNG|DRBG|Windows-PRNG|PKCS12|JKS|JCEKS|BKS|PKCS11|X\.?509|SunPKCS11|LunaProvider|nCipherKM|IBMJCE|IBMJCECCA|IBMJCEPlus|IBMJSSE2|BC|BCFIPS|SunJCE|SunJSSE|SunEC|SunRsaSign|AndroidKeyStore|"
    r"secp(?:256|384|521)r1|secp256k1|prime256v1|P-(?:256|384|521)|brainpoolP\d{3}r1|curve25519|X9\.62 prime256v1|RS(?:256|384|512)|PS(?:256|384|512)|ES(?:256|384|512|256K)|HS(?:256|384|512)|EdDSA|none|A(?:128|192|256)(?:GCM|KW|GCMKW|CBC-HS(?:256|384|512))|RSA-OAEP(?:-256)?|RSA1_5|dir|ECDH-ES(?:\+A(?:128|192|256)KW)?)$"
)
_JWT_ALG = re.compile(r"^(?:RS|PS|ES|HS)(?:256|384|512|256K)$|^EdDSA$|^none$")
_PROVIDER = re.compile(r"^(?:SunPKCS11|LunaProvider|nCipherKM|IBMJCE|IBMJCECCA|IBMJCEPlus|IBMJSSE2|BC|BCFIPS|SunJCE|SunJSSE|SunEC|SunRsaSign|AndroidKeyStore|CloudHSM|Cavium)$")
_PROVIDER_ALGO = {"SunPKCS11": "UNKNOWN", "LunaProvider": "UNKNOWN", "nCipherKM": "UNKNOWN", "IBMJCECCA": "UNKNOWN", "CloudHSM": "UNKNOWN", "Cavium": "UNKNOWN",
                  "IBMJSSE2": "TLS", "SunJSSE": "TLS", "AndroidKeyStore": "UNKNOWN", "IBMJCE": "UNKNOWN", "IBMJCEPlus": "UNKNOWN", "BC": "UNKNOWN", "BCFIPS": "UNKNOWN", "SunJCE": "UNKNOWN", "SunEC": "ECDSA", "SunRsaSign": "RSA"}
_KEYSTORE = {"PKCS12": "X509", "JKS": "X509", "JCEKS": "X509", "BKS": "X509", "PKCS11": "UNKNOWN"}
_CURVES = re.compile(r"^(?:secp(?:256|384|521)r1|secp256k1|prime256v1|P-(?:256|384|521)|brainpoolP\d{3}r1|X9\.62 prime256v1)$")
_RNG = re.compile(r"^(?:NativePRNG(?:Blocking|NonBlocking)?|SHA1PRNG|DRBG|Windows-PRNG)$")
_JOSE_ENC = {"A128GCM": "AES", "A192GCM": "AES", "A256GCM": "AES", "A128KW": "AES", "A192KW": "AES", "A256KW": "AES", "A128GCMKW": "AES", "A192GCMKW": "AES", "A256GCMKW": "AES",
             "A128CBC-HS256": "AES", "A192CBC-HS384": "AES", "A256CBC-HS512": "AES", "RSA-OAEP": "RSA", "RSA-OAEP-256": "RSA", "RSA1_5": "RSA", "ECDH-ES": "ECDH", "ECDH-ES+A128KW": "ECDH", "ECDH-ES+A192KW": "ECDH", "ECDH-ES+A256KW": "ECDH", "dir": "UNKNOWN"}


# --------------------------------------------------------------------------- constant pool
def _read_constant_pool(data: bytes) -> tuple[list[str], list[str]]:
    """Return (class names referenced, string constants) from a class file. Tolerant: returns what it parsed."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return [], []
    count = struct.unpack(">H", data[8:10])[0]
    pos = 10
    utf8: dict[int, str] = {}
    class_refs: list[int] = []
    string_refs: list[int] = []
    i = 1
    try:
        while i < count:
            tag = data[pos]
            pos += 1
            if tag == 1:  # Utf8
                ln = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                raw = data[pos:pos + ln]
                pos += ln
                try:
                    utf8[i] = raw.decode("utf-8", errors="replace")
                except Exception:  # pragma: no cover
                    utf8[i] = ""
            elif tag in (3, 4):  # Integer / Float
                pos += 4
            elif tag in (5, 6):  # Long / Double take two slots
                pos += 8
                i += 1
            elif tag == 7:  # Class
                class_refs.append(struct.unpack(">H", data[pos:pos + 2])[0])
                pos += 2
            elif tag == 8:  # String
                string_refs.append(struct.unpack(">H", data[pos:pos + 2])[0])
                pos += 2
            elif tag in (9, 10, 11, 12):  # Field/Method/InterfaceMethod/NameAndType
                pos += 4
            elif tag == 15:  # MethodHandle
                pos += 3
            elif tag == 16:  # MethodType
                pos += 2
            elif tag == 17 or tag == 18:  # Dynamic / InvokeDynamic
                pos += 4
            elif tag in (19, 20):  # Module / Package
                pos += 2
            else:
                break
            i += 1
    except (struct.error, IndexError):
        pass
    classes = [utf8.get(r, "") for r in class_refs]
    strings = [utf8.get(r, "") for r in string_refs]
    return [c for c in classes if c], [s for s in strings if s]


# --------------------------------------------------------------------------- per-class analysis
def analyse_class(data: bytes) -> list[tuple[str, str, str, str, str, str]]:
    """-> list of (algorithm, api_type, purpose, library, evidence, confidence)."""
    classes, strings = _read_constant_pool(data)
    if not classes:
        return []
    return analyse_pool(classes, strings)


def analyse_pool(classes: list[str], strings: list[str]) -> list[tuple[str, str, str, str, str, str]]:
    """Same analysis for any JVM-shaped symbol table: a class constant pool, or a DEX
    file's type + string tables (Android) — ``classes`` in ``javax/crypto/Cipher`` form."""
    out: list[tuple[str, str, str, str, str, str]] = []
    seen: set[str] = set()

    def add(algo: str, api: str, purpose: str, lib: str, ev: str, conf: str = "HIGH") -> None:
        key = (algo or "UNKNOWN").upper()
        if key in seen:
            return
        seen.add(key)
        out.append((algo or "UNKNOWN", api, purpose, lib, ev, conf))

    api_hits = [(c, spec) for c in classes for spec in _API_CLASSES if c.startswith(spec[0])]
    uses_crypto_api = bool(api_hits)
    default_api = api_hits[0][1] if api_hits else ("", "UNKNOWN", "UNKNOWN", "unknown")
    _, d_api, d_purpose, d_lib = default_api

    # 1. class-name families
    for c in classes:
        for pat, algo in _CLASS_ALGO:
            if pat.search(c):
                spec = next((s for s in _API_CLASSES if c.startswith(s[0])), default_api)
                add(algo, spec[1], spec[2], spec[3], c, "MEDIUM" if algo == "UNKNOWN" else "HIGH")
    # 2. string constants
    for s in strings:
        if len(s) > 64 or "\n" in s:
            continue
        if _SUITE.match(s):
            add("TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "JSSE", s)
            continue
        if _TRANSFORM.match(s):
            parsed = parse_transformation(s)
            algo = known_algorithm_or_unknown(parsed.algorithm if parsed else s.split("/")[0])
            add(algo, "CIPHER_INSTANCE", "ENCRYPTION", d_lib if uses_crypto_api else "JCE", s)
            continue
        if _PROTOCOL.match(s):
            if uses_crypto_api or any("ssl" in c.lower() or "tls" in c.lower() or "http" in c.lower() for c in classes):
                add({"SSLv3": "SSLv3", "SSLv2Hello": "SSLv2", "TLSv1": "TLS1.0", "TLSv1.0": "TLS1.0", "TLSv1.1": "TLS1.1", "TLSv1.2": "TLS1.2", "TLSv1.3": "TLS1.3"}.get(s, "TLS"),
                    "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "JSSE", s, "MEDIUM")
            continue
        if not uses_crypto_api:
            continue
        if not _ALGO_NAME.match(s):
            continue
        if _PROVIDER.match(s):
            add(_PROVIDER_ALGO[s], "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", {"SunPKCS11": "PKCS#11", "LunaProvider": "HSM/Luna", "nCipherKM": "HSM/nCipher", "IBMJCECCA": "IBMJCECCA", "IBMJSSE2": "IBMJSSE2", "IBMJCE": "IBMJCE", "IBMJCEPlus": "IBMJCE", "CloudHSM": "HSM/CloudHSM", "Cavium": "HSM/CloudHSM"}.get(s, d_lib), s, "MEDIUM")
            continue
        if s in _KEYSTORE:
            add(_KEYSTORE[s], "KEY_PAIR_GENERATOR", "KEY_MANAGEMENT", "JCA", s, "MEDIUM")
            continue
        if _CURVES.match(s):
            add("ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", d_lib, s, "MEDIUM")
            continue
        if _RNG.match(s):
            add("CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "JCA", s)
            continue
        if _JWT_ALG.match(s):
            if s == "none" and not any(c.startswith(("com/nimbusds/jose", "io/jsonwebtoken", "com/auth0/jwt", "org/jose4j")) for c in classes):
                continue  # "none" is an ordinary string unless a JOSE library is in play
            add("JWT", "SIGNATURE", "SIGNING", d_lib, s, "MEDIUM")
            fam = {"RS": "RSA", "PS": "RSA", "ES": "ECDSA", "HS": "HMAC"}.get(s[:2])
            if s == "EdDSA":
                fam = "Ed25519"
            if fam:
                add(fam, "SIGNATURE", "SIGNING", d_lib, s, "MEDIUM")
            continue
        if s in _JOSE_ENC:
            add(_JOSE_ENC[s], "CIPHER_INSTANCE", "ENCRYPTION", d_lib, s, "MEDIUM")
            continue
        parsed = parse_transformation(s)
        algo = known_algorithm_or_unknown(parsed.algorithm if parsed else s)
        if algo == "UNKNOWN":
            continue
        api, purpose = d_api, d_purpose
        low = s.lower()
        if low.startswith("hmac"):
            api, purpose = "MAC", "MAC_GENERATION"
        elif low.startswith(("sha", "md", "ripemd", "whirlpool", "blake", "shake")) and "with" not in low:
            api, purpose = "MESSAGE_DIGEST", "HASHING"
        elif "with" in low and ("rsa" in low or "dsa" in low or "ecdsa" in low) and not low.startswith("pbe"):
            api, purpose = "SIGNATURE", "SIGNING"
        elif low.startswith(("pbkdf2", "pbe")):
            api, purpose = "KEY_GENERATOR", "PASSWORD_HASHING"
        add(algo, api, purpose, d_lib, s)
        if parsed is not None:
            extra = getattr(parsed, "hash_algorithm", None)
            if extra and extra.upper() != algo.upper():
                add(extra, "MESSAGE_DIGEST", "HASHING", d_lib, s)
            if re.search(r"(?i)hmac", s) and algo.upper() != "HMAC":
                add("HMAC", "MAC", "MAC_GENERATION", d_lib, s)
    return out


# --------------------------------------------------------------------------- archives
def _artifact_name(archive: zipfile.ZipFile, fallback: str) -> str:
    for name in archive.namelist():
        if name.startswith("META-INF/maven/") and name.endswith("pom.properties"):
            try:
                props = dict(l.split("=", 1) for l in archive.read(name).decode("utf-8", "replace").splitlines() if "=" in l and not l.startswith("#"))
                g, a, v = props.get("groupId", "").strip(), props.get("artifactId", "").strip(), props.get("version", "").strip()
                if a:
                    return f"{g}:{a}:{v}".strip(":")
            except Exception as _handler_exc:  # pragma: no cover
                logger.warning(
                    "exception_suppressed",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                pass
    try:
        mf = archive.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
        title = re.search(r"^(?:Bundle-SymbolicName|Implementation-Title|Automatic-Module-Name):\s*(\S+)", mf, re.M)
        ver = re.search(r"^(?:Bundle-Version|Implementation-Version):\s*(\S+)", mf, re.M)
        if title:
            return f"{title.group(1)}:{ver.group(1)}" if ver else title.group(1)
    except KeyError:
        pass
    return fallback


def _finding(rel: str, member: str, algo: str, api: str, purpose: str, lib: str, evidence: str, conf: str, artifact: str) -> RawFinding:
    return RawFinding(
        scanner_id=SCANNER_ID,
        source=SourceLocation(type="BINARY", language="JAVA", file_path=f"{rel}!{member}", line_number=0, code_snippet=evidence[:120]),
        crypto=CryptoInfo(api_type=api, algorithm=algo, raw_transformation=evidence[:120]),
        metadata=FindingMetadata(confidence=conf, confidence_reason=f"bytecode constant pool of {artifact}", library=lib, code_origin="archive"),
    )


def _scan_archive_bytes(blob: bytes, rel: str, depth: int = 0) -> list[RawFinding]:
    findings: list[RawFinding] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return findings
    with archive:
        artifact = _artifact_name(archive, Path(rel.split("!")[-1]).name)
        for info in archive.infolist():
            name = info.filename
            if name.endswith("/") or info.file_size > 50_000_000:
                continue
            low = name.lower()
            if low.endswith(".class"):
                try:
                    data = archive.read(name)
                except Exception as _handler_exc:
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    continue
                for algo, api, purpose, lib, ev, conf in analyse_class(data):
                    findings.append(_finding(rel, name, algo, api, purpose, lib, ev, conf, artifact))
            elif low.endswith(ARCHIVE_SUFFIXES) and depth < 3:
                try:
                    inner = archive.read(name)
                except Exception as _handler_exc:
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    continue
                findings.extend(_scan_archive_bytes(inner, f"{rel}!{name}", depth + 1))
    return findings


def scan_jar(jar_path: Path | str, repo_root: Path | str | None = None) -> list[RawFinding]:
    path = Path(jar_path)
    if not path.is_file():
        return []
    root = Path(repo_root) if repo_root else path.parent
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    try:
        blob = path.read_bytes()
    except OSError:
        return []
    return _scan_archive_bytes(blob, rel)


def scan_class_file(class_path: Path | str, repo_root: Path | str | None = None) -> list[RawFinding]:
    """Loose ``.class`` files (``target/classes``, ``WEB-INF/classes`` checked into a repo)."""
    path = Path(class_path)
    root = Path(repo_root) if repo_root else path.parent
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    try:
        data = path.read_bytes()
    except OSError:
        return []
    return [_finding(rel, "", a, api, p, lib, ev, conf, path.name).model_copy(update={"source": SourceLocation(type="BINARY", language="JAVA", file_path=rel, line_number=0, code_snippet=ev[:120])})
            for a, api, p, lib, ev, conf in analyse_class(data)]
