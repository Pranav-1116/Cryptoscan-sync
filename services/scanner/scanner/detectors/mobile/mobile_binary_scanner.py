"""Mobile app packages without source: Android ``.apk`` / ``.aab`` / ``.dex`` and iOS ``.ipa`` / Mach-O.

A bank's mobile channel is usually delivered as a signed package by a vendor; nobody hands over
the source. What the package still contains:

* **DEX** (``classes*.dex``) — a type table (``Ljavax/crypto/Cipher;``) and a string table
  (``"AES/GCM/NoPadding"``, ``"SHA-256"``, ``"TLSv1.2"``). That is exactly the information the
  JAR constant-pool scanner already interprets, so the DEX tables are fed to the same
  ``analyse_pool``.
* **Native libraries** (``lib/<abi>/*.so`` in an APK, the app binary and ``Frameworks/*`` in an
  IPA) — ELF / Mach-O with symbol names and literals: ``EVP_aes_256_gcm``, ``CCCrypt``,
  ``SecKeyCreateSignature``, ``kCCAlgorithm3DES``, CryptoKit mangled names, TLS cipher-suite
  strings. Symbols go through the PE scanner's OpenSSL/libsodium/mbedTLS/wolfSSL/PKCS#11 table
  plus an Apple CommonCrypto / Security.framework / CryptoKit table added here.
* ``Info.plist`` (``NSAppTransportSecurity`` exceptions → TLS floor) and the Android
  ``network_security_config`` are read as plain strings when present uncompressed.

Findings carry ``source.type = "BINARY"``, ``code_origin = "archive"`` and the member path
inside the package (``app.apk!classes2.dex``).
"""

from __future__ import annotations

import io
import re
import struct
import zipfile
from pathlib import Path

from scanner.detectors.dotnet.assembly_scanner import analyse_imports
from scanner.detectors.java.jar_string_scanner import analyse_pool
from scanner.models.raw_finding import CryptoInfo, FindingMetadata, RawFinding, SourceLocation

SCANNER_ID = "mobile-binary-scanner-v1.0"
MOBILE_PACKAGE_EXT = {".apk", ".aab", ".ipa", ".dex", ".xapk", ".apks"}
_MAX_MEMBER = 200 * 1024 * 1024
_C, _D, _M, _S, _K, _KG, _TLS, _KDF = (("CIPHER_INSTANCE", "ENCRYPTION"), ("MESSAGE_DIGEST", "HASHING"), ("MAC", "MAC_GENERATION"), ("SIGNATURE", "SIGNING"),
                                       ("KEY_PAIR_GENERATOR", "KEY_GENERATION"), ("KEY_GENERATOR", "KEY_GENERATION"), ("KEY_AGREEMENT", "NETWORK_ENCRYPTION"), ("KEY_GENERATOR", "PASSWORD_HASHING"))

# Apple CommonCrypto / Security.framework / CryptoKit — symbol names as they appear in a Mach-O
# string table (leading underscore stripped) and Swift-mangled CryptoKit type names.
_APPLE: tuple[tuple[re.Pattern[str], str, tuple[str, str], str, str], ...] = (
    (re.compile(r"^kCCAlgorithmAES(?:128)?$|^CCCryptorCreateWithMode$"), "AES", _C, "CommonCrypto", "HIGH"),
    (re.compile(r"^kCCAlgorithm3DES$"), "3DES", _C, "CommonCrypto", "HIGH"),
    (re.compile(r"^kCCAlgorithmDES$"), "DES", _C, "CommonCrypto", "HIGH"),
    (re.compile(r"^kCCAlgorithmRC4$"), "RC4", _C, "CommonCrypto", "HIGH"),
    (re.compile(r"^kCCAlgorithmRC2$"), "RC2", _C, "CommonCrypto", "HIGH"),
    (re.compile(r"^kCCAlgorithmBlowfish$"), "Blowfish", _C, "CommonCrypto", "HIGH"),
    (re.compile(r"^CCCrypt$|^CCCryptorCreate$|^CCCryptorUpdate$|^CCCryptorFinal$"), "UNKNOWN", _C, "CommonCrypto", "MEDIUM"),
    (re.compile(r"^CC_MD5(?:_Init|_Update|_Final)?$"), "MD5", _D, "CommonCrypto", "HIGH"),
    (re.compile(r"^CC_SHA1(?:_Init|_Update|_Final)?$"), "SHA-1", _D, "CommonCrypto", "HIGH"),
    (re.compile(r"^CC_SHA256(?:_Init|_Update|_Final)?$"), "SHA-256", _D, "CommonCrypto", "HIGH"),
    (re.compile(r"^CC_SHA384(?:_Init|_Update|_Final)?$"), "SHA-384", _D, "CommonCrypto", "HIGH"),
    (re.compile(r"^CC_SHA512(?:_Init|_Update|_Final)?$"), "SHA-512", _D, "CommonCrypto", "HIGH"),
    (re.compile(r"^CCHmac(?:Init|Update|Final)?$|^kCCHmacAlg(?:SHA1|SHA256|SHA384|SHA512|MD5)$"), "HMAC", _M, "CommonCrypto", "HIGH"),
    (re.compile(r"^CCKeyDerivationPBKDF$|^kCCPBKDF2$"), "PBKDF2", _KDF, "CommonCrypto", "HIGH"),
    (re.compile(r"^CCRandomGenerateBytes$|^SecRandomCopyBytes$|^arc4random(?:_buf|_uniform)?$"), "CSPRNG", _KG, "Security.framework", "HIGH"),
    (re.compile(r"^SecKeyCreateSignature$|^SecKeyVerifySignature$|^SecKeyRawSign$|^SecKeyRawVerify$"), "UNKNOWN", _S, "Security.framework", "MEDIUM"),
    (re.compile(r"^SecKeyCreateEncryptedData$|^SecKeyCreateDecryptedData$|^SecKeyEncrypt$|^SecKeyDecrypt$"), "UNKNOWN", _C, "Security.framework", "MEDIUM"),
    (re.compile(r"^SecKeyCreateRandomKey$|^SecKeyGeneratePair$"), "UNKNOWN", _K, "Security.framework", "MEDIUM"),
    (re.compile(r"^kSecAttrKeyTypeRSA$"), "RSA", _K, "Security.framework", "HIGH"),
    (re.compile(r"^kSecAttrKeyTypeEC(?:SECPrimeRandom)?$|^kSecAttrKeyTypeECDSA$"), "ECDSA", _K, "Security.framework", "HIGH"),
    (re.compile(r"^kSecKeyAlgorithm(?:RSASignatureMessagePKCS1v15|RSASignatureDigestPKCS1v15|RSASignatureMessagePSS|RSAEncryption)\w*$"), "RSA", _S, "Security.framework", "HIGH"),
    (re.compile(r"^kSecKeyAlgorithmECDSASignature\w*$"), "ECDSA", _S, "Security.framework", "HIGH"),
    (re.compile(r"^kSecKeyAlgorithmECIESEncryption\w*$|^kSecKeyAlgorithmECDHKeyExchange\w*$"), "ECDH", _TLS, "Security.framework", "HIGH"),
    (re.compile(r"^kSecAttrTokenIDSecureEnclave$"), "ECDSA", _K, "SecureEnclave", "HIGH"),
    (re.compile(r"^SSLCreateContext$|^SSLHandshake$|^SSLSetProtocolVersionMin$|^SSLSetEnabledCiphers$|^kCFStreamSSLLevel$|^kCFStreamPropertySSLSettings$|^tls_protocol_version_t$|^sec_protocol_options_set_min_tls_protocol_version$|^nw_protocol_copy_tls_definition$"), "TLS", _TLS, "SecureTransport/Network.framework", "HIGH"),
    (re.compile(r"^SecTrustEvaluate(?:WithError|Async)?$|^SecCertificateCreateWithData$|^SecPolicyCreateSSL$|^kSecClassCertificate$|^SecPKCS12Import$"), "X509", _S, "Security.framework", "MEDIUM"),
    (re.compile(r"^kSecClassGenericPassword$|^kSecAttrAccessible\w+$|^SecItemAdd$|^SecItemCopyMatching$"), "UNKNOWN", ("KEY_STORE", "KEY_MANAGEMENT"), "Keychain", "LOW"),
    # Swift CryptoKit mangled names: 9CryptoKit3AESO3GCMO / 9CryptoKit6SHA256V / 9CryptoKit10ChaChaPolyO / 9CryptoKit10Curve25519O / 9CryptoKit4P256O / 9CryptoKit4HMACV
    (re.compile(r"9CryptoKit3AESO"), "AES", _C, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit6SHA256V"), "SHA-256", _D, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit6SHA384V"), "SHA-384", _D, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit6SHA512V"), "SHA-512", _D, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit8Insecure(?:O3MD5V|O4SHA1V)"), "UNKNOWN", _D, "CryptoKit.Insecure", "MEDIUM"),
    (re.compile(r"9CryptoKit8InsecureO3MD5V"), "MD5", _D, "CryptoKit.Insecure", "HIGH"),
    (re.compile(r"9CryptoKit8InsecureO4SHA1V"), "SHA-1", _D, "CryptoKit.Insecure", "HIGH"),
    (re.compile(r"9CryptoKit10ChaChaPolyO"), "ChaCha20-Poly1305", _C, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit10Curve25519O"), "X25519", _K, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit4P256O|9CryptoKit4P384O|9CryptoKit4P521O"), "ECDSA", _K, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit4HMACV"), "HMAC", _M, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit12HKDF"), "HKDF", _KDF, "CryptoKit", "HIGH"),
    (re.compile(r"9CryptoKit12SecureEnclaveO"), "ECDSA", _K, "SecureEnclave", "HIGH"),
    # Info.plist ATS keys
    (re.compile(r"^NSAllowsArbitraryLoads$|^NSExceptionAllowsInsecureHTTPLoads$|^NSExceptionMinimumTLSVersion$|^NSThirdPartyExceptionMinimumTLSVersion$|^NSPinnedDomains$|^NSPinnedLeafIdentities$|^NSExceptionRequiresForwardSecrecy$"), "TLS", _TLS, "App-Transport-Security", "HIGH"),
    (re.compile(r"^TLSv1\.[0-3]$"), "TLS", _TLS, "App-Transport-Security", "MEDIUM"),
)
# Android platform / OkHttp / Conscrypt names that only exist in native or resource strings
_ANDROID_RES: tuple[tuple[re.Pattern[str], str, tuple[str, str], str, str], ...] = (
    (re.compile(r"^cleartextTrafficPermitted$|^network_security_config$|^trust-anchors$|^pin-set$|^certificateTransparency$"), "TLS", _TLS, "Android-NetworkSecurityConfig", "HIGH"),
    (re.compile(r"^AndroidKeyStore$"), "UNKNOWN", ("KEY_STORE", "KEY_MANAGEMENT"), "AndroidKeyStore", "MEDIUM"),
    (re.compile(r"^StrongBox\w*$|^isStrongBoxBacked$|^setIsStrongBoxBacked$"), "UNKNOWN", ("KEY_STORE", "KEY_MANAGEMENT"), "Android-StrongBox", "MEDIUM"),
)
_SUITE = re.compile(r"^(?:TLS|SSL)_[A-Z0-9_]+_WITH_[A-Z0-9_]+$|^TLS_(?:AES_128_GCM_SHA256|AES_256_GCM_SHA384|CHACHA20_POLY1305_SHA256)$|^(?:ECDHE|DHE|ECDH|RSA)-[A-Z0-9-]+$")
_TRANSFORM = re.compile(r"^(?:AES|DES|DESede|TripleDES|RSA|Blowfish|RC2|RC4|ChaCha20)(?:/[A-Za-z0-9_]+){1,2}$|^(?:AES|DES|DESede|RSA|EC|ECDSA|ECDH|DH|HmacSHA(?:1|224|256|384|512)|SHA-?(?:1|224|256|384|512)|MD5|PBKDF2WithHmacSHA(?:1|256|512)|SHA(?:1|256|384|512)withRSA|SHA(?:256|384)withECDSA|Ed25519|X25519|ChaCha20-Poly1305|AES/GCM/NoPadding)$")
_ASCII = re.compile(rb"[\x20-\x7e]{5,200}")


# --------------------------------------------------------------------------- DEX
def _uleb128(buf: bytes, off: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, off
        shift += 7


def dex_tables(data: bytes) -> tuple[list[str], list[str]]:
    """(classes in ``javax/crypto/Cipher`` form, string constants) from a DEX file."""
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return [], []
    string_ids_size, string_ids_off, type_ids_size, type_ids_off = struct.unpack_from("<IIII", data, 0x38)
    if string_ids_off + string_ids_size * 4 > len(data) or type_ids_off + type_ids_size * 4 > len(data):
        return [], []
    strings: list[str] = []
    for i in range(string_ids_size):
        (off,) = struct.unpack_from("<I", data, string_ids_off + i * 4)
        if off >= len(data):
            strings.append("")
            continue
        try:
            _n, p = _uleb128(data, off)
            end = data.index(b"\0", p)
            strings.append(data[p:end].decode("utf-8", "replace"))
        except (ValueError, IndexError):
            strings.append("")
    classes: list[str] = []
    for i in range(type_ids_size):
        (idx,) = struct.unpack_from("<I", data, type_ids_off + i * 4)
        if idx < len(strings):
            desc = strings[idx]
            if desc.startswith("L") and desc.endswith(";"):
                classes.append(desc[1:-1])
    return classes, strings


# --------------------------------------------------------------------------- native
def _strings(data: bytes) -> list[str]:
    return [m.group(0).decode("ascii") for m in _ASCII.finditer(data)]


_TOKEN = re.compile(rb"[A-Za-z0-9_.\-]{3,120}")


def analyse_native(data: bytes, *, tokenize: bool = False) -> list[tuple[str, str, str, str, str, str]]:
    """ELF (.so) or Mach-O (iOS app binary / framework) → (algo, api, purpose, lib, evidence, conf).

    ``tokenize=True`` splits XML / binary plists into word tokens (keys are not NUL-separated there)."""
    out: list[tuple[str, str, str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(algo: str, api: tuple[str, str], lib: str, ev: str, conf: str) -> None:
        key = ((algo or "UNKNOWN").upper(), api[0])
        if key in seen:
            return
        seen.add(key)
        out.append((algo or "UNKNOWN", api[0], api[1], lib, ev, conf))

    strs = [m.group(0).decode("ascii") for m in _TOKEN.finditer(data)] if tokenize else _strings(data)
    symbols = [s[1:] if s.startswith("_") and not s.startswith("__") else s for s in strs]
    for member, algo, api, purpose, lib, ev, conf in analyse_imports([("native", s) for s in symbols]):
        add(algo, (api, purpose), lib, ev, conf)
    for s in symbols:
        for rx, algo, api, lib, conf in _APPLE + _ANDROID_RES:
            if rx.search(s):
                add(algo, api, lib, s[:80], conf)
                break
        else:
            if _SUITE.match(s):
                add("TLS-CIPHERS", _TLS, "native-tls", s, "HIGH")
            elif _TRANSFORM.match(s) and any(x in s for x in ("/", "with", "Hmac", "PBKDF2", "SHA", "MD5", "AES", "RSA", "Cha")):
                # bare "EC"/"DH" are too common in binaries; the transformation shapes above are not
                from scanner.extractors.algorithm_extractor import known_algorithm_or_unknown, parse_transformation

                parsed = parse_transformation(s)
                algo = known_algorithm_or_unknown(parsed.algorithm if parsed else s.split("/")[0])
                if algo != "UNKNOWN":
                    low = s.lower()
                    api = _M if low.startswith("hmac") else _D if low.startswith(("sha", "md5")) and "with" not in low else _S if "with" in low else _KDF if low.startswith("pbkdf2") else _C
                    add(algo, api, "native-literal", s, "MEDIUM")
    return out


# --------------------------------------------------------------------------- packages
def _finding(rel: str, member: str, algo: str, api: str, purpose: str, lib: str, ev: str, conf: str, language: str, reason: str) -> RawFinding:
    return RawFinding(
        scanner_id=SCANNER_ID,
        source=SourceLocation(type="BINARY", language=language, file_path=f"{rel}!{member}" if member else rel, line_number=0, code_snippet=ev[:120]),
        crypto=CryptoInfo(api_type=api, algorithm=algo, purpose=purpose, raw_transformation=ev[:120]),
        metadata=FindingMetadata(confidence=conf, confidence_reason=reason, library=lib, code_origin="archive"),
    )


def _is_native(name: str, head: bytes) -> bool:
    if head[:4] == b"\x7fELF":
        return True
    return head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce")


def scan_mobile_bytes(blob: bytes, rel: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    if blob[:4] == b"dex\n":
        classes, strings = dex_tables(blob)
        for algo, api, purpose, lib, ev, conf in analyse_pool(classes, strings):
            findings.append(_finding(rel, "", algo, api, purpose, lib, ev, conf, "DEX", "DEX type/string table"))
        return findings
    if _is_native(rel, blob[:4]):
        for algo, api, purpose, lib, ev, conf in analyse_native(blob):
            findings.append(_finding(rel, "", algo, api, purpose, lib, ev, conf, "NATIVE", "native symbol / literal"))
        return findings
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile:
        return findings
    with archive:
        for info in archive.infolist():
            name = info.filename
            if name.endswith("/") or info.file_size > _MAX_MEMBER:
                continue
            low = name.lower()
            base = low.rsplit("/", 1)[-1]
            is_dex = base.endswith(".dex")
            is_so = base.endswith(".so") or "/frameworks/" in low or ("payload/" in low and low.count("/") == 2 and "." not in base)
            is_plist = base == "info.plist" or base.endswith("network_security_config.xml")
            is_inner = base.endswith((".apk", ".aab", ".jar"))
            if not (is_dex or is_so or is_plist or is_inner):
                continue
            try:
                data = archive.read(name)
            except Exception:
                continue
            if is_dex or data[:4] == b"dex\n":
                classes, strings = dex_tables(data)
                for algo, api, purpose, lib, ev, conf in analyse_pool(classes, strings):
                    findings.append(_finding(rel, name, algo, api, purpose, lib, ev, conf, "DEX", "DEX type/string table"))
            elif is_inner:
                findings.extend(scan_mobile_bytes(data, f"{rel}!{name}"))
            elif is_plist or _is_native(name, data[:4]):
                for algo, api, purpose, lib, ev, conf in analyse_native(data, tokenize=is_plist):
                    findings.append(_finding(rel, name, algo, api, purpose, lib, ev, conf, "NATIVE" if not is_plist else "PLIST", "native symbol / literal" if not is_plist else "Info.plist / network security config"))
    return findings


def scan_mobile_package(path: Path | str, repo_root: Path | str | None = None) -> list[RawFinding]:
    p = Path(path)
    if not p.is_file():
        return []
    root = Path(repo_root) if repo_root else p.parent
    try:
        rel = str(p.relative_to(root))
    except ValueError:
        rel = p.name
    try:
        blob = p.read_bytes()
    except OSError:
        return []
    return scan_mobile_bytes(blob, rel)
