"""Swift crypto detector: CryptoKit, CommonCrypto, Security.framework (SecKey/SecTrust),
Network.framework / URLSession TLS settings, CryptoSwift, swift-sodium, JWTKit,
swift-crypto (server-side, same API as CryptoKit) and Vapor password hashers.

Design mirrors the other regex-backed parsers (Go/Rust/PHP): one rule per API
idiom, ``(line, algorithm)`` de-duplication, ``//``/``/* */`` comments stripped
with line numbers preserved. ``import CryptoKit`` alone is *not* a finding — the
call site is.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import Rule, filter_prng_context, run_rules

SCANNER_ID = "static-swift-scanner-v1.0"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_KA = {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern), {**base, "library": library, **extra}


_CK_DIGEST = {"sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5", "sha1": "SHA-1"}
_CC_DIGEST = {"md2": "MD2", "md4": "MD4", "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
_CC_ALG = {"aes128": "AES", "aes": "AES", "des": "DES", "3des": "3DES", "cast": "CAST5", "rc4": "RC4", "rc2": "RC2", "blowfish": "Blowfish"}
_CC_HMAC = {"sha1": "SHA-1", "md5": "MD5", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha224": "SHA-224"}
_SEC_KEY_TYPE = {"rsa": "RSA", "ec": "ECDSA", "ecsecprimerandom": "ECDSA", "dsa": "DSA", "ecdsa": "ECDSA", "aes": "AES", "3des": "3DES", "des": "DES", "rc4": "RC4", "rc2": "RC2", "cast": "CAST5"}
_CS_HASH = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha3": "SHA3-256"}
_JWT_ALGS = {
    "hs256": "JWT", "hs384": "JWT", "hs512": "JWT", "rs256": "JWT", "rs384": "JWT", "rs512": "JWT",
    "es256": "JWT", "es384": "JWT", "es512": "JWT", "ps256": "JWT", "ps384": "JWT", "ps512": "JWT", "eddsa": "JWT", "none": "none",
}

_RULES: list[Rule] = [
    # ------------------------------------------------------------ CryptoKit / swift-crypto
    _r(r"\bInsecure\.MD5\b", _D, "CryptoKit", algorithm="MD5"),
    _r(r"\bInsecure\.SHA1\b", _D, "CryptoKit", algorithm="SHA-1"),
    _r(r"(?<![\w.])(SHA256|SHA384|SHA512)\s*(?:\.hash\s*\(|\(\)|\.Digest\b)", _D, "CryptoKit", algo_from_group=1, algo_map=_CK_DIGEST),
    _r(r"\bHMAC\s*<\s*(SHA256|SHA384|SHA512|Insecure\.SHA1|Insecure\.MD5)\s*>", _M, "CryptoKit", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bAES\.GCM\.(?:seal|open|Nonce|SealedBox)\b", _C, "CryptoKit", algorithm="AES", mode="GCM"),
    _r(r"\bChaChaPoly\.(?:seal|open|Nonce|SealedBox)\b", _C, "CryptoKit", algorithm="ChaCha20-Poly1305"),
    _r(r"\bAES\.KeyWrap\.(?:wrap|unwrap)\b", _C, "CryptoKit", algorithm="AES", mode="KW"),
    _r(r"\bCurve25519\.Signing\.(?:PrivateKey|PublicKey)\b", _S, "CryptoKit", algorithm="Ed25519"),
    _r(r"\bCurve25519\.KeyAgreement\.(?:PrivateKey|PublicKey)\b", _KA, "CryptoKit", algorithm="X25519"),
    _r(r"\b(?:SecureEnclave\.)?P(?:256|384|521)\.Signing\.(?:PrivateKey|PublicKey|ECDSASignature)\b", _S, "CryptoKit", algorithm="ECDSA"),
    _r(r"\b(?:SecureEnclave\.)?P(?:256|384|521)\.KeyAgreement\.(?:PrivateKey|PublicKey)\b", _KA, "CryptoKit", algorithm="ECDH"),
    _r(r"\bHKDF\s*<\s*(SHA256|SHA384|SHA512|Insecure\.SHA1)\s*>", _KDF, "CryptoKit", algorithm="HKDF", emit_digest_group=1, purpose="KEY_GENERATION"),
    _r(r"\bSymmetricKey\s*\(\s*size\s*:", _RNG, "CryptoKit", algorithm="CSPRNG", confidence="MEDIUM", confidence_reason="CryptoKit SymmetricKey generated from system CSPRNG"),
    _r(r"\bsharedSecretFromKeyAgreement\s*\(", _KA, "CryptoKit", algorithm="ECDH", confidence="MEDIUM"),
    # swift-crypto extras (_CryptoExtras)
    _r(r"\b_RSA\.(?:Signing|Encryption)\.(?:PrivateKey|PublicKey)\b|\bRSA\.(?:Signing|Encryption)\.(?:PrivateKey|PublicKey)\b", _S, "swift-crypto", algorithm="RSA"),
    _r(r"\bKDF\.Insecure\.PBKDF2\.deriveKey\b|\bPBKDF2\.deriveKey\b", _KDF, "swift-crypto", algorithm="PBKDF2"),
    _r(r"\bKDF\.Scrypt\.deriveKey\b", _KDF, "swift-crypto", algorithm="SCRYPT"),
    _r(r"\bAES\._CBC\.(?:encrypt|decrypt)\b", _C, "swift-crypto", algorithm="AES", mode="CBC"),
    _r(r"\bAES\._CFB\.(?:encrypt|decrypt)\b", _C, "swift-crypto", algorithm="AES", mode="CFB"),
    _r(r"\bAES\._CTR\.(?:encrypt|decrypt)\b", _C, "swift-crypto", algorithm="AES", mode="CTR"),
    _r(r"\bMLKEM(?:768|1024)\.(?:PrivateKey|PublicKey)\b|\bMLKEM(?:768|1024)\b\.", _KA, "swift-crypto", algorithm="ML-KEM"),
    _r(r"\bMLDSA(?:65|87)\.(?:PrivateKey|PublicKey)\b", _S, "swift-crypto", algorithm="ML-DSA"),
    _r(r"\bXWingMLKEM768X25519\b", _KA, "swift-crypto", algorithm="ML-KEM"),
    # ------------------------------------------------------------ CommonCrypto
    _r(r"\bCC_(MD2|MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512)(?:_Init|_Update|_Final)?\s*\(", _D, "CommonCrypto", algo_from_group=1, algo_map=_CC_DIGEST),
    _r(r"\bCC_(MD2|MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512)_DIGEST_LENGTH\b", _D, "CommonCrypto", algo_from_group=1, algo_map=_CC_DIGEST, confidence="MEDIUM"),
    _r(r"\bkCCAlgorithm(AES128|AES|DES|3DES|CAST|RC4|RC2|Blowfish)\b", _C, "CommonCrypto", algo_from_group=1, algo_map=_CC_ALG),
    _r(r"\bCCCrypt(?:orCreate(?:WithMode)?)?\s*\((?![^\n]*kCCAlgorithm)", _C, "CommonCrypto", algorithm="UNKNOWN", confidence="LOW", confidence_reason="CCCrypt with algorithm resolved elsewhere"),
    _r(r"\bkCCMode(ECB|CBC|CFB|CTR|OFB|XTS|RC4|CFB8)\b", _C, "CommonCrypto", algorithm="UNKNOWN", confidence="LOW", confidence_reason="cipher mode constant"),
    _r(r"\bkCCHmacAlg(SHA1|MD5|SHA256|SHA384|SHA512|SHA224)\b", _M, "CommonCrypto", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCCHmac(?:Init|Update|Final)?\s*\((?![^\n]*kCCHmacAlg)", _M, "CommonCrypto", algorithm="HMAC", confidence="MEDIUM"),
    _r(r"\bkCCPBKDF2\b|\bCCKeyDerivationPBKDF\s*\(", _KDF, "CommonCrypto", algorithm="PBKDF2"),
    _r(r"\bkCCPRFHmacAlg(SHA1|SHA224|SHA256|SHA384|SHA512)\b", _M, "CommonCrypto", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCCRandomGenerateBytes\s*\(|\bSecRandomCopyBytes\s*\(|\bCCRandomCopyBytes\s*\(", _RNG, "CommonCrypto", algorithm="CSPRNG"),
    _r(r"\bSystemRandomNumberGenerator\s*\(", _RNG, "Swift stdlib", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\barc4random(?:_uniform|_buf)?\s*\(", _RNG, "libc", algorithm="CSPRNG", confidence="MEDIUM", confidence_reason="arc4random is CSPRNG-backed on Apple platforms"),
    _r(r"\b(?:drand48|srand48|rand|srand|random|srandom|lrand48)\s*\(", _RNG, "libc", algorithm="PRNG", confidence="HIGH", confidence_reason="non-cryptographic PRNG in security context"),
    _r(r"\bGKRandomSource\b|\bGKARC4RandomSource\b|\bGKLinearCongruentialRandomSource\b|\bGKMersenneTwisterRandomSource\b", _RNG, "GameplayKit", algorithm="PRNG", confidence="HIGH", confidence_reason="GameplayKit random sources are not cryptographic"),
    # ------------------------------------------------------------ Security.framework
    _r(r"\bkSecAttrKeyType(RSA|ECSECPrimeRandom|EC|ECDSA|DSA|AES|3DES|DES|RC4|RC2|CAST)\b", _K, "Security.framework", algo_from_group=1, algo_map=_SEC_KEY_TYPE),
    _r(r"\bSecKeyCreateRandomKey\s*\((?![^\n]*kSecAttrKeyType)", _K, "Security.framework", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\.(?:rsa(?:Signature|Encryption)[A-Za-z0-9]*?(SHA1|SHA224|SHA256|SHA384|SHA512)(?![0-9])|rsaSignatureRaw\b|rsaEncryptionRaw\b|rsaEncryptionPKCS1\b)", _S, "Security.framework", algorithm="RSA", emit_digest_group=1),
    _r(r"\.ecdsaSignature(?:Message|Digest)(?:X962|RFC4754)(SHA1|SHA224|SHA256|SHA384|SHA512)\b", _S, "Security.framework", algorithm="ECDSA", emit_digest_group=1),
    _r(r"\.eciesEncryption[A-Za-z0-9]*?(SHA1|SHA224|SHA256|SHA384|SHA512)[A-Za-z0-9]*?AESGCM\b", _C, "Security.framework", algorithm="ECDH", emit_digest_group=1, confidence_reason="ECIES (ECDH + AES-GCM)"),
    _r(r"\.eciesEncryption[A-Za-z0-9]*?AESGCM\b", _C, "Security.framework", algorithm="AES", mode="GCM"),
    _r(r"\.ecdhKeyExchange(?:Standard|Cofactor)(?:X963)?(?:SHA1|SHA224|SHA256|SHA384|SHA512)?\b", _KA, "Security.framework", algorithm="ECDH"),
    _r(r"\bSecKeyCreate(?:Signature|EncryptedData|DecryptedData)\s*\(|\bSecKeyVerifySignature\s*\(", _S, "Security.framework", algorithm="UNKNOWN", confidence="LOW", confidence_reason="SecKey operation; algorithm given by SecKeyAlgorithm constant"),
    _r(r"\bSecTrust(?:Evaluate(?:WithError|Async)?|SetAnchorCertificates|CreateWithCertificates|SetPolicies|CopyCertificateChain)\s*\(|\bSecPolicyCreate(?:SSL|BasicX509)\s*\(|\bSecCertificateCreateWithData\s*\(|\bSecPKCS12Import\s*\(|\bSecIdentityCopyCertificate\s*\(", _TLS, "Security.framework", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bSecTrustSetAnchorCertificatesOnly\s*\(\s*\w+\s*,\s*false\s*\)", _TLS, "Security.framework", algorithm="TRUST-ALL", confidence="MEDIUM", confidence_reason="system anchors re-enabled alongside custom anchors"),
    # URLSession challenge handler returning the server trust without evaluating it
    _r(r"URLCredential\s*\(\s*trust\s*:\s*(?:challenge\.protectionSpace\.)?serverTrust\s*!?\s*\)", _TLS, "URLSession", algorithm="TRUST-ALL", confidence="MEDIUM", confidence_reason="server trust accepted in authentication challenge (verify SecTrustEvaluate precedes it)"),
    _r(r"\.performDefaultHandling\b|\.cancelAuthenticationChallenge\b", _TLS, "URLSession", algorithm="TLS", confidence="LOW"),
    _r(r"\bNSAllowsArbitraryLoads\b", _TLS, "App Transport Security", algorithm="TLS-CLEARTEXT", confidence="HIGH", confidence_reason="ATS exception permits plaintext HTTP"),
    _r(r"\bNSExceptionAllowsInsecureHTTPLoads\b|\bNSThirdPartyExceptionAllowsInsecureHTTPLoads\b", _TLS, "App Transport Security", algorithm="TLS-CLEARTEXT", confidence="HIGH"),
    _r(r"\bNSExceptionMinimumTLSVersion\b[^\n]*?TLSv1\.0\b", _TLS, "App Transport Security", algorithm="TLS1.0", confidence="HIGH"),
    _r(r"\bNSExceptionMinimumTLSVersion\b[^\n]*?TLSv1\.1\b", _TLS, "App Transport Security", algorithm="TLS1.1", confidence="HIGH"),
    _r(r"\bNSExceptionMinimumTLSVersion\b[^\n]*?TLSv1\.2\b", _TLS, "App Transport Security", algorithm="TLS1.2"),
    _r(r"\bNSExceptionMinimumTLSVersion\b[^\n]*?TLSv1\.3\b", _TLS, "App Transport Security", algorithm="TLS1.3"),
    # Network.framework / URLSessionConfiguration / SecureTransport TLS versions
    _r(r"\.TLSv13\b|\btls_protocol_version_t\.TLSv13\b|\bkTLSProtocol13\b|\.tlsProtocol13\b", _TLS, "Network.framework", algorithm="TLS1.3"),
    _r(r"\.TLSv12\b|\btls_protocol_version_t\.TLSv12\b|\bkTLSProtocol12\b|\.tlsProtocol12\b", _TLS, "Network.framework", algorithm="TLS1.2"),
    _r(r"\.TLSv11\b|\btls_protocol_version_t\.TLSv11\b|\bkTLSProtocol11\b|\.tlsProtocol11\b", _TLS, "Network.framework", algorithm="TLS1.1", confidence="HIGH", confidence_reason="deprecated protocol"),
    _r(r"\.TLSv10\b|\btls_protocol_version_t\.TLSv10\b|\bkTLSProtocol1\b|\.tlsProtocol1\b", _TLS, "Network.framework", algorithm="TLS1.0", confidence="HIGH", confidence_reason="deprecated protocol"),
    _r(r"\bkSSLProtocol3\b|\.sslProtocol3\b", _TLS, "SecureTransport", algorithm="SSLv3", confidence="HIGH"),
    _r(r"\bkSSLProtocol2\b|\.sslProtocol2\b", _TLS, "SecureTransport", algorithm="SSLv2", confidence="HIGH"),
    _r(r"\bsec_protocol_options_(?:set_min_tls_protocol_version|set_max_tls_protocol_version|append_tls_ciphersuite|set_verify_block|set_peer_authentication_required)\s*\(|\bNWProtocolTLS\.Options\s*\(|\bSSLCreateContext\s*\(|\bSSLHandshake\s*\(", _TLS, "Network.framework", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bsec_protocol_options_set_peer_authentication_required\s*\([^,\n]*,\s*false\s*\)", _TLS, "Network.framework", algorithm="TLS-CERT-NONE", confidence="HIGH", confidence_reason="peer authentication disabled"),
    _r(r"\bsec_protocol_options_append_tls_ciphersuite(?:_group)?\s*\(", _TLS, "Network.framework", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"\btls_ciphersuite_t\.(RSA_WITH_[A-Z0-9_]+|ECDHE_[A-Z0-9_]+|AES_[A-Z0-9_]+|CHACHA20_[A-Z0-9_]+)\b", _TLS, "Network.framework", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"\bTLS_[A-Z0-9_]+_WITH_[A-Z0-9_]+\b", _TLS, "SecureTransport", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"\bServerTrustPolicy\.disableEvaluation\b|\bDisabledTrustEvaluator\s*\(|\bDisabledEvaluator\s*\(|\bServerTrustManager\s*\([^\n]*disable", _TLS, "Alamofire", algorithm="TRUST-ALL", confidence="HIGH", confidence_reason="Alamofire server trust evaluation disabled"),
    _r(r"\bPinnedCertificatesTrustEvaluator\s*\(|\bPublicKeysTrustEvaluator\s*\(|\bServerTrustPolicy\.pin(?:Certificates|PublicKeys)\b", _TLS, "Alamofire", algorithm="X509", confidence="MEDIUM", confidence_reason="certificate / public-key pinning"),
    # ------------------------------------------------------------ CryptoSwift
    _r(r"\bAES\s*\(\s*key\s*:[^\n]*?blockMode\s*:\s*(GCM|CBC|CTR|ECB|CFB|OFB|PCBC|CCM)\b", _C, "CryptoSwift", algorithm="AES", mode_from_group=1),
    _r(r"\bAES\s*\(\s*key\s*:(?![^\n]*blockMode)", _C, "CryptoSwift", algorithm="AES", confidence="MEDIUM"),
    _r(r"\bBlowfish\s*\(\s*key\s*:", _C, "CryptoSwift", algorithm="Blowfish"),
    _r(r"\bChaCha20\s*\(\s*key\s*:", _C, "CryptoSwift", algorithm="ChaCha20"),
    _r(r"\bRabbit\s*\(\s*key\s*:", _C, "CryptoSwift", algorithm="Rabbit"),
    _r(r"\bHMAC\s*\(\s*key\s*:[^\n]*?variant\s*:\s*\.(?:sha2\s*\(\s*\.)?(md5|sha1|sha256|sha384|sha512|sha224)\b", _M, "CryptoSwift", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bHMAC\s*\(\s*key\s*:(?![^\n]*variant)", _M, "CryptoSwift", algorithm="HMAC", confidence="MEDIUM"),
    _r(r"\bPoly1305\s*\(\s*key\s*:", _M, "CryptoSwift", algorithm="Poly1305"),
    _r(r"\bCMAC\s*\(\s*key\s*:", _M, "CryptoSwift", algorithm="AES", confidence_reason="AES-CMAC"),
    _r(r"\bPKCS5\.PBKDF2\s*\(", _KDF, "CryptoSwift", algorithm="PBKDF2"),
    _r(r"\bPKCS5\.PBKDF1\s*\(", _KDF, "CryptoSwift", algorithm="PBKDF1"),
    _r(r"\bScrypt\s*\(\s*password\s*:", _KDF, "CryptoSwift", algorithm="SCRYPT"),
    _r(r"\bHKDF\s*\(\s*password\s*:", _KDF, "CryptoSwift", algorithm="HKDF", purpose="KEY_GENERATION"),
    _r(r"\bDigest\.(md5|sha1|sha224|sha256|sha384|sha512|sha3)\s*\(", _D, "CryptoSwift", algo_from_group=1, algo_map=_CS_HASH),
    _r(r"\.(md5|sha1|sha224|sha256|sha384|sha512)\s*\(\s*\)", _D, "CryptoSwift", algo_from_group=1, algo_map=_CS_HASH, confidence="MEDIUM", confidence_reason="Data/String/Array digest extension"),
    _r(r"\bSHA3\s*\(\s*variant\s*:", _D, "CryptoSwift", algorithm="SHA3-256"),
    _r(r"\bMD5\s*\(\s*\)", _D, "CryptoSwift", algorithm="MD5"),
    _r(r"\bSHA1\s*\(\s*\)", _D, "CryptoSwift", algorithm="SHA-1"),
    _r(r"\bSHA2\s*\(\s*variant\s*:\s*\.(sha224|sha256|sha384|sha512)\b", _D, "CryptoSwift", algo_from_group=1, algo_map=_CS_HASH),
    _r(r"\bRSA\s*\(\s*(?:keySize|n|rawRepresentation|derRepresentation|pemRepresentation)\s*:", _K, "CryptoSwift", algorithm="RSA"),
    # ------------------------------------------------------------ swift-sodium / libsodium
    _r(r"\bsodium\.secretBox\.(?:seal|open)\b|\bcrypto_secretbox_easy\b", _C, "swift-sodium", algorithm="XSalsa20-Poly1305"),
    _r(r"\bsodium\.aead\.xchacha20poly1305ietf\b|\bcrypto_aead_xchacha20poly1305_ietf_(?:encrypt|decrypt)\b", _C, "swift-sodium", algorithm="ChaCha20-Poly1305"),
    _r(r"\bsodium\.aead\.aes256gcm\b|\bcrypto_aead_aes256gcm_(?:encrypt|decrypt)\b", _C, "swift-sodium", algorithm="AES", mode="GCM"),
    _r(r"\bsodium\.box\.(?:seal|open|keyPair)\b|\bcrypto_box_(?:easy|open_easy|keypair|seal)\b", _KA, "swift-sodium", algorithm="X25519"),
    _r(r"\bsodium\.sign\.(?:sign|verify|keyPair|signature)\b|\bcrypto_sign_(?:detached|verify_detached|keypair)\b", _S, "swift-sodium", algorithm="Ed25519"),
    _r(r"\bsodium\.pwHash\.(?:str|hash|strVerify)\b|\bcrypto_pwhash(?:_str)?\b", _KDF, "swift-sodium", algorithm="ARGON2"),
    _r(r"\bsodium\.genericHash\.(?:hash|initStream)\b|\bcrypto_generichash\b", _D, "swift-sodium", algorithm="BLAKE2b"),
    _r(r"\bsodium\.auth\.(?:tag|verify)\b|\bcrypto_auth\b", _M, "swift-sodium", algorithm="HMAC-SHA512"),
    _r(r"\bsodium\.keyExchange\.(?:keyPair|sessionKeyPair)\b|\bcrypto_kx_", _KA, "swift-sodium", algorithm="X25519"),
    _r(r"\bsodium\.shortHash\.hash\b|\bcrypto_shorthash\b", _M, "swift-sodium", algorithm="SipHash", confidence="MEDIUM"),
    _r(r"\bsodium\.stream\.xor\b|\bcrypto_stream_xor\b", _C, "swift-sodium", algorithm="XSalsa20"),
    _r(r"\bsodium\.randomBytes\.buf\b|\brandombytes_buf\b", _RNG, "swift-sodium", algorithm="CSPRNG"),
    # ------------------------------------------------------------ JWTKit / Vapor
    _r(r"\.(hs256|hs384|hs512|rs256|rs384|rs512|es256|es384|es512|ps256|ps384|ps512|eddsa)\s*\(\s*(?:key|curve)\s*:", _S, "JWTKit", algo_from_group=1, algo_map=_JWT_ALGS),
    _r(r"\bJWTSigner\.(hs256|hs384|hs512|rs256|rs384|rs512|es256|es384|es512|ps256|ps384|ps512|eddsa)\b", _S, "JWTKit", algo_from_group=1, algo_map=_JWT_ALGS),
    _r(r"\bHMACKey\s*\(|\.add\s*\(\s*hmac\s*:(?![^\n]*digestAlgorithm)", _M, "JWTKit", algorithm="HMAC", confidence="MEDIUM", confidence_reason="JWT HMAC signing key"),
    _r(r"\.add\s*\(\s*hmac\s*:[^\n]*?digestAlgorithm\s*:\s*\.(sha256|sha384|sha512)\b|\bHMACKey\s*\([^\n]*?digestAlgorithm\s*:\s*\.(sha256|sha384|sha512)\b", _M, "JWTKit", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bInsecure\.RSA\.(?:PrivateKey|PublicKey)\b|\bRSAKey\s*\(|\.add\s*\(\s*(?:rsa|pss)\s*:", _S, "JWTKit", algorithm="RSA"),
    _r(r"\bES(?:256|384|512)(?:PrivateKey|PublicKey)\b|\bECDSAKey\s*\(|\.add\s*\(\s*ecdsa\s*:", _S, "JWTKit", algorithm="ECDSA"),
    _r(r"\bEdDSA\.(?:PrivateKey|PublicKey)\b|\bEdDSAKey\s*\(|\.add\s*\(\s*eddsa\s*:", _S, "JWTKit", algorithm="Ed25519"),
    _r(r"\.add\s*\(\s*(?:hmac|rsa|pss|ecdsa|eddsa)\s*:|\bHMACKey\s*\(|\bInsecure\.RSA\.(?:PrivateKey|PublicKey)\b|\bES(?:256|384|512)(?:PrivateKey|PublicKey)\b|\bEdDSA\.(?:PrivateKey|PublicKey)\b", _S, "JWTKit", algorithm="JWT", confidence="MEDIUM", confidence_reason="JWT signing key material"),
    _r(r"\bJWTKeyCollection\s*\(|\bJWTSigners\s*\(|\bjwt\.(?:sign|verify)\s*\(|\.signers\.use\s*\(", _S, "JWTKit", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bapp\.passwords\.use\s*\(\s*\.bcrypt\b|\bBcrypt\.(?:hash|verify)\s*\(|\bBCrypt\.(?:hash|verify)\s*\(", _KDF, "Vapor", algorithm="BCRYPT"),
    _r(r"\bapp\.passwords\.use\s*\(\s*\.plaintext\b", _KDF, "Vapor", algorithm="PLAINTEXT", confidence="HIGH", confidence_reason="plaintext password verifier"),
    # ------------------------------------------------------------ Keychain / misc
    _r(r"\bSecKeyGeneratePair\s*\(", _K, "Security.framework", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bkSecAttrKeySizeInBits\b[^\n]*?\b(1024|2048|3072|4096)\b", _K, "Security.framework", algorithm="RSA", key_from_group=1, confidence="MEDIUM"),
    _r(r"\bkSecAttrKeySizeInBits\b[^\n]*?\b(256|384|521)\b", _K, "Security.framework", algorithm="ECDSA", key_from_group=1, confidence="MEDIUM"),
    _r(r"\bkSecAttrKeySizeInBits\b[^\n]*?\b(128|192)\b", _K, "Security.framework", algorithm="AES", key_from_group=1, confidence="MEDIUM"),
    _r(r"\bRNCryptor\.(?:encrypt|decrypt)\s*\(|\bRNEncryptor\s*\(|\bRNDecryptor\s*\(", _C, "RNCryptor", algorithm="AES", mode="CBC", confidence_reason="RNCryptor v3 format: AES-256-CBC + HMAC-SHA256 + PBKDF2"),
    _r(r"\bRNCryptor\.(?:encrypt|decrypt)\s*\(|\bRNEncryptor\s*\(", _M, "RNCryptor", algorithm="HMAC-SHA256", confidence="MEDIUM"),
    _r(r"\bRNCryptor\.(?:encrypt|decrypt)\s*\(|\bRNEncryptor\s*\(", _KDF, "RNCryptor", algorithm="PBKDF2", confidence="MEDIUM"),
    _r(r"\bSwiftyRSA\b|\bClearMessage\s*\([^\n]*\)\.(?:encrypted|signed)\s*\(|\bEncryptedMessage\s*\([^\n]*\)\.decrypted\s*\(", _S, "SwiftyRSA", algorithm="RSA"),
    _r(r"\bPublicKey\s*\(\s*pemNamed\s*:|\bPrivateKey\s*\(\s*pemNamed\s*:|\bPublicKey\s*\(\s*base64Encoded\s*:", _K, "SwiftyRSA", algorithm="RSA", confidence="MEDIUM"),
    _r(r"\.padding\s*:\s*\.(?:PKCS1|OAEP)\b|\bpadding\s*:\s*\.(?:PKCS1|OAEP)\b", _S, "SwiftyRSA", algorithm="RSA", confidence="MEDIUM"),
    _r(r"\bSecureRandom\.(?:bytes|hex|string)\b|\bRandom\.secure\b", _RNG, "Swift", algorithm="CSPRNG", confidence="MEDIUM"),
]

# `.sha256()` style extensions are only crypto when the file actually deals with
# CryptoSwift / hashing; guard against unrelated `.md5()` naming collisions by
# requiring the library to be imported or a CryptoSwift type to be present.
_CRYPTOSWIFT_HINT = re.compile(r"\bimport\s+CryptoSwift\b|\bDigest\.|\bPKCS5\.|\bblockMode\s*:")
_CRYPTOSWIFT_EXT_RULE = _RULES[[i for i, (_, spec) in enumerate(_RULES) if spec.get("confidence_reason") == "Data/String/Array digest extension"][0]][0]

_FUNC_DECL = re.compile(r"^\s*(?:(?:public|private|internal|fileprivate|open|static|final|override|mutating|@objc)\s+)*(?:func|init)\b[^\n]*", re.M)


def parse_swift_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rules = _RULES
    if not _CRYPTOSWIFT_HINT.search(text):
        rules = [r for r in _RULES if r[0] is not _CRYPTOSWIFT_EXT_RULE]
    findings = run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=text,
        rules=rules,
        language="SWIFT",
        scanner_id=SCANNER_ID,
        confidence_reason="swift-crypto-api",
    )
    findings = filter_prng_context(findings, text, _FUNC_DECL)
    # An UNKNOWN placeholder on a line that also produced a concrete algorithm is noise.
    concrete = {f.source.line_number for f in findings if f.crypto.algorithm != "UNKNOWN"}
    return [f for f in findings if f.crypto.algorithm != "UNKNOWN" or f.source.line_number not in concrete]
