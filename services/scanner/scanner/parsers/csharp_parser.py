"""C# cryptographic API parser (regex, no Roslyn required)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding
from scanner.parsers.rule_engine import filter_prng_context, CIPHER_TOKENS, DIGEST_TOKENS, Rule, run_rules

SCANNER_ID = "static-csharp-scanner-v1.0"

PATTERNS = [
    (re.compile(r"\bAes(?:Gcm|Cng|Managed)?\.Create\s*\("), "CIPHER_INSTANCE", "AES", "ENCRYPTION", None, None),
    (re.compile(r"\bnew\s+AesGcm\s*\("), "CIPHER_INSTANCE", "AES", "ENCRYPTION", "GCM", None),
    (re.compile(r"\bDES(?:CryptoServiceProvider)?\.Create\s*\("), "CIPHER_INSTANCE", "DES", "ENCRYPTION", None, None),
    (re.compile(r"\bTripleDES(?:CryptoServiceProvider)?\.Create\s*\("), "CIPHER_INSTANCE", "3DES", "ENCRYPTION", None, None),
    (re.compile(r"\bRC2(?:CryptoServiceProvider)?\.Create\s*\("), "CIPHER_INSTANCE", "RC2", "ENCRYPTION", None, None),
    (re.compile(r"\bMD5(?:CryptoServiceProvider)?\.Create\s*\("), "MESSAGE_DIGEST", "MD5", "HASHING", None, None),
    (re.compile(r"\bSHA1(?:CryptoServiceProvider|Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-1", "HASHING", None, None),
    (re.compile(r"\bSHA256(?:CryptoServiceProvider|Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-256", "HASHING", None, None),
    (re.compile(r"\bSHA384(?:Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-384", "HASHING", None, None),
    (re.compile(r"\bSHA512(?:Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-512", "HASHING", None, None),
    (re.compile(r"\bHMACSHA256\.Create\s*\("), "MAC", "HMAC-SHA256", "MAC_GENERATION", None, None),
    (re.compile(r"\bHMACSHA1\.Create\s*\("), "MAC", "HMAC-SHA1", "MAC_GENERATION", None, None),
    (re.compile(r"\bHMACSHA384\.Create\s*\("), "MAC", "HMAC-SHA384", "MAC_GENERATION", None, None),
    (re.compile(r"\bHMACSHA512\.Create\s*\("), "MAC", "HMAC-SHA512", "MAC_GENERATION", None, None),
    (re.compile(r"\bnew\s+HMACSHA256\s*\("), "MAC", "HMAC-SHA256", "MAC_GENERATION", None, None),
    (re.compile(r"\bnew\s+HMACSHA1\s*\("), "MAC", "HMAC-SHA1", "MAC_GENERATION", None, None),
    (re.compile(r"\bRSA\.Create\s*\(\s*(\d+)\s*\)"), "KEY_PAIR_GENERATOR", "RSA", "KEY_GENERATION", None, "group1"),
    (re.compile(r"\bRSA\.Create\s*\("), "KEY_PAIR_GENERATOR", "RSA", "KEY_GENERATION", None, None),
    (re.compile(r"\bECDsa\.Create\s*\("), "KEY_PAIR_GENERATOR", "ECDSA", "KEY_GENERATION", None, None),
    (re.compile(r"\bnew\s+Rfc2898DeriveBytes\s*\("), "KEY_GENERATOR", "PBKDF2", "PASSWORD_HASHING", None, None),
    (re.compile(r"\bRandomNumberGenerator\.Create\s*\("), "KEY_GENERATOR", "CSPRNG", "KEY_GENERATION", None, None),
    (re.compile(r"\bnew\s+RNGCryptoServiceProvider\s*\("), "KEY_GENERATOR", "CSPRNG", "KEY_GENERATION", None, None),
]

CIPHERMODE = re.compile(r"CipherMode\.(ECB|CBC|CFB|OFB|CTS)", re.IGNORECASE)
HARDCODED = re.compile(
    r"""(?:Key|IV)\s*=\s*new\s+byte\s*\[\s*\]\s*\{([^}]+)\}""",
    re.IGNORECASE,
)
BCRYPT = re.compile(r"BCrypt\.Net\.BCrypt\.(HashPassword|Verify)\s*\(", re.IGNORECASE)
IDENTITY = re.compile(r"PasswordHasher<\w+>", re.IGNORECASE)
NSEC_AEAD = re.compile(
    r"\b(?:NSec\.Cryptography\.)?(AeadAlgorithm\.(ChaCha20Poly1305|Aes256Gcm|XChaCha20Poly1305)|Aes256Gcm|ChaCha20Poly1305|XChaCha20Poly1305)\b"
)
NSEC_HASH = re.compile(
    r"\b(?:NSec\.Cryptography\.)?(Blake2b|Sha256|Sha512|Sha512256|HmacSha256|HmacSha512|Ed25519|X25519)\b"
)
BOUNCY_ENGINE = re.compile(
    r"\bnew\s+(Org\.BouncyCastle\.Crypto\.(?:Engines\.)?)?(AesEngine|DesEngine|DesEdeEngine|Rc4Engine|RsaEngine|AesFastEngine)\b"
)
BOUNCY_DIGEST = re.compile(
    r"\bnew\s+(Org\.BouncyCastle\.Crypto\.Digests\.)?(MD5Digest|Sha1Digest|Sha256Digest|Sha384Digest|Sha512Digest)\b"
)
BOUNCY_UTIL = re.compile(
    r"\b(?:DigestUtilities\.GetDigest|CipherUtilities\.GetCipher)\s*\(\s*[\"']([^\"']+)[\"']"
)
BOUNCY_TLS = re.compile(r"\bOrg\.BouncyCastle\.Crypto\.Tls\.\w+")
RSA_SIGN = re.compile(r"\b(?:rsa|RSA)\.SignData\s*\(")
HASH_ALG_NAME = re.compile(r"HashAlgorithmName\.(SHA256|SHA384|SHA512|SHA1|MD5)\b")

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_KA = {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_SSC = "System.Security.Cryptography"
_BC = "BouncyCastle"


def _r(pattern: str, base: dict, library: str = _SSC, **extra) -> Rule:
    return re.compile(pattern), {**base, "library": library, **extra}


# Names accepted by HashAlgorithm.Create / SymmetricAlgorithm.Create /
# AsymmetricAlgorithm.Create / CryptoConfig.CreateFromName.
_FACTORY_NAMES = {
    "md5": "MD5", "system.security.cryptography.md5": "MD5",
    "sha": "SHA-1", "sha1": "SHA-1", "sha-1": "SHA-1", "system.security.cryptography.sha1": "SHA-1",
    "sha256": "SHA-256", "sha-256": "SHA-256", "system.security.cryptography.sha256": "SHA-256",
    "sha384": "SHA-384", "sha-384": "SHA-384", "sha512": "SHA-512", "sha-512": "SHA-512",
    "sha3-256": "SHA3-256", "sha3-384": "SHA3-384", "sha3-512": "SHA3-512",
    "ripemd160": "RIPEMD-160", "ripemd-160": "RIPEMD-160",
    "aes": "AES", "rijndael": "AES", "aesmanaged": "AES", "aescryptoserviceprovider": "AES", "system.security.cryptography.aes": "AES",
    "des": "DES", "system.security.cryptography.des": "DES",
    "tripledes": "3DES", "3des": "3DES", "triple des": "3DES", "system.security.cryptography.tripledes": "3DES",
    "rc2": "RC2", "system.security.cryptography.rc2": "RC2",
    "rsa": "RSA", "system.security.cryptography.rsa": "RSA",
    "dsa": "DSA", "system.security.cryptography.dsa": "DSA",
    "ecdsa": "ECDSA", "ecdsacng": "ECDSA", "ecdiffiehellman": "ECDH", "ecdiffiehellmancng": "ECDH",
    "hmacmd5": "HMAC-MD5", "hmacsha1": "HMAC-SHA1", "hmacsha256": "HMAC-SHA256", "hmacsha384": "HMAC-SHA384", "hmacsha512": "HMAC-SHA512",
    "mactripledes": "3DES", "randomnumbergenerator": "CSPRNG",
}

_RULES: list[Rule] = [
    _r(r"\bEncryptionAlgorithm\.(AES_(?:128|192|256)_(?:CBC|GCM))\b", _C, "aspnet-dataprotection", algo_from_group=1, algo_map={"aes_128_cbc": "AES", "aes_192_cbc": "AES", "aes_256_cbc": "AES", "aes_128_gcm": "AES", "aes_192_gcm": "AES", "aes_256_gcm": "AES"}),
    _r(r"\bValidationAlgorithm\.(HMACSHA256|HMACSHA512)\b", _M, "aspnet-dataprotection", algo_from_group=1, algo_map={"hmacsha256": "HMAC-SHA256", "hmacsha512": "HMAC-SHA512"}),
    _r(r"\bPasswordHasherOptions\b|\bPasswordHasherCompatibilityMode\.Identity(?:V2|V3)\b|\bnew\s+PasswordHasher<|\bIPasswordHasher<", _KDF, "aspnet-identity", algorithm="PBKDF2", confidence="MEDIUM", confidence_reason="ASP.NET Identity PasswordHasher is PBKDF2-HMAC"),
    _r(r"\bDangerousAcceptAnyServerCertificateValidator\b", _TLS, "System.Net.Http", algorithm="TLS-CERT-NONE", confidence="HIGH", confidence_reason="certificate validation disabled"),
    _r(r"\bSslProtocols\.(Ssl2|Ssl3|Tls|Tls11|Tls12|Tls13|Default|None)\b", _TLS, "System.Security.Authentication", algo_from_group=1, algo_map={"ssl2": "SSLv2", "ssl3": "SSLv3", "tls": "TLS1.0", "tls11": "TLS1.1", "tls12": "TLS1.2", "tls13": "TLS1.3", "default": "TLS", "none": "TLS"}),
    # --- symmetric providers / classes
    _r(r"\bnew\s+(?:Aes(?:Managed|CryptoServiceProvider|Cng|Ccm|Gcm)|Rijndael(?:Managed)?)\s*\(|\bRijndael(?:Managed)?\.Create\s*\(", _C, algorithm="AES"),
    _r(r"\bnew\s+AesGcm\s*\(|\bnew\s+AesCcm\s*\(", _C, algorithm="AES", mode="GCM"),
    _r(r"\bnew\s+(?:System\.)?Random\s*\(", _RNG, "System", algorithm="PRNG", confidence="MEDIUM", confidence_reason="System.Random used for security material; not a CSPRNG"),
    _r(r"\bnew\s+(?:TripleDESCryptoServiceProvider|TripleDESCng|MACTripleDES)\s*\(", _C, algorithm="3DES"),
    _r(r"\bnew\s+DESCryptoServiceProvider\s*\(", _C, algorithm="DES"),
    _r(r"\bnew\s+RC2CryptoServiceProvider\s*\(", _C, algorithm="RC2"),
    _r(r"\bnew\s+ChaCha20Poly1305\s*\(|\bChaCha20Poly1305\.IsSupported\b", _C, algorithm="ChaCha20-Poly1305"),
    _r(r"\bnew\s+(?:MD5CryptoServiceProvider|MD5Cng)\s*\(|\bMD5\.HashData\s*\(", _D, algorithm="MD5"),
    _r(r"\bnew\s+(?:SHA1CryptoServiceProvider|SHA1Managed|SHA1Cng)\s*\(|\bSHA1\.HashData\s*\(", _D, algorithm="SHA-1"),
    _r(r"\bnew\s+(?:SHA256CryptoServiceProvider|SHA256Managed|SHA256Cng)\s*\(|\bSHA256\.HashData\s*\(", _D, algorithm="SHA-256"),
    _r(r"\bnew\s+(?:SHA384CryptoServiceProvider|SHA384Managed|SHA384Cng)\s*\(|\bSHA384\.HashData\s*\(", _D, algorithm="SHA-384"),
    _r(r"\bnew\s+(?:SHA512CryptoServiceProvider|SHA512Managed|SHA512Cng)\s*\(|\bSHA512\.HashData\s*\(", _D, algorithm="SHA-512"),
    _r(r"\bSHA3_(256|384|512)\.(?:Create|HashData|IsSupported)\b", _D, algorithm="SHA3-256"),
    _r(r"\bnew\s+RIPEMD160Managed\s*\(|\bRIPEMD160\.Create\s*\(", _D, algorithm="RIPEMD-160"),
    _r(r"\bnew\s+HMAC(MD5|SHA1|SHA256|SHA384|SHA512|RIPEMD160)\s*\(|\bHMAC(MD5|SHA1|SHA256|SHA384|SHA512)\.(?:Create|HashData)\s*\(", _M, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bHMAC(?:SHA1|SHA256|SHA384|SHA512|MD5)\.HashData\s*\(", _M, algorithm="HMAC"),
    _r(r"\bnew\s+HMACSHA384\s*\(", _D, algorithm="SHA-384"),
    _r(r"\bnew\s+HMACSHA512\s*\(", _D, algorithm="SHA-512"),
    _r(r"\bnew\s+HMACMD5\s*\(", _D, algorithm="MD5"),
    _r(r"\bnew\s+HMACSHA1\s*\(", _D, algorithm="SHA-1"),
    _r(r"\bnew\s+HMACSHA256\s*\(", _D, algorithm="SHA-256"),
    _r(r"\bnew\s+AesCmac\s*\(|\bnew\s+CMac\s*\(", _M, algorithm="CMAC"),
    # --- asymmetric
    _r(r"\bnew\s+RSACryptoServiceProvider\s*\(\s*(\d+)", _K, algorithm="RSA", key_from_group=1),
    _r(r"\bnew\s+(?:RSACryptoServiceProvider|RSACng|RSAOpenSsl)\s*\(|\bRSA(?:Cng|OpenSsl)?\.Create\s*\(|\bRSA\.ImportFromPem\b|\bnew\s+RSAParameters\b", _K, algorithm="RSA"),
    _r(r"\bRSA(?:Encryption|Signature)Padding\.(Pkcs1|OaepSHA1|OaepSHA256|OaepSHA384|OaepSHA512|Pss)\b", _K, algorithm="RSA", emit_digest_group=1),
    _r(r"\bRSAEncryptionPadding\.OaepSHA1\b", _D, algorithm="SHA-1", confidence="MEDIUM"),
    _r(r"\bRSAEncryptionPadding\.OaepSHA256\b", _D, algorithm="SHA-256", confidence="MEDIUM"),
    _r(r"\bRSAEncryptionPadding\.OaepSHA384\b", _D, algorithm="SHA-384", confidence="MEDIUM"),
    _r(r"\bRSAEncryptionPadding\.OaepSHA512\b", _D, algorithm="SHA-512", confidence="MEDIUM"),
    _r(r"\bRSAEncryptionPadding\.Pkcs1\b", _K, algorithm="RSA", padding="PKCS1", confidence_reason="rsa-pkcs1v15-padding"),
    _r(r"\bnew\s+RSAPKCS1(?:Signature|KeyExchange)(?:Formatter|Deformatter)\s*\(|\bnew\s+RSAOAEPKeyExchange(?:Formatter|Deformatter)\s*\(", _K, algorithm="RSA"),
    _r(r"\bDSA\.Create\s*\(\s*(\d+)", _K, algorithm="DSA", key_from_group=1),
    _r(r"\bnew\s+(?:DSACryptoServiceProvider|DSACng|DSAOpenSsl)\s*\(|\bDSA(?:Cng|OpenSsl)?\.Create\s*\(", _K, algorithm="DSA"),
    _r(r"\bnew\s+(?:ECDsaCng|ECDsaOpenSsl)\s*\(|\bECDsa(?:Cng|OpenSsl)?\.Create\s*\(", _S, algorithm="ECDSA"),
    _r(r"\bnew\s+(?:ECDiffieHellmanCng|ECDiffieHellmanOpenSsl)\s*\(|\bECDiffieHellman(?:Cng|OpenSsl)?\.Create\s*\(", _KA, algorithm="ECDH"),
    _r(r"\bECDiffieHellman(?:Cng)?\.Create\s*\(\s*ECCurve\.NamedCurves\.(?:nistP256|nistP384|nistP521|brainpoolP\w+)\b", _KA, algorithm="ECDH", confidence="HIGH"),
    _r(r"(?<!ECDiffieHellman.Create\()(?<!ECDiffieHellmanCng.Create\()\bECCurve\.NamedCurves\.(?:nistP256|nistP384|nistP521|brainpoolP\w+)\b(?![^\n]*ECDiffieHellman)", _S, algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bIncrementalHash\.CreateHMAC\s*\(", _M, algorithm="HMAC", confidence="HIGH"),
    _r(r"\bCngAlgorithm\.(ECDsaP256|ECDsaP384|ECDsaP521|ECDiffieHellmanP256|ECDiffieHellmanP384|ECDiffieHellmanP521|Rsa|MD5|Sha1|Sha256|Sha384|Sha512)\b", _K, algo_from_group=1,
       algo_map={"ecdsap256": "ECDSA", "ecdsap384": "ECDSA", "ecdsap521": "ECDSA", "ecdiffiehellmanp256": "ECDH", "ecdiffiehellmanp384": "ECDH", "ecdiffiehellmanp521": "ECDH", "rsa": "RSA", "md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}),
    _r(r"\bCngKey\.Create\s*\(", _K, algorithm="UNKNOWN", confidence="LOW"),
    # --- key derivation / password hashing
    _r(r"\bRfc2898DeriveBytes\.Pbkdf2\s*\(|\bnew\s+Rfc2898DeriveBytes\s*\(", _KDF, algorithm="PBKDF2"),
    _r(r"\bnew\s+PasswordDeriveBytes\s*\(", _KDF, algorithm="PBKDF1"),
    _r(r"\bKeyDerivation\.Pbkdf2\s*\(|\bKeyDerivationPrf\.HMACSHA(1|256|512)\b", _KDF, "Microsoft.AspNetCore.Cryptography.KeyDerivation", algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bHKDF\.(?:DeriveKey|Extract|Expand)\s*\(", _KDF, algorithm="HKDF", purpose="KEY_GENERATION"),
    _r(r"\bSCrypt\.(?:ComputeDerivedKey|Hash)\s*\(|\bScryptEncoder\b|\bScrypt\.Net\b", _KDF, "Scrypt.NET", algorithm="SCRYPT"),
    _r(r"\bArgon2(?:id|i|d)?\s*\(|\bnew\s+Argon2(?:id|i|d)\s*\(|\bKonscious\.Security\.Cryptography\b|\bIsopoh\.Cryptography\.Argon2\b|\bArgon2\.Hash\s*\(", _KDF, "Argon2", algorithm="ARGON2"),
    _r(r"\bBCrypt\.(?:HashPassword|Verify|EnhancedHashPassword|EnhancedVerify|GenerateSalt)\s*\(", _KDF, "BCrypt.Net", algorithm="BCRYPT"),
    _r(r"\bnew\s+PasswordHasher<", _KDF, "ASP.NET Identity", algorithm="PBKDF2", confidence="MEDIUM"),
    _r(r"\bFormsAuthentication\.HashPasswordForStoringInConfigFile\s*\([^,]+,\s*\"(MD5|SHA1)\"", _D, "System.Web", algo_from_group=1, algo_map=DIGEST_TOKENS),
    # --- randomness
    _r(r"\bRandomNumberGenerator\.(?:GetBytes|Fill|GetInt32|Create|GetHexString|GetString|GetItems|Shuffle)\s*\(|\bnew\s+RNGCryptoServiceProvider\s*\(|\bRNGCryptoServiceProvider\.Create\b", _RNG, algorithm="CSPRNG", confidence="MEDIUM"),
    # --- JWT / tokens / data protection
    _r(r"\bSecurityAlgorithms\.(HmacSha256|HmacSha384|HmacSha512|RsaSha256|RsaSha384|RsaSha512|EcdsaSha256|EcdsaSha384|EcdsaSha512|RsaSsaPssSha256|Aes128CbcHmacSha256|Aes256CbcHmacSha512|Aes128KW|Aes256KW|RsaOAEP|RsaPKCS1|Aes128Gcm|Aes256Gcm)(?:Signature)?\b", _S, "Microsoft.IdentityModel", algo_from_group=1,
       algo_map={"hmacsha256": "HS256", "hmacsha384": "HS384", "hmacsha512": "HS512", "rsasha256": "RS256", "rsasha384": "RS384", "rsasha512": "RS512", "ecdsasha256": "ES256", "ecdsasha384": "ES384", "ecdsasha512": "ES512", "rsassapsssha256": "PS256", "aes128cbchmacsha256": "AES", "aes256cbchmacsha512": "AES", "aes128kw": "AES", "aes256kw": "AES", "rsaoaep": "RSA", "rsapkcs1": "RSA", "aes128gcm": "AES", "aes256gcm": "AES"}),
    _r(r"\bnew\s+JwtSecurityTokenHandler\s*\(|\bnew\s+JsonWebTokenHandler\s*\(|\bJwtBuilder\.Create\s*\(|\bnew\s+SigningCredentials\s*\(|\bJwt\.(?:Encode|Decode)\b|\bJwtBearer\b", _S, "Microsoft.IdentityModel", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bnew\s+SymmetricSecurityKey\s*\(", _M, "Microsoft.IdentityModel", algorithm="HMAC", confidence="MEDIUM"),
    _r(r"\bMachineKey\.(?:Protect|Unprotect)\s*\(|\bIDataProtector\b|\bCreateProtector\s*\(|\bDataProtectionProvider\.Create\s*\(", _C, "DataProtection", algorithm="AES", mode="CBC", confidence="MEDIUM"),
    _r(r"\bProtectedData\.(?:Protect|Unprotect)\s*\(|\bDataProtectionScope\.\w+", _C, "DPAPI", algorithm="DPAPI", confidence="MEDIUM"),
    # --- TLS / certificates
    _r(r"\bSecurityProtocolType\.Ssl3\b", _TLS, "System.Net", algorithm="SSLv3"),
    _r(r"\bSecurityProtocolType\.Tls\b(?!1)", _TLS, "System.Net", algorithm="TLS1.0"),
    _r(r"\bSecurityProtocolType\.Tls11\b", _TLS, "System.Net", algorithm="TLS1.1"),
    _r(r"\bSecurityProtocolType\.Tls12\b", _TLS, "System.Net", algorithm="TLS1.2"),
    _r(r"\bSecurityProtocolType\.Tls13\b", _TLS, "System.Net", algorithm="TLS1.3"),
    _r(r"\bSecurityProtocolType\.SystemDefault\b|\bServicePointManager\.SecurityProtocol\b|\bSslProtocols\.(?:None|Default|Tls|Tls11|Tls12|Tls13|Ssl2|Ssl3)\b|\bnew\s+SslStream\s*\(|\bAuthenticateAsClient(?:Async)?\s*\(|\bAuthenticateAsServer(?:Async)?\s*\(|\bSslClientAuthenticationOptions\b", _TLS, "System.Net", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bSslProtocols\.Ssl2\b", _TLS, "System.Net", algorithm="SSLv2"),
    _r(r"\bSslProtocols\.Ssl3\b", _TLS, "System.Net", algorithm="SSLv3"),
    _r(r"\bSslProtocols\.Tls\b(?!1)", _TLS, "System.Net", algorithm="TLS1.0"),
    _r(r"\bSslProtocols\.Tls11\b", _TLS, "System.Net", algorithm="TLS1.1"),
    _r(r"\bServerCertificateValidationCallback\s*=\s*(?:\([^)]*\)|\w+)\s*=>\s*true\b|\bServerCertificateCustomValidationCallback\s*=\s*(?:\([^)]*\)|\w+)\s*=>\s*true\b|\bDangerousAcceptAnyServerCertificateValidator\b|\bRemoteCertificateValidationCallback\s*\(\s*(?:\([^)]*\)|\w+)\s*=>\s*true\b", _TLS, "System.Net", algorithm="TLS-CERT-NONE", confidence_reason="certificate validation disabled"),
    _r(r"\bnew\s+X509Certificate2?\s*\(|\bX509Certificate2?\.CreateFrom\w+\(|\bnew\s+X509Store\s*\(|\bnew\s+X509Chain\s*\(|\bnew\s+CertificateRequest\s*\(|\bX509Certificate2\.CreateFromPem\b", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "System.Security.Cryptography.X509Certificates", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bnew\s+SshClient\s*\(|\bnew\s+SftpClient\s*\(|\bnew\s+PrivateKeyFile\s*\(|\bRenci\.SshNet\b", _TLS, "SSH.NET", algorithm="SSH", confidence="MEDIUM"),
    # --- BouncyCastle (C#)
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Engines\.)?(AesEngine|AesFastEngine|AesLightEngine|RijndaelEngine|DesEngine|DesEdeEngine|RC2Engine|RC4Engine|Rc4Engine|RC532Engine|RC564Engine|RC6Engine|BlowfishEngine|TwofishEngine|SerpentEngine|CamelliaEngine|Cast5Engine|Cast6Engine|IdeaEngine|SeedEngine|Salsa20Engine|XSalsa20Engine|ChaChaEngine|ChaCha7539Engine|RsaEngine|RsaBlindedEngine|ElGamalEngine|NaccacheSternEngine|Gost28147Engine|NoekeonEngine|SkipjackEngine|TeaEngine|XteaEngine|ThreefishEngine|Sm4Engine)\b", _C, _BC, algo_from_group=1,
       algo_map={"aesengine": "AES", "aesfastengine": "AES", "aeslightengine": "AES", "rijndaelengine": "AES", "desengine": "DES", "desedeengine": "3DES", "rc2engine": "RC2", "rc4engine": "RC4", "rc532engine": "RC5", "rc564engine": "RC5", "rc6engine": "RC6", "blowfishengine": "Blowfish", "twofishengine": "Twofish", "serpentengine": "Serpent", "camelliaengine": "Camellia", "cast5engine": "CAST5", "cast6engine": "CAST6", "ideaengine": "IDEA", "seedengine": "SEED", "salsa20engine": "Salsa20", "xsalsa20engine": "XSalsa20", "chachaengine": "ChaCha20", "chacha7539engine": "ChaCha20", "rsaengine": "RSA", "rsablindedengine": "RSA", "elgamalengine": "ElGamal", "naccachesternengine": "NaccacheStern", "gost28147engine": "GOST28147", "noekeonengine": "Noekeon", "skipjackengine": "Skipjack", "teaengine": "TEA", "xteaengine": "XTEA", "threefishengine": "Threefish", "sm4engine": "SM4"}),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Modes\.)?(GcmBlockCipher|CcmBlockCipher|EaxBlockCipher|OcbBlockCipher|CbcBlockCipher|CfbBlockCipher|OfbBlockCipher|SicBlockCipher|KCcmBlockCipher|ChaCha20Poly1305)\s*\(", _C, _BC, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Digests\.)?(MD2Digest|MD4Digest|MD5Digest|Sha1Digest|Sha224Digest|Sha256Digest|Sha384Digest|Sha512Digest|Sha512tDigest|Sha3Digest|ShakeDigest|KeccakDigest|RipeMD128Digest|RipeMD160Digest|RipeMD256Digest|WhirlpoolDigest|TigerDigest|Gost3411Digest|Blake2bDigest|Blake2sDigest|Blake3Digest|SM3Digest)\b", _D, _BC, algo_from_group=1,
       algo_map={"md2digest": "MD2", "md4digest": "MD4", "md5digest": "MD5", "sha1digest": "SHA-1", "sha224digest": "SHA-224", "sha256digest": "SHA-256", "sha384digest": "SHA-384", "sha512digest": "SHA-512", "sha512tdigest": "SHA-512", "sha3digest": "SHA3-256", "shakedigest": "SHAKE", "keccakdigest": "SHA3-256", "ripemd128digest": "RIPEMD-128", "ripemd160digest": "RIPEMD-160", "ripemd256digest": "RIPEMD-256", "whirlpooldigest": "WHIRLPOOL", "tigerdigest": "TIGER", "gost3411digest": "GOST3411", "blake2bdigest": "BLAKE2b", "blake2sdigest": "BLAKE2s", "blake3digest": "BLAKE3", "sm3digest": "SM3"}),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Macs\.)?HMac\s*\(\s*new\s+(\w+Digest)\b", _M, _BC, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Macs\.)?(?:HMac|CMac|CbcBlockCipherMac|GMac|Poly1305|SipHash)\s*\(", _M, _BC, algorithm="HMAC", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Generators\.)?(RsaKeyPairGenerator|DsaKeyPairGenerator|ECKeyPairGenerator|DHKeyPairGenerator|ElGamalKeyPairGenerator|Ed25519KeyPairGenerator|Ed448KeyPairGenerator|X25519KeyPairGenerator|X448KeyPairGenerator|Pkcs5S2ParametersGenerator|Pkcs12ParametersGenerator|OpenSslPbeParametersGenerator|Argon2BytesGenerator|SCrypt|BCrypt|HkdfBytesGenerator|Kdf1BytesGenerator|Kdf2BytesGenerator|KyberKeyPairGenerator|DilithiumKeyPairGenerator|SphincsPlusKeyPairGenerator|MLKemKeyPairGenerator|MLDsaKeyPairGenerator|SlhDsaKeyPairGenerator)\b", _K, _BC, algo_from_group=1,
       algo_map={"rsakeypairgenerator": "RSA", "dsakeypairgenerator": "DSA", "eckeypairgenerator": "ECDSA", "dhkeypairgenerator": "DH", "elgamalkeypairgenerator": "ElGamal", "ed25519keypairgenerator": "Ed25519", "ed448keypairgenerator": "Ed448", "x25519keypairgenerator": "X25519", "x448keypairgenerator": "X448", "pkcs5s2parametersgenerator": "PBKDF2", "pkcs12parametersgenerator": "PKCS12-KDF", "opensslpbeparametersgenerator": "EVP_BytesToKey", "argon2bytesgenerator": "ARGON2", "scrypt": "SCRYPT", "bcrypt": "BCRYPT", "hkdfbytesgenerator": "HKDF", "kdf1bytesgenerator": "KDF1", "kdf2bytesgenerator": "KDF2", "kyberkeypairgenerator": "ML-KEM", "dilithiumkeypairgenerator": "ML-DSA", "sphincspluskeypairgenerator": "SLH-DSA", "mlkemkeypairgenerator": "ML-KEM", "mldsakeypairgenerator": "ML-DSA", "slhdsakeypairgenerator": "SLH-DSA"}),
    _r(r"\bGeneratorUtilities\.GetKeyPairGenerator\s*\(\s*\"(RSA|DSA|EC|ECDSA|ECDH|DH|ElGamal|Ed25519|X25519)\"", _K, _BC, algo_from_group=1,
       algo_map={"rsa": "RSA", "dsa": "DSA", "ec": "ECDSA", "ecdsa": "ECDSA", "ecdh": "ECDH", "dh": "DH", "elgamal": "ElGamal", "ed25519": "Ed25519", "x25519": "X25519"}),
    _r(r"\bSignerUtilities\.GetSigner\s*\(\s*\"([A-Za-z0-9-]+)with([A-Za-z0-9]+)\"", _S, _BC, algo_from_group=2, algo_map={"rsa": "RSA", "ecdsa": "ECDSA", "dsa": "DSA", "rsaandmgf1": "RSA", "ed25519": "Ed25519", "plain-ecdsa": "ECDSA"}, emit_digest_group=1),
    _r(r"\bSignerUtilities\.GetSigner\s*\(\s*\"(SHA-?1|SHA-?256|SHA-?384|SHA-?512|MD5)with", _D, _BC, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bDigestUtilities\.GetDigest\s*\(\s*\"([A-Za-z0-9-]+)\"", _D, _BC, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bDigestUtilities\.CalculateDigest\s*\(\s*\"([A-Za-z0-9-]+)\"", _D, _BC, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bMacUtilities\.GetMac\s*\(\s*\"HMAC-?([A-Za-z0-9-]+)\"", _M, _BC, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCipherUtilities\.GetCipher\s*\(\s*\"([A-Za-z0-9]+)(?:/[^\"]*)?\"", _C, _BC, algo_from_group=1,
       algo_map={**CIPHER_TOKENS, "desede": "3DES", "rsa": "RSA", "elgamal": "ElGamal", "ecies": "ECIES", "rijndael": "AES"}),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Security\.)?SecureRandom\s*\(|\bSecureRandom\.GetInstance\s*\(", _RNG, _BC, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.Crypto\.Prng\.)?(?:VmpcRandomGenerator|DigestRandomGenerator|ThreadedSeedGenerator)\s*\(", _RNG, _BC, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bOrg\.BouncyCastle\.(?:Tls|Crypto\.Tls)\.\w+|\bnew\s+TlsClientProtocol\s*\(|\bnew\s+TlsServerProtocol\s*\(", _TLS, _BC, algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:Org\.BouncyCastle\.OpenSsl\.)?PemReader\s*\(|\bnew\s+PemWriter\s*\(|\bX509CertificateParser\b|\bnew\s+X509V3CertificateGenerator\s*\(", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, _BC, algorithm="X509", confidence="MEDIUM"),
    # --- libsodium / NSec bindings
    _r(r"\bSodium\.SecretBox\.(?:Create|Open)\b|\bSecretBox\.(?:Create|Open|GenerateKey)\s*\(", _C, "libsodium-net", algorithm="XSalsa20-Poly1305"),
    _r(r"\bSodium\.SecretAead(?:ChaCha20Poly1305|XChaCha20Poly1305)?\.(?:Encrypt|Decrypt)\b|\bSecretAeadChaCha20Poly1305\.(?:Encrypt|Decrypt)\b", _C, "libsodium-net", algorithm="ChaCha20-Poly1305"),
    _r(r"\bSodium\.SecretAeadAes\.(?:Encrypt|Decrypt)\b", _C, "libsodium-net", algorithm="AES", mode="GCM"),
    _r(r"\bSodium\.PublicKeyAuth\.\w+|\bPublicKeyAuth\.(?:GenerateKeyPair|Sign|Verify|SignDetached)\b", _S, "libsodium-net", algorithm="Ed25519"),
    _r(r"\bSodium\.PublicKeyBox\.\w+|\bPublicKeyBox\.(?:GenerateKeyPair|Create|Open)\b", _C, "libsodium-net", algorithm="X25519"),
    _r(r"\bSodium\.PasswordHash\.(?:ArgonHashString|ArgonHashBinary|ScryptHashString|ScryptHashBinary)\b|\bPasswordHash\.Argon\w+\(", _KDF, "libsodium-net", algorithm="ARGON2"),
    _r(r"\bPasswordHash\.Scrypt\w+\(", _KDF, "libsodium-net", algorithm="SCRYPT"),
    _r(r"\bSodium\.GenericHash\.\w+|\bGenericHash\.Hash\s*\(", _D, "libsodium-net", algorithm="BLAKE2b"),
    _r(r"\bSodium\.CryptoHash\.Sha256\b|\bCryptoHash\.Sha256\s*\(", _D, "libsodium-net", algorithm="SHA-256"),
    _r(r"\bSodium\.CryptoHash\.Sha512\b|\bCryptoHash\.Sha512\s*\(", _D, "libsodium-net", algorithm="SHA-512"),
    _r(r"\bSodium\.SecretKeyAuth\.\w+|\bSecretKeyAuth\.(?:Sign|Verify)\w*\(", _M, "libsodium-net", algorithm="HMAC"),
    _r(r"\bSodium\.ScalarMult\.\w+|\bScalarMult\.(?:Base|Mult)\s*\(", _KA, "libsodium-net", algorithm="X25519"),
    _r(r"\bSodiumCore\.GetRandomBytes\s*\(|\bSodium\.SodiumCore\.GetRandomBytes\b|\bRandomBytes\.Buf\w*\(", _RNG, "libsodium-net", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bSignatureAlgorithm\.Ed25519\b|\bKeyAgreementAlgorithm\.X25519\b|\bAeadAlgorithm\.Aes256Gcm\b|\bAeadAlgorithm\.(?:X)?ChaCha20Poly1305\b|\bHashAlgorithm\.(?:Sha256|Sha512|Blake2b_\d+)\b|\bMacAlgorithm\.(?:HmacSha256|HmacSha512|Blake2b_\d+)\b|\bKeyDerivationAlgorithm\.(?:HkdfSha256|HkdfSha512)\b|\bPasswordBasedKeyDerivationAlgorithm\.(?:Argon2id|Scrypt)\b", _C, "NSec", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bKeyDerivationAlgorithm\.HkdfSha(256|512)\b", _KDF, "NSec", algorithm="HKDF", emit_digest_group=1, purpose="KEY_GENERATION"),
    _r(r"\bPasswordBasedKeyDerivationAlgorithm\.Argon2id\b", _KDF, "NSec", algorithm="ARGON2"),
    _r(r"\bPasswordBasedKeyDerivationAlgorithm\.Scrypt\b", _KDF, "NSec", algorithm="SCRYPT"),
    # --- weak RNG in key contexts (LOW; only when the result is obviously key material)
    _r(r"\b(?:key|iv|salt|nonce|token|secret|password)\w*\s*=\s*[^;]*\bnew\s+(?:System\.)?Random\s*\(", _RNG, "System", algorithm="PRNG", confidence="MEDIUM", confidence_reason="System.Random is not a CSPRNG; use RandomNumberGenerator"),
]
_ALL_RULES = [(re.compile(p.pattern, p.flags | re.M), s) for p, s in _RULES]

_STRING_CONST = re.compile(r"\b(?:var|string|String|const\s+string|readonly\s+string|static\s+string|private\s+string|public\s+string)\s+(\w+)\s*=\s*\"([^\"]{1,64})\"\s*;")
_FACTORY_CALL = re.compile(
    r"\b(HashAlgorithm|SymmetricAlgorithm|AsymmetricAlgorithm|KeyedHashAlgorithm|HMAC|CryptoConfig)\.(Create|CreateFromName)\s*\(\s*(?:\"([^\"]+)\"|(\w+))\s*[,)]"
)


def _factory_findings(source: str, file_path: Path, repo_root: Path | None) -> list[RawFinding]:
    """``HashAlgorithm.Create("SHA1")`` / ``SymmetricAlgorithm.Create(name)`` where
    ``name`` is a string constant declared in the same file."""
    consts = {m.group(1): m.group(2) for m in _STRING_CONST.finditer(source)}
    out: list[RawFinding] = []
    for m in _FACTORY_CALL.finditer(source):
        raw = m.group(3) or consts.get(m.group(4) or "")
        if not raw:
            continue
        algo = _FACTORY_NAMES.get(raw.strip().lower())
        if not algo:
            continue
        if m.group(1) == "HMAC" or algo.startswith("HMAC"):
            api_type, purpose = "MAC", "MAC_GENERATION"
        elif algo in {"AES", "DES", "3DES", "RC2"}:
            api_type, purpose = "CIPHER_INSTANCE", "ENCRYPTION"
        elif algo in {"RSA", "DSA", "ECDSA", "ECDH"}:
            api_type, purpose = "KEY_PAIR_GENERATOR", "KEY_GENERATION"
        elif algo == "CSPRNG":
            api_type, purpose = "KEY_GENERATOR", "KEY_GENERATION"
        else:
            api_type, purpose = "MESSAGE_DIGEST", "HASHING"
        out.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=source[: m.start()].count("\n") + 1,
                language="CSHARP",
                scanner_id=SCANNER_ID,
                library=_SSC,
                api_type=api_type,
                algorithm=algo,
                purpose=purpose,
                confidence="HIGH" if m.group(3) else "MEDIUM",
                confidence_reason="algorithm-factory-by-name" if m.group(3) else "algorithm-factory-name-resolved-from-local-constant",
                raw_transformation=m.group(0)[:80],
            )
        )
    return out


def parse_csharp_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw_source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_c_like_comments

    source = strip_c_like_comments(raw_source)
    findings: list[RawFinding] = []

    def add(match: re.Match, **kwargs) -> None:
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=source[: match.start()].count("\n") + 1,
                language="CSHARP",
                scanner_id=SCANNER_ID,
                library="System.Security.Cryptography",
                **kwargs,
            )
        )

    claimed: set[int] = set()
    for pattern, api_type, algorithm, purpose, mode, key_flag in PATTERNS:
        for match in pattern.finditer(source):
            if match.start() in claimed:
                continue
            key_size = None
            if key_flag == "group1" and match.lastindex:
                try:
                    key_size = int(match.group(1))
                except (TypeError, ValueError):
                    key_size = None
            claimed.add(match.start())
            add(
                match,
                api_type=api_type,
                algorithm=algorithm,
                purpose=purpose,
                mode=mode,
                key_size=key_size,
            )
    for match in CIPHERMODE.finditer(source):
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm="AES",
            purpose="ENCRYPTION",
            mode=match.group(1).upper(),
            confidence="MEDIUM",
            confidence_reason="CipherMode assignment",
        )
    for match in HARDCODED.finditer(source):
        raw = match.group(1)
        length = len([part for part in raw.split(",") if part.strip()])
        add(
            match,
            api_type="HARDCODED_KEY",
            algorithm="UNKNOWN",
            purpose="KEY_GENERATION",
            is_hardcoded_key=True,
            hardcoded_key_length=length,
            confidence="HIGH",
            confidence_reason="byte-array Key/IV initializer",
        )
    for match in BCRYPT.finditer(source):
        add(
            match,
            api_type="KEY_GENERATOR",
            algorithm="BCRYPT",
            purpose="PASSWORD_HASHING",
        )
        findings[-1].metadata.library = "BCrypt.Net"
    for match in IDENTITY.finditer(source):
        add(
            match,
            api_type="KEY_GENERATOR",
            algorithm="PBKDF2",
            purpose="PASSWORD_HASHING",
            confidence="MEDIUM",
            confidence_reason="ASP.NET Identity password hasher",
        )
        findings[-1].metadata.library = "ASP.NET Identity"
    for match in NSEC_AEAD.finditer(source):
        token = match.group(0)
        algorithm = "AES"
        mode = "GCM"
        if "ChaCha20" in token:
            algorithm = "ChaCha20-Poly1305"
            mode = None
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algorithm,
            mode=mode,
            purpose="ENCRYPTION",
        )
        findings[-1].metadata.library = "NSec"
    for match in NSEC_HASH.finditer(source):
        name = match.group(1)
        mapping = {
            "Blake2b": ("MESSAGE_DIGEST", "BLAKE2b", "HASHING"),
            "Sha256": ("MESSAGE_DIGEST", "SHA-256", "HASHING"),
            "Sha512": ("MESSAGE_DIGEST", "SHA-512", "HASHING"),
            "Sha512256": ("MESSAGE_DIGEST", "SHA-512/256", "HASHING"),
            "HmacSha256": ("MAC", "HMAC-SHA256", "MAC_GENERATION"),
            "HmacSha512": ("MAC", "HMAC-SHA512", "MAC_GENERATION"),
            "Ed25519": ("SIGNATURE", "Ed25519", "SIGNING"),
            "X25519": ("KEY_PAIR_GENERATOR", "X25519", "KEY_EXCHANGE"),
        }
        api_type, algorithm, purpose = mapping.get(name, ("MESSAGE_DIGEST", name.upper(), "HASHING"))
        add(match, api_type=api_type, algorithm=algorithm, purpose=purpose)
        findings[-1].metadata.library = "NSec"
    for match in BOUNCY_ENGINE.finditer(source):
        name = match.group(2)
        mapping = {
            "AesEngine": ("AES", "ENCRYPTION", "CIPHER_INSTANCE"),
            "AesFastEngine": ("AES", "ENCRYPTION", "CIPHER_INSTANCE"),
            "DesEngine": ("DES", "ENCRYPTION", "CIPHER_INSTANCE"),
            "DesEdeEngine": ("3DES", "ENCRYPTION", "CIPHER_INSTANCE"),
            "Rc4Engine": ("RC4", "ENCRYPTION", "CIPHER_INSTANCE"),
            "RsaEngine": ("RSA", "ENCRYPTION", "CIPHER_INSTANCE"),
        }
        algorithm, purpose, api_type = mapping.get(name, (name, "ENCRYPTION", "CIPHER_INSTANCE"))
        add(match, api_type=api_type, algorithm=algorithm, purpose=purpose)
        findings[-1].metadata.library = "BouncyCastle"
    for match in BOUNCY_DIGEST.finditer(source):
        name = match.group(2)
        mapping = {
            "MD5Digest": "MD5",
            "Sha1Digest": "SHA-1",
            "Sha256Digest": "SHA-256",
            "Sha384Digest": "SHA-384",
            "Sha512Digest": "SHA-512",
        }
        add(match, api_type="MESSAGE_DIGEST", algorithm=mapping.get(name, name), purpose="HASHING")
        findings[-1].metadata.library = "BouncyCastle"
    for match in BOUNCY_UTIL.finditer(source):
        raw = match.group(1).upper()
        algo = "AES" if "AES" in raw else ("MD5" if "MD5" in raw else ("SHA-1" if "SHA1" in raw or "SHA-1" in raw else raw))
        purpose = "HASHING" if "MD" in raw or "SHA" in raw else "ENCRYPTION"
        add(
            match,
            api_type="MESSAGE_DIGEST" if purpose == "HASHING" else "CIPHER_INSTANCE",
            algorithm=algo,
            purpose=purpose,
        )
        findings[-1].metadata.library = "BouncyCastle"
    for match in BOUNCY_TLS.finditer(source):
        add(match, api_type="KEY_AGREEMENT", algorithm="TLS", purpose="KEY_EXCHANGE")
        findings[-1].metadata.library = "BouncyCastle"
    for match in RSA_SIGN.finditer(source):
        add(match, api_type="SIGNATURE", algorithm="RSA", purpose="SIGNING")
    for match in HASH_ALG_NAME.finditer(source):
        name = match.group(1)
        mapped = {"SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "SHA1": "SHA-1", "MD5": "MD5"}[name]
        add(match, api_type="MESSAGE_DIGEST", algorithm=mapped, purpose="HASHING", confidence="MEDIUM")
    seen = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
    findings.extend(
        run_rules(
            file_path=file_path,
            repo_root=repo_root,
            text=source,
            rules=_ALL_RULES,
            language="CSHARP",
            scanner_id=SCANNER_ID,
            confidence_reason="dotnet-crypto-api",
            strip_comments=False,
            seen=seen,
        )
    )
    findings.extend(_factory_findings(source, file_path, repo_root))
    return filter_prng_context(findings, source, _CS_METHOD_DECL)


_CS_METHOD_DECL = re.compile(r"^\s*(?:public|private|protected|internal|static|async|override|virtual|\s)*[\w<>\[\],\.\s\?]+\s+\w+\s*\([^;]*$")
