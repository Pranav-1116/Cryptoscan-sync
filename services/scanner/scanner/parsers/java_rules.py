"""Supplementary regex rules for JVM sources (Java / Kotlin / Scala).

The JCA ``getInstance`` family is handled by the token walker in
``java_ast``.  This module covers library APIs that never go through a JCA
string: BouncyCastle lightweight engines/digests/generators, JWT libraries,
password hashers (jBCrypt, argon2-jvm, Spring Security encoders, password4j),
Google Tink, Guava/Commons-Codec digests, Spring ``Encryptors``, OkHttp TLS
versions, Conscrypt/Netty SSL, and reflection-based ``Cipher.getInstance``.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import DIGEST_TOKENS, Rule, run_rules

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_KA = {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_BC = "BouncyCastle"


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.M), {**base, "library": library, **extra}


_BC_ENGINES = {
    "aesengine": "AES", "aesfastengine": "AES", "aeslightengine": "AES", "rijndaelengine": "AES",
    "desengine": "DES", "desedeengine": "3DES", "rc2engine": "RC2", "rc4engine": "RC4", "rc532engine": "RC5",
    "rc564engine": "RC5", "rc6engine": "RC6", "blowfishengine": "Blowfish", "twofishengine": "Twofish",
    "serpentengine": "Serpent", "tnepresengine": "Serpent", "camelliaengine": "Camellia", "camellialightengine": "Camellia",
    "cast5engine": "CAST5", "cast6engine": "CAST6", "ideaengine": "IDEA", "seedengine": "SEED", "salsa20engine": "Salsa20",
    "xsalsa20engine": "XSalsa20", "chachaengine": "ChaCha20", "chacha7539engine": "ChaCha20", "rsaengine": "RSA",
    "rsablindedengine": "RSA", "rsablindingengine": "RSA", "elgamalengine": "ElGamal", "naccachesternengine": "NaccacheStern",
    "gost28147engine": "GOST28147", "noekeonengine": "Noekeon", "skipjackengine": "Skipjack", "teaengine": "TEA",
    "xteaengine": "XTEA", "threefishengine": "Threefish", "sm4engine": "SM4", "sm2engine": "SM2", "ariaengine": "ARIA",
    "grain128engine": "Grain", "hc128engine": "HC-128", "hc256engine": "HC-256", "isaacengine": "ISAAC", "vmpcengine": "VMPC",
    "zuc128engine": "ZUC", "dstu7624engine": "DSTU7624", "shacal2engine": "SHACAL-2", "lea": "LEA",
}
_BC_DIGESTS = {
    "md2digest": "MD2", "md4digest": "MD4", "md5digest": "MD5", "sha1digest": "SHA-1", "sha224digest": "SHA-224",
    "sha256digest": "SHA-256", "sha384digest": "SHA-384", "sha512digest": "SHA-512", "sha512tdigest": "SHA-512",
    "sha3digest": "SHA3-256", "shakedigest": "SHAKE", "keccakdigest": "SHA3-256", "ripemd128digest": "RIPEMD-128",
    "ripemd160digest": "RIPEMD-160", "ripemd256digest": "RIPEMD-256", "ripemd320digest": "RIPEMD-320",
    "whirlpooldigest": "WHIRLPOOL", "tigerdigest": "TIGER", "gost3411digest": "GOST3411", "gost3411_2012_256digest": "GOST3411",
    "blake2bdigest": "BLAKE2b", "blake2sdigest": "BLAKE2s", "blake3digest": "BLAKE3", "sm3digest": "SM3",
    "dstu7564digest": "DSTU7564", "skeindigest": "Skein", "harakadigest": "Haraka", "parallelhash": "SHA3-256", "tuplehash": "SHA3-256",
}
_BC_GENERATORS = {
    "rsakeypairgenerator": "RSA", "dsakeypairgenerator": "DSA", "eckeypairgenerator": "ECDSA", "dhkeypairgenerator": "DH",
    "dhbasickeypairgenerator": "DH", "elgamalkeypairgenerator": "ElGamal", "ed25519keypairgenerator": "Ed25519",
    "ed448keypairgenerator": "Ed448", "x25519keypairgenerator": "X25519", "x448keypairgenerator": "X448",
    "pkcs5s1parametersgenerator": "PBKDF1", "pkcs5s2parametersgenerator": "PBKDF2", "pkcs12parametersgenerator": "PKCS12-KDF",
    "opensslpbeparametersgenerator": "EVP_BytesToKey", "argon2bytesgenerator": "ARGON2", "scrypt": "SCRYPT", "bcrypt": "BCRYPT",
    "openbsdbcrypt": "BCRYPT", "hkdfbytesgenerator": "HKDF", "kdf1bytesgenerator": "KDF1", "kdf2bytesgenerator": "KDF2",
    "kdfcounterbytesgenerator": "KDF-Counter", "kdffeedbackbytesgenerator": "KDF-Feedback", "mgf1bytesgenerator": "MGF1",
    "kyberkeypairgenerator": "ML-KEM", "mlkemkeypairgenerator": "ML-KEM", "dilithiumkeypairgenerator": "ML-DSA",
    "mldsakeypairgenerator": "ML-DSA", "sphincspluskeypairgenerator": "SLH-DSA", "slhdsakeypairgenerator": "SLH-DSA",
    "falconkeypairgenerator": "Falcon", "ntrukeypairgenerator": "NTRU", "frodokeypairgenerator": "FrodoKEM",
    "bikekeypairgenerator": "BIKE", "hqckeypairgenerator": "HQC", "xmsskeypairgenerator": "XMSS", "lmskeypairgenerator": "LMS",
    "gost3410keypairgenerator": "GOST3410", "ecgost3410keypairgenerator": "GOST3410", "sm2keypairgenerator": "SM2",
    "naccachesternkeypairgenerator": "NaccacheStern", "cramershoupkeypairgenerator": "CramerShoup",
}
_BC_SIGNERS = {
    "rsadigestsigner": "RSA", "pssSigner".lower(): "RSA", "iso9796d2signer": "RSA", "x931signer": "RSA", "genericsigner": "RSA",
    "dsasigner": "DSA", "dsadigestsigner": "DSA", "ecdsasigner": "ECDSA", "ecnrsigner": "ECDSA", "ecgost3410signer": "GOST3410",
    "gost3410signer": "GOST3410", "ed25519signer": "Ed25519", "ed25519ctxsigner": "Ed25519", "ed25519phsigner": "Ed25519",
    "ed448signer": "Ed448", "ed448phsigner": "Ed448", "sm2signer": "SM2", "dilithiumsigner": "ML-DSA", "mldsasigner": "ML-DSA",
    "sphincsplussigner": "SLH-DSA", "slhdsasigner": "SLH-DSA", "falconsigner": "Falcon", "xmsssigner": "XMSS", "lmssigner": "LMS",
}
_BC_AGREEMENT = {
    "ecdhbasicagreement": "ECDH", "ecdhcbasicagreement": "ECDH", "ecdhcunifiedagreement": "ECDH", "ecmqvbasicagreement": "ECMQV",
    "dhbasicagreement": "DH", "dhunifiedagreement": "DH", "mqvbasicagreement": "MQV", "x25519agreement": "X25519", "x448agreement": "X448",
    "sm2keyexchange": "SM2", "kyberkemgenerator": "ML-KEM", "mlkemgenerator": "ML-KEM", "ntrukemgenerator": "NTRU", "frodokemgenerator": "FrodoKEM",
}
_JWT_ALGS = {
    "hs256": "HS256", "hs384": "HS384", "hs512": "HS512", "rs256": "RS256", "rs384": "RS384", "rs512": "RS512",
    "es256": "ES256", "es256k": "ES256K", "es384": "ES384", "es512": "ES512", "ps256": "PS256", "ps384": "PS384", "ps512": "PS512",
    "eddsa": "EdDSA", "none": "none",
}
_AUTH0_ALGS = {
    "hmac256": "HS256", "hmac384": "HS384", "hmac512": "HS512", "rsa256": "RS256", "rsa384": "RS384", "rsa512": "RS512",
    "ecdsa256": "ES256", "ecdsa256k": "ES256K", "ecdsa384": "ES384", "ecdsa512": "ES512", "none": "none",
}
_TINK = {
    "aes128_gcm": "AES", "aes256_gcm": "AES", "aes128_gcm_raw": "AES", "aes256_gcm_raw": "AES", "aes128_ctr_hmac_sha256": "AES",
    "aes256_ctr_hmac_sha256": "AES", "aes128_eax": "AES", "aes256_eax": "AES", "aes256_gcm_siv": "AES", "aes128_gcm_siv": "AES",
    "chacha20_poly1305": "ChaCha20-Poly1305", "xchacha20_poly1305": "XChaCha20-Poly1305", "aes256_siv": "AES", "aes_cmac": "CMAC",
    "hmac_sha256_128bittag": "HMAC-SHA256", "hmac_sha256_256bittag": "HMAC-SHA256", "hmac_sha512_256bittag": "HMAC-SHA512",
    "hmac_sha512_512bittag": "HMAC-SHA512", "ecdsa_p256": "ECDSA", "ecdsa_p384": "ECDSA", "ecdsa_p521": "ECDSA", "ecdsa_p256_ieee_p1363": "ECDSA",
    "ed25519": "Ed25519", "rsa_ssa_pkcs1_3072_sha256_f4": "RSA", "rsa_ssa_pkcs1_4096_sha512_f4": "RSA", "rsa_ssa_pss_3072_sha256_sha256_32_f4": "RSA",
    "rsa_ssa_pss_4096_sha512_sha512_64_f4": "RSA", "ecies_p256_hkdf_hmac_sha256_aes128_gcm": "ECIES", "dhkem_x25519_hkdf_sha256_hkdf_sha256_aes_256_gcm": "HPKE",
    "aes128_gcm_hkdf_1mb": "AES", "aes256_gcm_hkdf_1mb": "AES", "aes256_gcm_hkdf_4kb": "AES", "aes128_ctr_hmac_sha256_4kb": "AES",
    "hkdf_sha256": "HKDF", "aes256_siv_raw": "AES", "ml_dsa_65": "ML-DSA", "slh_dsa_sha2_128s": "SLH-DSA", "ml_kem_768": "ML-KEM",
}

RULES: list[Rule] = [
    # ------------------------------------------------------------- BouncyCastle lightweight API
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.engines\.)?(" + "|".join(sorted({k[0].upper() + k[1:] for k in _BC_ENGINES} | {"AESEngine", "AESFastEngine", "AESLightEngine", "DESEngine", "DESedeEngine", "RC2Engine", "RC4Engine", "RC532Engine", "RC564Engine", "RC6Engine", "BlowfishEngine", "TwofishEngine", "SerpentEngine", "CamelliaEngine", "CAST5Engine", "CAST6Engine", "IDEAEngine", "SEEDEngine", "Salsa20Engine", "XSalsa20Engine", "ChaChaEngine", "ChaCha7539Engine", "RSAEngine", "RSABlindedEngine", "ElGamalEngine", "GOST28147Engine", "SM4Engine", "ARIAEngine", "SkipjackEngine", "TEAEngine", "XTEAEngine", "ThreefishEngine", "NoekeonEngine", "HC128Engine", "HC256Engine", "Grain128Engine", "ISAACEngine", "VMPCEngine", "Zuc128Engine", "DSTU7624Engine", "Shacal2Engine"}, key=len, reverse=True)) + r")\s*\(", _C, _BC, algo_from_group=1, algo_map=_BC_ENGINES),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.digests\.)?(MD2Digest|MD4Digest|MD5Digest|SHA1Digest|SHA224Digest|SHA256Digest|SHA384Digest|SHA512Digest|SHA512tDigest|SHA3Digest|SHAKEDigest|KeccakDigest|RIPEMD128Digest|RIPEMD160Digest|RIPEMD256Digest|RIPEMD320Digest|WhirlpoolDigest|TigerDigest|GOST3411Digest|GOST3411_2012_256Digest|Blake2bDigest|Blake2sDigest|Blake3Digest|SM3Digest|DSTU7564Digest|SkeinDigest|HarakaDigest|ParallelHash|TupleHash)\s*\(", _D, _BC, algo_from_group=1, algo_map=_BC_DIGESTS),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.macs\.)?HMac\s*\(\s*new\s+(\w+Digest)\b", _M, _BC, algorithm="HMAC", emit_digest_group=1),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.macs\.)?(HMac|CMac|CBCBlockCipherMac|CFBBlockCipherMac|GMac|KGMac|Poly1305|SipHash|SipHash128|KMAC|Zuc128Mac|Zuc256Mac|GOST28147Mac|DSTU7624Mac|SkeinMac|Blake3Mac|VMPCMac|ISO9797Alg3Mac)\s*\(", _M, _BC, algo_from_group=1,
       algo_map={"hmac": "HMAC", "cmac": "CMAC", "cbcblockciphermac": "CBC-MAC", "cfbblockciphermac": "CFB-MAC", "gmac": "GMAC", "kgmac": "GMAC", "poly1305": "Poly1305", "siphash": "SipHash", "siphash128": "SipHash", "kmac": "KMAC", "zuc128mac": "ZUC", "zuc256mac": "ZUC", "gost28147mac": "GOST28147", "dstu7624mac": "DSTU7624", "skeinmac": "Skein", "blake3mac": "BLAKE3", "vmpcmac": "VMPC", "iso9797alg3mac": "3DES"}),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.(?:generators|pqc\.crypto\.\w+)\.)?(" + "|".join(sorted({"RSAKeyPairGenerator", "DSAKeyPairGenerator", "ECKeyPairGenerator", "DHKeyPairGenerator", "DHBasicKeyPairGenerator", "ElGamalKeyPairGenerator", "Ed25519KeyPairGenerator", "Ed448KeyPairGenerator", "X25519KeyPairGenerator", "X448KeyPairGenerator", "PKCS5S1ParametersGenerator", "PKCS5S2ParametersGenerator", "PKCS12ParametersGenerator", "OpenSSLPBEParametersGenerator", "Argon2BytesGenerator", "HKDFBytesGenerator", "KDF1BytesGenerator", "KDF2BytesGenerator", "KDFCounterBytesGenerator", "KDFFeedbackBytesGenerator", "MGF1BytesGenerator", "KyberKeyPairGenerator", "MLKEMKeyPairGenerator", "DilithiumKeyPairGenerator", "MLDSAKeyPairGenerator", "SPHINCSPlusKeyPairGenerator", "SLHDSAKeyPairGenerator", "FalconKeyPairGenerator", "NTRUKeyPairGenerator", "FrodoKeyPairGenerator", "BIKEKeyPairGenerator", "HQCKeyPairGenerator", "XMSSKeyPairGenerator", "LMSKeyPairGenerator", "GOST3410KeyPairGenerator", "ECGOST3410KeyPairGenerator", "SM2KeyPairGenerator", "NaccacheSternKeyPairGenerator", "CramerShoupKeyPairGenerator"}, key=len, reverse=True)) + r")\s*\(", _K, _BC, algo_from_group=1, algo_map=_BC_GENERATORS),
    _r(r"\b(?:SCrypt|org\.bouncycastle\.crypto\.generators\.SCrypt)\.generate\s*\(", _KDF, _BC, algorithm="SCRYPT"),
    _r(r"\b(?:BCrypt|OpenBSDBCrypt|org\.bouncycastle\.crypto\.generators\.(?:BCrypt|OpenBSDBCrypt))\.(?:generate|hashpw|checkpw|checkPassword)\s*\(", _KDF, _BC, algorithm="BCRYPT"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.signers\.)?(RSADigestSigner|PSSSigner|ISO9796d2Signer|X931Signer|GenericSigner|DSASigner|DSADigestSigner|ECDSASigner|ECNRSigner|ECGOST3410Signer|GOST3410Signer|Ed25519Signer|Ed25519ctxSigner|Ed25519phSigner|Ed448Signer|Ed448phSigner|SM2Signer|DilithiumSigner|MLDSASigner|SPHINCSPlusSigner|SLHDSASigner|FalconSigner|XMSSSigner|LMSSigner)\s*\(", _S, _BC, algo_from_group=1, algo_map=_BC_SIGNERS),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.agreement\.)?(ECDHBasicAgreement|ECDHCBasicAgreement|ECDHCUnifiedAgreement|ECMQVBasicAgreement|DHBasicAgreement|DHUnifiedAgreement|MQVBasicAgreement|X25519Agreement|X448Agreement|SM2KeyExchange|KyberKEMGenerator|MLKEMGenerator|NTRUKEMGenerator|FrodoKEMGenerator)\s*\(", _KA, _BC, algo_from_group=1, algo_map=_BC_AGREEMENT),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.modes\.)?(?:GCMBlockCipher|CCMBlockCipher|EAXBlockCipher|OCBBlockCipher|CBCBlockCipher|CFBBlockCipher|OFBBlockCipher|SICBlockCipher|KCCMBlockCipher|KCTRBlockCipher|GOFBBlockCipher|ChaCha20Poly1305|KXTSBlockCipher|GCMSIVBlockCipher)\s*\(", _C, _BC, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.modes\.)?ChaCha20Poly1305\s*\(", _C, _BC, algorithm="ChaCha20-Poly1305"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.encodings\.)?(OAEPEncoding|PKCS1Encoding|ISO9796d1Encoding)\s*\(", _C, _BC, algorithm="RSA", padding="OAEP"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.crypto\.prng\.)?(?:SP800SecureRandomBuilder|DigestRandomGenerator|VMPCRandomGenerator|ThreadedSeedGenerator|X931SecureRandomBuilder|FixedSecureRandom)\s*\(", _RNG, _BC, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.jce\.provider\.)?BouncyCastleProvider\s*\(|\bnew\s+BouncyCastleFipsProvider\s*\(|\bnew\s+BouncyCastlePQCProvider\s*\(|\bSecurity\.addProvider\s*\(", {"api_type": "PROVIDER", "purpose": "KEY_GENERATION"}, _BC, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.tls\.)?(?:TlsClientProtocol|TlsServerProtocol|DefaultTlsClient|DefaultTlsServer|BcTlsCrypto|JcaTlsCryptoProvider)\s*\(", _TLS, _BC, algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:org\.bouncycastle\.openssl\.)?(?:PEMParser|PEMWriter|JcaPEMWriter|JcaPEMKeyConverter)\s*\(|\bnew\s+JcaX509CertificateConverter\s*\(|\bnew\s+(?:JcaX509v[13]CertificateBuilder|X509v[13]CertificateBuilder)\s*\(|\bnew\s+JcaContentSignerBuilder\s*\(\s*\"([A-Za-z0-9-]+)with([A-Za-z0-9]+)", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, _BC, algorithm="X509", confidence="MEDIUM"),
    _r(r"\bnew\s+JcaContentSignerBuilder\s*\(\s*\"(SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5|SHA3-\d+)with(RSA|ECDSA|DSA|RSAandMGF1|Ed25519|Ed448)", _S, _BC, algo_from_group=2, algo_map={"rsa": "RSA", "ecdsa": "ECDSA", "dsa": "DSA", "rsaandmgf1": "RSA", "ed25519": "Ed25519", "ed448": "Ed448"}, emit_digest_group=1),
    # ------------------------------------------------------------- JWT libraries
    _r(r"\bSignatureAlgorithm\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|NONE)\b", _S, "jjwt", algo_from_group=1, algo_map={**_JWT_ALGS, "none": "none"}),
    _r(r"\bJwts\.(?:builder|parser|parserBuilder|SIG|ENC|KEY)\b|\bJwts\.SIG\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)\b", _S, "jjwt", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bJwts\.SIG\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)\b", _S, "jjwt", algo_from_group=1, algo_map=_JWT_ALGS),
    _r(r"\bAlgorithm\.(HMAC256|HMAC384|HMAC512|RSA256|RSA384|RSA512|ECDSA256|ECDSA256K|ECDSA384|ECDSA512|none)\s*\(", _S, "java-jwt", algo_from_group=1, algo_map=_AUTH0_ALGS),
    _r(r"\bJWT\.(?:create|require|decode)\s*\(", _S, "java-jwt", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bJWSAlgorithm\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES256K|ES384|ES512|PS256|PS384|PS512|EdDSA|Ed25519|Ed448)\b", _S, "nimbus-jose-jwt", algo_from_group=1, algo_map={**_JWT_ALGS, "ed25519": "EdDSA", "ed448": "EdDSA"}),
    _r(r"\bJWEAlgorithm\.(RSA_OAEP_256|RSA_OAEP|RSA1_5|A128KW|A192KW|A256KW|DIR|ECDH_ES|ECDH_ES_A128KW|ECDH_ES_A256KW|A128GCMKW|A256GCMKW|PBES2_HS256_A128KW|PBES2_HS512_A256KW)\b", _C, "nimbus-jose-jwt", algo_from_group=1,
       algo_map={"rsa_oaep_256": "RSA", "rsa_oaep": "RSA", "rsa1_5": "RSA", "a128kw": "AES", "a192kw": "AES", "a256kw": "AES", "dir": "UNKNOWN", "ecdh_es": "ECDH", "ecdh_es_a128kw": "ECDH", "ecdh_es_a256kw": "ECDH", "a128gcmkw": "AES", "a256gcmkw": "AES", "pbes2_hs256_a128kw": "PBKDF2", "pbes2_hs512_a256kw": "PBKDF2"}),
    _r(r"\bEncryptionMethod\.(A128CBC_HS256|A192CBC_HS384|A256CBC_HS512|A128GCM|A192GCM|A256GCM|XC20P)\b", _C, "nimbus-jose-jwt", algo_from_group=1,
       algo_map={"a128cbc_hs256": "AES", "a192cbc_hs384": "AES", "a256cbc_hs512": "AES", "a128gcm": "AES", "a192gcm": "AES", "a256gcm": "AES", "xc20p": "XChaCha20-Poly1305"}),
    _r(r"\bnew\s+(?:MACSigner|MACVerifier)\s*\(", _M, "nimbus-jose-jwt", algorithm="HMAC"),
    _r(r"\bnew\s+(?:RSASSASigner|RSASSAVerifier|RSAEncrypter|RSADecrypter)\s*\(", _S, "nimbus-jose-jwt", algorithm="RSA"),
    _r(r"\bnew\s+(?:ECDSASigner|ECDSAVerifier|ECDHEncrypter|ECDHDecrypter)\s*\(", _S, "nimbus-jose-jwt", algorithm="ECDSA"),
    _r(r"\bnew\s+(?:Ed25519Signer|Ed25519Verifier)\s*\(", _S, "nimbus-jose-jwt", algorithm="Ed25519"),
    _r(r"\bnew\s+(?:JwtParser|JwtBuilder|SignedJWT|JWSObject|JWEObject|PlainJWT|JWSHeader|DefaultJwtBuilder|DefaultJwtParser)\s*\(|\bJwtHelper\.(?:encode|decode|decodeAndVerify)\s*\(|\bJwtParser\s+\w+\s*=|\bNimbusJwtDecoder\.|\bNimbusJwtEncoder\b|\bJwtDecoders\.fromIssuerLocation\b|\bnew\s+MacAlgorithm\b|\bMacAlgorithm\.(HS256|HS384|HS512)\b|\bSignatureAlgorithm\.(RS256|ES256)\b", _S, "jwt", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bnew\s+MacSigner\s*\(|\bnew\s+RsaSigner\s*\(|\bnew\s+RsaVerifier\s*\(|\bnew\s+MacVerifier\s*\(", _S, "spring-security-jwt", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bio\.fusionauth\.jwt\b|\bHMACSigner\.newSHA(256|384|512)Signer\b|\bRSASigner\.newSHA(256|384|512)Signer\b|\bECSigner\.newSHA(256|384|512)Signer\b", _S, "fusionauth-jwt", algorithm="JWT", emit_digest_group=1),
    _r(r"\bcom\.auth0\.jwt\b|\bio\.jsonwebtoken\b|\bcom\.nimbusds\.jose\b|\borg\.jose4j\b", _S, "jwt", algorithm="JWT", confidence="LOW"),
    _r(r"\bAlgorithmIdentifiers\.(HMAC_SHA256|HMAC_SHA384|HMAC_SHA512|RSA_USING_SHA256|RSA_USING_SHA384|RSA_USING_SHA512|ECDSA_USING_P256_CURVE_AND_SHA256|ECDSA_USING_P384_CURVE_AND_SHA384|ECDSA_USING_P521_CURVE_AND_SHA512|RSA_PSS_USING_SHA256|EDDSA|NONE)\b", _S, "jose4j", algo_from_group=1,
       algo_map={"hmac_sha256": "HS256", "hmac_sha384": "HS384", "hmac_sha512": "HS512", "rsa_using_sha256": "RS256", "rsa_using_sha384": "RS384", "rsa_using_sha512": "RS512", "ecdsa_using_p256_curve_and_sha256": "ES256", "ecdsa_using_p384_curve_and_sha384": "ES384", "ecdsa_using_p521_curve_and_sha512": "ES512", "rsa_pss_using_sha256": "PS256", "eddsa": "EdDSA", "none": "none"}),
    _r(r"\bnew\s+(?:JsonWebSignature|JsonWebEncryption|JwtConsumerBuilder|JwtClaims)\s*\(", _S, "jose4j", algorithm="JWT", confidence="MEDIUM"),
    # ------------------------------------------------------------- password hashing libraries
    _r(r"\bBCrypt\.(?:hashpw|checkpw|gensalt|withDefaults|verifyer|with)\s*\(|\borg\.mindrot\.jbcrypt\b|\bat\.favre\.lib\.crypto\.bcrypt\b|\bnew\s+BCryptPasswordEncoder\s*\(|\bBCryptPasswordEncoder\b|\bBCrypt\.Version\.VERSION_2[ABXY]\b", _KDF, "bcrypt", algorithm="BCRYPT"),
    _r(r"\bArgon2Factory\.create\s*\(|\bde\.mkammerer\.argon2\b|\bnew\s+Argon2PasswordEncoder\s*\(|\bArgon2PasswordEncoder\.defaultsForSpringSecurity_v5_\d\s*\(|\bArgon2PasswordEncoder\b|\bArgon2Advanced\b|\bArgon2Function\.getInstance\b|\bArgon2Parameters\.Builder\s*\(|\bArgon2Parameters\.ARGON2_(?:id|i|d)\b", _KDF, "argon2", algorithm="ARGON2"),
    _r(r"\bnew\s+SCryptPasswordEncoder\s*\(|\bSCryptPasswordEncoder\.defaultsForSpringSecurity_v5_\d\s*\(|\bSCryptPasswordEncoder\b|\bcom\.lambdaworks\.crypto\.SCryptUtil\b|\bSCryptUtil\.(?:scrypt|check)\s*\(|\bScryptFunction\.getInstance\b", _KDF, "scrypt", algorithm="SCRYPT"),
    _r(r"\bnew\s+Pbkdf2PasswordEncoder\s*\(|\bPbkdf2PasswordEncoder\.defaultsForSpringSecurity_v5_\d\s*\(|\bPbkdf2PasswordEncoder\b|\bPBKDF2Function\.getInstance\b|\bCompressedPBKDF2Function\.getInstance\b", _KDF, "spring-security", algorithm="PBKDF2"),
    _r(r"\bnew\s+(?:StandardPasswordEncoder|MessageDigestPasswordEncoder|Md5PasswordEncoder|ShaPasswordEncoder|LdapShaPasswordEncoder|Md4PasswordEncoder)\s*\(", _KDF, "spring-security", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bnew\s+Md5PasswordEncoder\s*\(", _D, "spring-security", algorithm="MD5"),
    _r(r"\bnew\s+Md4PasswordEncoder\s*\(", _D, "spring-security", algorithm="MD4"),
    _r(r"\bnew\s+(?:ShaPasswordEncoder|LdapShaPasswordEncoder)\s*\(", _D, "spring-security", algorithm="SHA-1"),
    _r(r"\bnew\s+StandardPasswordEncoder\s*\(", _D, "spring-security", algorithm="SHA-256"),
    _r(r"\bnew\s+MessageDigestPasswordEncoder\s*\(\s*\"([A-Za-z0-9-]+)\"", _D, "spring-security", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bNoOpPasswordEncoder\.getInstance\s*\(|\bnew\s+PlaintextPasswordEncoder\s*\(", _KDF, "spring-security", algorithm="PLAINTEXT", confidence="HIGH", confidence_reason="passwords stored without hashing"),
    _r(r"\bPasswordEncoderFactories\.createDelegatingPasswordEncoder\s*\(|\bnew\s+DelegatingPasswordEncoder\s*\(", _KDF, "spring-security", algorithm="BCRYPT", confidence="MEDIUM"),
    _r(r"\bPassword\.hash\s*\([^)]*\)\s*\.\s*with(Bcrypt|Scrypt|Argon2|PBKDF2|CompressedPBKDF2|MessageDigest|BalloonHashing)\s*\(", _KDF, "password4j", algo_from_group=1,
       algo_map={"bcrypt": "BCRYPT", "scrypt": "SCRYPT", "argon2": "ARGON2", "pbkdf2": "PBKDF2", "compressedpbkdf2": "PBKDF2", "messagedigest": "UNKNOWN", "balloonhashing": "BALLOON"}),
    _r(r"\bcom\.password4j\b", _KDF, "password4j", algorithm="UNKNOWN", confidence="LOW"),
    # ------------------------------------------------------------- Guava / Commons Codec / Spring digests
    _r(r"\bHashing\.(md5|sha1|sha256|sha384|sha512|hmacMd5|hmacSha1|hmacSha256|hmacSha512|crc32|crc32c|adler32|murmur3_32|murmur3_32_fixed|murmur3_128|sipHash24|farmHashFingerprint64|goodFastHash|fingerprint2011)\s*\(", _D, "guava", algo_from_group=1,
       algo_map={"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "hmacmd5": "HMAC-MD5", "hmacsha1": "HMAC-SHA1", "hmacsha256": "HMAC-SHA256", "hmacsha512": "HMAC-SHA512"}),
    _r(r"\bDigestUtils\.(md2|md5|sha1|sha|sha256|sha384|sha512|sha3_224|sha3_256|sha3_384|sha3_512|sha512_224|sha512_256)(?:Hex)?\s*\(", _D, "commons-codec", algo_from_group=1, algo_map={**DIGEST_TOKENS, "sha": "SHA-1"}),
    _r(r"\bDigestUtils\.get(Md2|Md5|Sha1|Sha256|Sha384|Sha512|Sha3_224|Sha3_256|Sha3_384|Sha3_512)Digest\s*\(", _D, "commons-codec", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bDigestUtils\.getDigest\s*\(\s*\"([A-Za-z0-9-]+)\"|\bnew\s+DigestUtils\s*\(\s*\"([A-Za-z0-9-]+)\"", _D, "commons-codec", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bMessageDigestAlgorithms\.(MD2|MD5|SHA_1|SHA_224|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_512)\b", _D, "commons-codec", algo_from_group=1,
       algo_map={"md2": "MD2", "md5": "MD5", "sha_1": "SHA-1", "sha_224": "SHA-224", "sha_256": "SHA-256", "sha_384": "SHA-384", "sha_512": "SHA-512", "sha3_256": "SHA3-256", "sha3_512": "SHA3-512"}),
    _r(r"\bHmacUtils\.hmac(Md5|Sha1|Sha256|Sha384|Sha512)(?:Hex)?\s*\(|\bnew\s+HmacUtils\s*\(\s*HmacAlgorithms\.HMAC_(MD5|SHA_1|SHA_256|SHA_384|SHA_512)\b|\bHmacAlgorithms\.HMAC_(MD5|SHA_1|SHA_224|SHA_256|SHA_384|SHA_512)\b", _M, "commons-codec", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bHmacAlgorithms\.HMAC_SHA_1\b|\bHmacUtils\.hmacSha1(?:Hex)?\s*\(", _D, "commons-codec", algorithm="SHA-1"),
    _r(r"\bHmacAlgorithms\.HMAC_SHA_256\b|\bHmacUtils\.hmacSha256(?:Hex)?\s*\(", _D, "commons-codec", algorithm="SHA-256"),
    _r(r"\bHmacAlgorithms\.HMAC_SHA_512\b|\bHmacUtils\.hmacSha512(?:Hex)?\s*\(", _D, "commons-codec", algorithm="SHA-512"),
    _r(r"\bHmacAlgorithms\.HMAC_MD5\b|\bHmacUtils\.hmacMd5(?:Hex)?\s*\(", _D, "commons-codec", algorithm="MD5"),
    _r(r"\bDigestUtils\.(?:md5Digest|md5DigestAsHex|appendMd5DigestAsHex)\s*\(", _D, "spring-core", algorithm="MD5"),
    _r(r"\bEncryptors\.(?:text|queryableText|stronger|standard|delux)\s*\(", _C, "spring-security-crypto", algorithm="AES", mode="GCM"),
    _r(r"\bEncryptors\.(?:text|queryableText|standard)\s*\(", _C, "spring-security-crypto", algorithm="AES", mode="CBC"),
    _r(r"\bnew\s+(?:AesBytesEncryptor|HexEncodingTextEncryptor)\s*\(|\bAesBytesEncryptor\.CipherAlgorithm\.(CBC|GCM)\b", _C, "spring-security-crypto", algorithm="AES"),
    _r(r"\bKeyGenerators\.(?:secureRandom|shared|string)\s*\(", _RNG, "spring-security-crypto", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:StandardPBEStringEncryptor|PooledPBEStringEncryptor|StandardPBEByteEncryptor|BasicTextEncryptor|StrongTextEncryptor|AES256TextEncryptor)\s*\(|\bsetAlgorithm\s*\(\s*\"(PBEWith\w+)\"", _C, "jasypt", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bnew\s+BasicTextEncryptor\s*\(", _C, "jasypt", algorithm="DES", padding="PKCS5", confidence_reason="jasypt BasicTextEncryptor = PBEWithMD5AndDES"),
    _r(r"\bnew\s+BasicTextEncryptor\s*\(", _D, "jasypt", algorithm="MD5"),
    _r(r"\bnew\s+StrongTextEncryptor\s*\(", _C, "jasypt", algorithm="3DES", confidence_reason="jasypt StrongTextEncryptor = PBEWithMD5AndTripleDES"),
    _r(r"\bnew\s+AES256TextEncryptor\s*\(", _C, "jasypt", algorithm="AES", key_size=256),
    _r(r"\bnew\s+(?:StandardStringDigester|BasicPasswordEncryptor|StrongPasswordEncryptor|ConfigurablePasswordEncryptor)\s*\(", _KDF, "jasypt", algorithm="UNKNOWN", confidence="MEDIUM"),
    # ------------------------------------------------------------- Google Tink
    _r(r"\bKeyTemplates\.get\s*\(\s*\"([A-Z0-9_]+)\"", _C, "tink", algo_from_group=1, algo_map=_TINK),
    _r(r"\b(?:AeadKeyTemplates|MacKeyTemplates|SignatureKeyTemplates|HybridKeyTemplates|DeterministicAeadKeyTemplates|StreamingAeadKeyTemplates|KeyTemplates)\.([A-Z0-9_]+)\b", _C, "tink", algo_from_group=1, algo_map=_TINK),
    _r(r"\b(?:AesGcmKeyManager|AesCtrHmacAeadKeyManager|AesEaxKeyManager|AesGcmSivKeyManager|AesSivKeyManager|AesGcmHkdfStreamingKeyManager|AesCtrHmacStreamingKeyManager|AesCmacKeyManager|AesCmacPrfKeyManager)\.\w+\s*\(", _C, "tink", algorithm="AES"),
    _r(r"\b(?:ChaCha20Poly1305KeyManager|XChaCha20Poly1305KeyManager)\.\w+\s*\(", _C, "tink", algorithm="ChaCha20-Poly1305"),
    _r(r"\bHmacKeyManager\.\w+\s*\(|\bHmacPrfKeyManager\.\w+\s*\(", _M, "tink", algorithm="HMAC"),
    _r(r"\bHkdfPrfKeyManager\.\w+\s*\(", _KDF, "tink", algorithm="HKDF", purpose="KEY_GENERATION"),
    _r(r"\bEcdsaSignKeyManager\.\w+\s*\(|\bEcdsaVerifyKeyManager\.\w+\s*\(", _S, "tink", algorithm="ECDSA"),
    _r(r"\bEd25519PrivateKeyManager\.\w+\s*\(|\bEd25519PublicKeyManager\.\w+\s*\(", _S, "tink", algorithm="Ed25519"),
    _r(r"\bRsaSsaPkcs1SignKeyManager\.\w+\s*\(|\bRsaSsaPssSignKeyManager\.\w+\s*\(", _S, "tink", algorithm="RSA"),
    _r(r"\bEciesAeadHkdfPrivateKeyManager\.\w+\s*\(", _KA, "tink", algorithm="ECIES"),
    _r(r"\bHpkePrivateKeyManager\.\w+\s*\(|\bHpkeParameters\b", _KA, "tink", algorithm="HPKE"),
    _r(r"\b(?:AeadConfig|MacConfig|SignatureConfig|HybridConfig|DeterministicAeadConfig|StreamingAeadConfig|PrfConfig|TinkConfig|JwtMacConfig|JwtSignatureConfig)\.register\s*\(", {"api_type": "PROVIDER", "purpose": "KEY_GENERATION"}, "tink", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bJwtHmacKeyManager\.\w+\s*\(|\bJwtEcdsaSignKeyManager\.\w+\s*\(|\bJwtRsaSsaPkcs1SignKeyManager\.\w+\s*\(|\bJwtRsaSsaPssSignKeyManager\.\w+\s*\(|\bRawJwt\.newBuilder\s*\(|\bJwtValidator\.newBuilder\s*\(", _S, "tink", algorithm="JWT"),
    _r(r"\bKeysetHandle\.generateNew\s*\(|\bKeysetHandle\.generateEntryFromParameters\b|\bKeysetHandle\.newBuilder\s*\(", _RNG, "tink", algorithm="CSPRNG", confidence="LOW"),
    # ------------------------------------------------------------- JDK APIs outside getInstance
    _r(r"\bnew\s+ECGenParameterSpec\s*\(\s*\"(secp\w+|prime\w+|P-\d+|brainpool\w+|sect\w+|NIST P-\d+|X9\.62 \w+)\"", _K, "java.security.spec", algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bnew\s+NamedParameterSpec\s*\(\s*\"(X25519|X448|Ed25519|Ed448)\"|\bNamedParameterSpec\.(X25519|X448|ED25519|ED448)\b", _K, "java.security.spec", algo_from_group=1,
       algo_map={"x25519": "X25519", "x448": "X448", "ed25519": "Ed25519", "ed448": "Ed448"}),
    _r(r"\bnew\s+NamedParameterSpec\s*\(\s*\"(X25519|X448|Ed25519|Ed448)\"", _K, "java.security.spec", algo_from_group=1,
       algo_map={"x25519": "X25519", "x448": "X448", "ed25519": "Ed25519", "ed448": "Ed448"}),
    _r(r"\bnew\s+(?:RSAKeyGenParameterSpec|RSAPrivateKeySpec|RSAPublicKeySpec|RSAPrivateCrtKeySpec|PSSParameterSpec|OAEPParameterSpec)\s*\(", _K, "java.security.spec", algorithm="RSA"),
    _r(r"\bnew\s+OAEPParameterSpec\s*\(\s*\"(SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5)\"", _D, "java.security.spec", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bnew\s+PSSParameterSpec\s*\(\s*\"(SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5)\"", _D, "java.security.spec", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bnew\s+(?:DSAPrivateKeySpec|DSAPublicKeySpec|DSAParameterSpec)\s*\(", _K, "java.security.spec", algorithm="DSA"),
    _r(r"\bnew\s+(?:DHParameterSpec|DHPrivateKeySpec|DHPublicKeySpec|DHGenParameterSpec)\s*\(", _KA, "javax.crypto.spec", algorithm="DH"),
    _r(r"\bnew\s+(?:ECPrivateKeySpec|ECPublicKeySpec|ECParameterSpec)\s*\(", _K, "java.security.spec", algorithm="ECDSA"),
    _r(r"\bnew\s+(?:EdECPrivateKeySpec|EdECPublicKeySpec)\s*\(", _S, "java.security.spec", algorithm="Ed25519"),
    _r(r"\bnew\s+(?:XECPrivateKeySpec|XECPublicKeySpec)\s*\(", _KA, "java.security.spec", algorithm="X25519"),
    _r(r"\bnew\s+(?:DESKeySpec)\s*\(", _C, "javax.crypto.spec", algorithm="DES"),
    _r(r"\bnew\s+(?:DESedeKeySpec)\s*\(", _C, "javax.crypto.spec", algorithm="3DES"),
    _r(r"\bnew\s+(?:RC2ParameterSpec)\s*\(", _C, "javax.crypto.spec", algorithm="RC2"),
    _r(r"\bnew\s+(?:RC5ParameterSpec)\s*\(", _C, "javax.crypto.spec", algorithm="RC5"),
    _r(r"\bnew\s+ChaCha20ParameterSpec\s*\(", _C, "javax.crypto.spec", algorithm="ChaCha20"),
    _r(r"\bnew\s+GCMParameterSpec\s*\(", _C, "javax.crypto.spec", algorithm="AES", mode="GCM", confidence="MEDIUM"),
    _r(r"\bnew\s+PBEParameterSpec\s*\(", _KDF, "javax.crypto.spec", algorithm="PBKDF2", confidence="MEDIUM"),
    _r(r"\bnew\s+SecureRandom\s*\(|\bSecureRandom\.getInstanceStrong\s*\(|\bnew\s+java\.security\.SecureRandom\s*\(", _RNG, "java.security", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\b(?:key|iv|salt|nonce|token|secret|password|seed)\w*\s*=\s*[^;]*\bnew\s+(?:java\.util\.)?Random\s*\(|\bnew\s+(?:java\.util\.)?Random\s*\([^)]*\)\s*\.\s*nextBytes\s*\(", _RNG, "java.util", algorithm="PRNG", confidence="MEDIUM", confidence_reason="java.util.Random is not a CSPRNG"),
    _r(r"\bMath\.random\s*\(\s*\)[^;]*(?:key|token|secret|password|salt|nonce)|(?:key|token|secret|password|salt|nonce)\w*\s*=[^;]*\bMath\.random\s*\(", _RNG, "java.lang", algorithm="PRNG", confidence="MEDIUM", confidence_reason="Math.random is not a CSPRNG"),
    _r(r"\bnew\s+ThreadLocalRandom\b|\bThreadLocalRandom\.current\s*\(\s*\)\s*\.\s*nextBytes\s*\(", _RNG, "java.util.concurrent", algorithm="PRNG", confidence="LOW"),
    _r(r"\bjava\.util\.zip\.CRC32\b|\bnew\s+CRC32C?\s*\(|\bnew\s+Adler32\s*\(", {"api_type": "CHECKSUM", "purpose": "INTEGRITY"}, "java.util.zip", algorithm=None),
    _r(r"\bnew\s+SealedObject\s*\(|\bnew\s+SignedObject\s*\(", _C, "javax.crypto", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bnew\s+(?:CipherInputStream|CipherOutputStream|DigestInputStream|DigestOutputStream)\s*\(", _C, "javax.crypto", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bKeyStore\.getDefaultType\s*\(|\bnew\s+KeyStore\.PasswordProtection\s*\(", _K, "java.security", algorithm="KeyStore", confidence="LOW"),
    _r(r"\bnew\s+JcaPKCS10CertificationRequestBuilder\s*\(|\bnew\s+PKCS10CertificationRequest\s*\(|\bX509Certificate\s+\w+\s*=|\bCertPathValidator\.getInstance\s*\(|\bCertPathBuilder\.getInstance\s*\(|\bnew\s+PKIXParameters\s*\(|\bnew\s+X509EncodedKeySpec\s*\(|\bnew\s+PKCS8EncodedKeySpec\s*\(", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "java.security.cert", algorithm="X509", confidence="MEDIUM"),
    # ------------------------------------------------------------- TLS (OkHttp / Netty / Conscrypt / Apache HttpClient / JDK props)
    _r(r"\bTlsVersion\.SSL_3_0\b|\bConnectionSpec\.COMPATIBLE_TLS\b", _TLS, "okhttp", algorithm="SSLv3"),
    _r(r"\bTlsVersion\.TLS_1_0\b", _TLS, "okhttp", algorithm="TLS1.0"),
    _r(r"\bTlsVersion\.TLS_1_1\b", _TLS, "okhttp", algorithm="TLS1.1"),
    _r(r"\bTlsVersion\.TLS_1_2\b|\bConnectionSpec\.MODERN_TLS\b", _TLS, "okhttp", algorithm="TLS1.2"),
    _r(r"\bTlsVersion\.TLS_1_3\b|\bConnectionSpec\.RESTRICTED_TLS\b", _TLS, "okhttp", algorithm="TLS1.3"),
    _r(r"\bConnectionSpec\.CLEARTEXT\b", _TLS, "okhttp", algorithm="TLS-CLEARTEXT", confidence_reason="cleartext HTTP allowed"),
    _r(r"\bnew\s+ConnectionSpec\.Builder\s*\(|\bCipherSuite\.(TLS_\w+)\b|\bsslSocketFactory\s*\(|\bhostnameVerifier\s*\(\s*(?:\([^)]*\)|\w+)\s*->\s*true", _TLS, "okhttp", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bhostnameVerifier\s*\(\s*(?:\([^)]*\)|\w+)\s*->\s*true|\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bNoopHostnameVerifier\b|\bTrustAllStrategy\b|\bTrustSelfSignedStrategy\b|\bInsecureTrustManagerFactory\.INSTANCE\b|\bnew\s+TrustAllX509TrustManager\b", _TLS, "javax.net.ssl", algorithm="TRUST-ALL", confidence_reason="certificate/hostname validation disabled"),
    _r(r"\bSslContextBuilder\.(?:forClient|forServer)\s*\(|\bSslContext\s+\w+\s*=|\bSslProvider\.(?:OPENSSL|JDK|OPENSSL_REFCNT)\b|\bnew\s+SslHandler\s*\(|\bOpenSsl\.isAvailable\s*\(", _TLS, "netty", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bConscrypt\.newProvider\s*\(|\borg\.conscrypt\b", _TLS, "conscrypt", algorithm="TLS", confidence="LOW"),
    _r(r"\bSSLContextBuilder\.create\s*\(|\bSSLContexts\.custom\s*\(|\bnew\s+SSLConnectionSocketFactory\s*\(|\bSSLConnectionSocketFactory\.getSocketFactory\s*\(|\bSSLSocketFactory\.getDefault\s*\(|\bHttpsURLConnection\.setDefaultSSLSocketFactory\s*\(|\bnew\s+DefaultHostnameVerifier\s*\(", _TLS, "javax.net.ssl", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bsetEnabledProtocols\s*\(\s*new\s+String\s*\[\s*\]\s*\{\s*\"(SSLv3|TLSv1|TLSv1\.1|TLSv1\.2|TLSv1\.3|SSLv2Hello)\"", _TLS, "javax.net.ssl", algo_from_group=1,
       algo_map={"sslv3": "SSLv3", "tlsv1": "TLS1.0", "tlsv1.1": "TLS1.1", "tlsv1.2": "TLS1.2", "tlsv1.3": "TLS1.3", "sslv2hello": "SSLv2"}),
    _r(r"\bSystem\.setProperty\s*\(\s*\"(?:https\.protocols|jdk\.tls\.client\.protocols|jdk\.tls\.server\.protocols)\"\s*,\s*\"([^\"]+)\"", _TLS, "javax.net.ssl", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bSystem\.setProperty\s*\(\s*\"(?:https\.protocols|jdk\.tls\.client\.protocols)\"\s*,\s*\"[^\"]*\b(SSLv3|TLSv1|TLSv1\.1)\b", _TLS, "javax.net.ssl", algo_from_group=1, algo_map={"sslv3": "SSLv3", "tlsv1": "TLS1.0", "tlsv1.1": "TLS1.1"}),
    _r(r"\bnew\s+JSch\s*\(|\bjsch\.getSession\s*\(|\bSshClient\.setUpDefaultClient\s*\(|\bnet\.schmizz\.sshj\b|\bnew\s+SSHClient\s*\(|\bcom\.jcraft\.jsch\b", _TLS, "ssh", algorithm="SSH", confidence="MEDIUM"),
    # ------------------------------------------------------------- Android
    _r(r"\bKeyProperties\.KEY_ALGORITHM_(AES|RSA|EC|HMAC_SHA1|HMAC_SHA224|HMAC_SHA256|HMAC_SHA384|HMAC_SHA512|3DES|XDH)\b", _K, "android.security.keystore", algo_from_group=1,
       algo_map={"aes": "AES", "rsa": "RSA", "ec": "ECDSA", "hmac_sha1": "HMAC-SHA1", "hmac_sha224": "HMAC-SHA224", "hmac_sha256": "HMAC-SHA256", "hmac_sha384": "HMAC-SHA384", "hmac_sha512": "HMAC-SHA512", "3des": "3DES", "xdh": "X25519"}),
    _r(r"\bKeyProperties\.BLOCK_MODE_(ECB|CBC|CTR|GCM)\b", _C, "android.security.keystore", algorithm="AES", confidence="LOW"),
    _r(r"\bKeyProperties\.DIGEST_(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|NONE)\b", _D, "android.security.keystore", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bMasterKeys\.AES256_GCM_SPEC\b|\bMasterKey\.KeyScheme\.AES256_GCM\b|\bEncryptedSharedPreferences\.PrefKeyEncryptionScheme\.AES256_SIV\b|\bEncryptedSharedPreferences\.PrefValueEncryptionScheme\.AES256_GCM\b|\bEncryptedFile\.FileEncryptionScheme\.AES256_GCM_HKDF_4KB\b", _C, "androidx.security.crypto", algorithm="AES", mode="GCM"),
    _r(r"\bnew\s+KeyGenParameterSpec\.Builder\s*\(|\bKeyGenParameterSpec\.Builder\s*\(", _K, "android.security.keystore", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bBiometricPrompt\.CryptoObject\s*\(", _C, "androidx.biometric", algorithm="UNKNOWN", confidence="LOW"),
    # ------------------------------------------------------------- Kotlin / misc JVM crypto libs
    _r(r"\bdev\.whyoleg\.cryptography\b|\bCryptographyProvider\.Default\b", {"api_type": "PROVIDER", "purpose": "KEY_GENERATION"}, "cryptography-kotlin", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bget\s*\(\s*(AES\.GCM|AES\.CBC|AES\.CTR|AES\.ECB|SHA1|SHA256|SHA384|SHA512|SHA3_256|SHA3_512|MD5|HMAC|RSA\.OAEP|RSA\.PSS|RSA\.PKCS1|ECDSA|ECDH|PBKDF2|HKDF)\s*\)", _C, "cryptography-kotlin", algo_from_group=1,
       algo_map={"aes.gcm": "AES", "aes.cbc": "AES", "aes.ctr": "AES", "aes.ecb": "AES", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha3_256": "SHA3-256", "sha3_512": "SHA3-512", "md5": "MD5", "hmac": "HMAC", "rsa.oaep": "RSA", "rsa.pss": "RSA", "rsa.pkcs1": "RSA", "ecdsa": "ECDSA", "ecdh": "ECDH", "pbkdf2": "PBKDF2", "hkdf": "HKDF"}),
    _r(r"\bLazySodiumJava\b|\bLazySodiumAndroid\b|\bcom\.goterl\.lazysodium\b|\bSodiumJava\b", _C, "lazysodium", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bcryptoSecretBoxEasy\s*\(|\bcryptoSecretBoxKeygen\s*\(|\bSecretBox\.Native\b|\bcrypto_secretbox_easy\s*\(", _C, "lazysodium", algorithm="XSalsa20-Poly1305"),
    _r(r"\bcryptoSignKeypair\s*\(|\bcryptoSignDetached\s*\(|\bcrypto_sign_keypair\s*\(", _S, "lazysodium", algorithm="Ed25519"),
    _r(r"\bcryptoPwHashStr\s*\(|\bcryptoPwHash\s*\(|\bcrypto_pwhash_str\s*\(", _KDF, "lazysodium", algorithm="ARGON2"),
    _r(r"\bcryptoAeadChaCha20Poly1305IetfEncrypt\s*\(|\bcryptoAeadXChaCha20Poly1305IetfEncrypt\s*\(", _C, "lazysodium", algorithm="ChaCha20-Poly1305"),
    _r(r"\bcryptoAeadAES256GCMEncrypt\s*\(", _C, "lazysodium", algorithm="AES", mode="GCM"),
    _r(r"\bnew\s+(?:PGPEncryptedDataGenerator|PGPSignatureGenerator|PGPKeyRingGenerator|JcePGPDataEncryptorBuilder|BcPGPDataEncryptorBuilder|PGPPublicKeyRingCollection|PGPSecretKeyRingCollection)\s*\(|\bPGPEncryptedData\.(AES_128|AES_192|AES_256|TRIPLE_DES|CAST5|BLOWFISH|TWOFISH|IDEA|DES|SAFER|CAMELLIA_128|CAMELLIA_256)\b", _C, "bcpg", algo_from_group=1,
       algo_map={"aes_128": "AES", "aes_192": "AES", "aes_256": "AES", "triple_des": "3DES", "cast5": "CAST5", "blowfish": "Blowfish", "twofish": "Twofish", "idea": "IDEA", "des": "DES", "safer": "SAFER", "camellia_128": "Camellia", "camellia_256": "Camellia"}),
    _r(r"\bnew\s+(?:PGPEncryptedDataGenerator|PGPSignatureGenerator|PGPKeyRingGenerator)\s*\(", _C, "bcpg", algorithm="PGP", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:Ed25519PrivateKeyParameters|Ed25519PublicKeyParameters)\s*\(", _S, _BC, algorithm="Ed25519"),
    _r(r"\bnew\s+(?:X25519PrivateKeyParameters|X25519PublicKeyParameters)\s*\(", _KA, _BC, algorithm="X25519"),
    _r(r"\bnew\s+(?:RSAKeyParameters|RSAPrivateCrtKeyParameters|RSAKeyGenerationParameters)\s*\(", _K, _BC, algorithm="RSA"),
    _r(r"\bnew\s+(?:ECPrivateKeyParameters|ECPublicKeyParameters|ECKeyGenerationParameters|ECDomainParameters|ECNamedCurveTable)\s*\(|\bECNamedCurveTable\.getParameterSpec\s*\(|\bSECNamedCurves\.getByName\s*\(|\bCustomNamedCurves\.getByName\s*\(", _K, _BC, algorithm="ECDSA"),
    _r(r"\bnew\s+(?:DSAKeyGenerationParameters|DSAParameters|DSAPrivateKeyParameters)\s*\(", _K, _BC, algorithm="DSA"),
    _r(r"\bnew\s+(?:DHParameters|DHKeyGenerationParameters|DHPrivateKeyParameters)\s*\(", _KA, _BC, algorithm="DH"),
    _r(r"\bnew\s+(?:PaddedBufferedBlockCipher|BufferedBlockCipher|DefaultBufferedBlockCipher)\s*\(", _C, _BC, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bnew\s+(?:PKCS7Padding|PKCS5Padding|ISO10126d2Padding|ISO7816d4Padding|X923Padding|ZeroBytePadding|TBCPadding)\s*\(", _C, _BC, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bnew\s+(?:KeyParameter|ParametersWithIV|ParametersWithRandom|AEADParameters|ParametersWithSalt)\s*\(", _C, _BC, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bMlKemParameters\.(ml_kem_512|ml_kem_768|ml_kem_1024)\b|\bKyberParameterSpec\.(kyber512|kyber768|kyber1024)\b|\bMLKEMParameterSpec\.(ml_kem_512|ml_kem_768|ml_kem_1024)\b", _KA, _BC, algorithm="ML-KEM"),
    _r(r"\bMlDsaParameters\.(ml_dsa_44|ml_dsa_65|ml_dsa_87)\b|\bDilithiumParameterSpec\.(dilithium2|dilithium3|dilithium5)\b|\bMLDSAParameterSpec\.(ml_dsa_44|ml_dsa_65|ml_dsa_87)\b", _S, _BC, algorithm="ML-DSA"),
    _r(r"\bSlhDsaParameters\.\w+|\bSPHINCSPlusParameterSpec\.\w+|\bSLHDSAParameterSpec\.\w+", _S, _BC, algorithm="SLH-DSA"),
    _r(r"\bFalconParameterSpec\.\w+|\bFalconParameters\.\w+", _S, _BC, algorithm="Falcon"),
    _r(r"\bNTRUParameterSpec\.\w+|\bFrodoParameterSpec\.\w+|\bBIKEParameterSpec\.\w+|\bHQCParameterSpec\.\w+", _KA, _BC, algorithm="PQC-KEM", confidence="MEDIUM"),
    _r(r"\bXMSSParameterSpec\.\w+|\bLMSParameters\.\w+|\bXMSSMTParameterSpec\.\w+|\bLMSKeyGenParameterSpec\b", _S, _BC, algorithm="XMSS", confidence="MEDIUM"),
    # ------------------------------------------------------------- Scala / Play / Akka
    _r(r"\bplay\.api\.libs\.Crypto\b|\bCrypto\.(?:encryptAES|decryptAES|sign|generateSignedToken)\s*\(", _C, "play", algorithm="AES"),
    _r(r"\bCrypto\.sign\s*\(", _M, "play", algorithm="HMAC-SHA1"),
    _r(r"\bplay\.api\.libs\.crypto\.(?:CookieSigner|CSRFTokenSigner|AESCTRCrypter|AESCrypter)\b|\bcookieSigner\.sign\s*\(", _M, "play", algorithm="HMAC-SHA1", confidence="MEDIUM"),
    _r(r"\bcom\.roundeights\.hasher\.Implicits\b|\b\.\s*(md5|sha1|sha256|sha384|sha512|bcrypt|crc32|pbkdf2|hmac)\b(?=\s*(?:\.hex|\.bytes|\.hash|\())", _D, "hasher", algo_from_group=1,
       algo_map={"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "bcrypt": "BCRYPT", "pbkdf2": "PBKDF2", "hmac": "HMAC"}, confidence="MEDIUM"),
    _r(r"\bcom\.github\.t3hnar\.bcrypt\b|\b\.\s*bcrypt(?:Bounded|SafeBounded)?\b|\b\.\s*isBcrypted(?:Bounded|SafeBounded)?\b", _KDF, "scala-bcrypt", algorithm="BCRYPT"),
    _r(r"\bpdi\.jwt\.(?:Jwt|JwtAlgorithm|JwtCirce|JwtJson|JwtPlayJson|JwtUpickle|JwtSprayJson|JwtArgonaut)\b|\bJwtAlgorithm\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|EdDSA|Ed25519)\b|\bJwt\.(?:encode|decode|decodeRaw|decodeAll|isValid|validate)\s*\(", _S, "jwt-scala", algo_from_group=1, algo_map={**_JWT_ALGS, "ed25519": "EdDSA"}),
    _r(r"\bpdi\.jwt\.(?:Jwt|JwtAlgorithm|JwtCirce|JwtJson)\b|\bJwt\.(?:encode|decode|decodeRaw|decodeAll|isValid|validate)\s*\(", _S, "jwt-scala", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\btsec\.\w+|\bAES128GCM\b|\bAES256GCM\b|\bAES128CTR\b|\bAES256CTR\b|\bAES128CBC\b|\bAES256CBC\b|\bXChaCha20Poly1305\b", _C, "tsec", algorithm="AES", confidence="MEDIUM"),
    _r(r"\bHMACSHA256\.(?:generateKey|sign|verify)\w*\b|\bHMACSHA512\.(?:generateKey|sign|verify)\w*\b|\bHMACSHA1\.(?:generateKey|sign|verify)\w*\b", _M, "tsec", algorithm="HMAC"),
    _r(r"\bSHA256\.(?:hash|hashPure|hashToString)\b|\bSHA1\.(?:hash|hashPure|hashToString)\b|\bMD5\.(?:hash|hashPure|hashToString)\b|\bSHA512\.(?:hash|hashPure|hashToString)\b", _D, "tsec", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bSCrypt\.(?:hashpw|checkpw)\w*\b|\bHardenedSCrypt\.(?:hashpw|checkpw)\w*\b", _KDF, "tsec", algorithm="SCRYPT"),
    _r(r"\bBCrypt\.(?:hashpw|checkpw)\w*\[", _KDF, "tsec", algorithm="BCRYPT"),
    _r(r"\bJWTMac\.(?:build|verifyFromString|verifyAndParse)\w*\b|\bJWSMacCV\b|\bJWTMacImpure\b", _S, "tsec", algorithm="JWT"),
    _r(r"\bakka\.http\.scaladsl\.(?:HttpsConnectionContext|ConnectionContext)\b|\bConnectionContext\.https(?:Server|Client)?\s*\(|\bHttpsConnectionContext\s*\(", _TLS, "akka-http", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bakka\.stream\.TLS\b|\bTLSProtocol\.\w+|\bTLS\.apply\s*\(|\bTLSRole\.\w+", _TLS, "akka-stream", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bplay\.server\.https\.\w+|\bplay\.ws\.ssl\.\w+|\bws\.ssl\.(?:protocol|enabledProtocols|enabledCipherSuites)\b|\bDefaultSSLConfigParser\b|\bSSLConfigSettings\b|\bnew\s+SSLConfig\s*\(", _TLS, "play-ws", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bcom\.typesafe\.sslconfig\b|\bSSLConfigFactory\.parse\s*\(|\bsslConfig\.loose\.acceptAnyCertificate\s*=\s*true|\bacceptAnyCertificate\s*=\s*true", _TLS, "ssl-config", algorithm="TRUST-ALL", confidence_reason="certificate validation disabled"),
    _r(r"\bcom\.typesafe\.sslconfig\b|\bSSLConfigFactory\.parse\s*\(", _TLS, "ssl-config", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bsttp\.client\d?\.\w+|\bHttpClientSyncBackend\s*\(|\bAsyncHttpClientBackend\b", _TLS, "sttp", algorithm="TLS", confidence="LOW"),
    _r(r"\bcats\.effect\.std\.SecureRandom\b|\bSecureRandom\.javaSecuritySecureRandom\b", _RNG, "cats-effect", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bscala\.util\.Random\b(?=[^;]*(?:key|token|secret|password|salt|nonce))|\bRandom\.(?:nextBytes|alphanumeric)\b(?=[^;]*(?:key|token|secret|password|salt|nonce))", _RNG, "scala.util", algorithm="PRNG", confidence="MEDIUM", confidence_reason="scala.util.Random is not a CSPRNG"),
    _r(r"\bscala\.util\.Random\b|\bnew\s+Random\s*\(\s*\)|\bRandom\.nextInt\s*\(|\bRandom\.nextBytes\s*\(", _RNG, "scala.util", algorithm="PRNG", confidence="LOW"),
    # ------------------------------------------------------------- Reflection (Class.forName + getMethod("getInstance").invoke(null, "ALG"))
    _r(r"Class\.forName\s*\(\s*\"javax\.crypto\.Cipher\"\s*\)[\s\S]{0,400}?getMethod\s*\(\s*\"getInstance\"[\s\S]{0,200}?invoke\s*\(\s*null\s*,\s*\"([A-Za-z0-9/_\-]+)\"", _C, "javax.crypto", transformation_group=1, confidence="HIGH", confidence_reason="reflection-resolved-transformation"),
    _r(r"Class\.forName\s*\(\s*\"java\.security\.MessageDigest\"\s*\)[\s\S]{0,400}?getMethod\s*\(\s*\"getInstance\"[\s\S]{0,200}?invoke\s*\(\s*null\s*,\s*\"([A-Za-z0-9\-]+)\"", _D, "java.security", algo_from_group=1, algo_map=DIGEST_TOKENS, confidence="HIGH", confidence_reason="reflection-resolved-transformation"),
    _r(r"Class\.forName\s*\(\s*\"javax\.crypto\.Mac\"\s*\)[\s\S]{0,400}?getMethod\s*\(\s*\"getInstance\"[\s\S]{0,200}?invoke\s*\(\s*null\s*,\s*\"(Hmac[A-Za-z0-9\-]+)\"", _M, "javax.crypto", algorithm="HMAC", confidence="HIGH", confidence_reason="reflection-resolved-transformation"),
    _r(r"Class\.forName\s*\(\s*\"java\.security\.(?:Signature|KeyPairGenerator|KeyFactory)\"\s*\)[\s\S]{0,400}?getMethod\s*\(\s*\"getInstance\"[\s\S]{0,200}?invoke\s*\(\s*null\s*,\s*\"([A-Za-z0-9\-]+)\"", _S, "java.security", transformation_group=1, confidence="HIGH", confidence_reason="reflection-resolved-transformation"),
]


def run_java_rules(file_path: Path, repo_root: Path | None, source: str, language: str, scanner_id: str, seen: set[tuple[int, str]] | None = None) -> list[RawFinding]:
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=source,
        rules=RULES,
        language=language,
        scanner_id=scanner_id,
        confidence_reason="jvm-library-api",
        strip_comments=True,
        seen=seen,
    )
