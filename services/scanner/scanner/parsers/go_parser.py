"""Go crypto detector — stdlib ``crypto/*``, ``golang.org/x/crypto``, and the
common third-party ecosystem (jwt, bcrypt/argon2, nacl, age, minio/sio, tink,
cloudflare circl, filippo.io/edwards25519, go-jose, grpc credentials, etc.).

Import aliases are resolved before matching so ``import m "crypto/md5"`` +
``m.Sum(...)`` is seen as ``md5.Sum(...)``; ``math/rand`` and ``crypto/rand``
are disambiguated by import path.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import DIGEST_TOKENS, Rule, run_rules

SCANNER_ID = "static-go-scanner-v1.1"

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_KA = {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_X = {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.M), {**base, "library": library, **extra}


# crypto.Hash enum names → digest family
_CRYPTO_HASH = {
    "md4": "MD4", "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
    "sha512": "SHA-512", "sha512_224": "SHA-512", "sha512_256": "SHA-512", "sha3_224": "SHA3-224", "sha3_256": "SHA3-256",
    "sha3_384": "SHA3-384", "sha3_512": "SHA3-512", "ripemd160": "RIPEMD-160", "md5sha1": "MD5", "blake2s_256": "BLAKE2s",
    "blake2b_256": "BLAKE2b", "blake2b_384": "BLAKE2b", "blake2b_512": "BLAKE2b",
}
_TLS_VERSIONS = {"versionssl30": "SSLv3", "versiontls10": "TLS1.0", "versiontls11": "TLS1.1", "versiontls12": "TLS1.2", "versiontls13": "TLS1.3"}
_JWT_METHODS = {
    "hs256": "HS256", "hs384": "HS384", "hs512": "HS512", "rs256": "RS256", "rs384": "RS384", "rs512": "RS512", "es256": "ES256",
    "es384": "ES384", "es512": "ES512", "ps256": "PS256", "ps384": "PS384", "ps512": "PS512", "eddsa": "EdDSA", "none": "none",
}

RULES: list[Rule] = [
    _r(r"\bsslmode=(?:disable|allow|prefer)\b|\bssl-mode=(?:DISABLED|PREFERRED)\b|\bsslmode=disable\b", _TLS, "database/sql", algorithm="TLS-DISABLED", confidence="MEDIUM", confidence_reason="database connection without TLS (sslmode)"),
    # ------------------------------------------------------------ stdlib digests
    _r(r"\bmd4\.(?:Sum|New)\b", _D, "golang.org/x/crypto/md4", algorithm="MD4"),
    _r(r"\bmd5\.(?:Sum|New|SumHex|Size|BlockSize)\b", _D, "crypto/md5", algorithm="MD5"),
    _r(r"\bsha1\.(?:Sum|New)\b", _D, "crypto/sha1", algorithm="SHA-1"),
    _r(r"\bsha256\.(?:Sum224|New224)\b", _D, "crypto/sha256", algorithm="SHA-224"),
    _r(r"\bsha256\.(?:Sum256|New)\b", _D, "crypto/sha256", algorithm="SHA-256"),
    _r(r"\bsha512\.(?:Sum384|New384)\b", _D, "crypto/sha512", algorithm="SHA-384"),
    _r(r"\bsha512\.(?:Sum512|New|Sum512_256|Sum512_224|New512_256|New512_224)\b", _D, "crypto/sha512", algorithm="SHA-512"),
    _r(r"\bsha3\.(?:New224|Sum224)\b", _D, "golang.org/x/crypto/sha3", algorithm="SHA3-224"),
    _r(r"\bsha3\.(?:New256|Sum256|NewLegacyKeccak256|New)\b", _D, "golang.org/x/crypto/sha3", algorithm="SHA3-256"),
    _r(r"\bsha3\.(?:New384|Sum384)\b", _D, "golang.org/x/crypto/sha3", algorithm="SHA3-384"),
    _r(r"\bsha3\.(?:New512|Sum512|NewLegacyKeccak512)\b", _D, "golang.org/x/crypto/sha3", algorithm="SHA3-512"),
    _r(r"\bsha3\.(?:NewShake128|ShakeSum128|NewCShake128)\b", _D, "golang.org/x/crypto/sha3", algorithm="SHAKE128"),
    _r(r"\bsha3\.(?:NewShake256|ShakeSum256|NewCShake256)\b", _D, "golang.org/x/crypto/sha3", algorithm="SHAKE256"),
    _r(r"\bblake2b\.(?:New256|New384|New512|Sum256|Sum384|Sum512|New|NewXOF)\b", _D, "golang.org/x/crypto/blake2b", algorithm="BLAKE2b"),
    _r(r"\bblake2s\.(?:New256|New128|Sum256|NewXOF)\b", _D, "golang.org/x/crypto/blake2s", algorithm="BLAKE2s"),
    _r(r"\bblake3\.(?:New|Sum256|Sum512|NewDeriveKey|NewKeyed)\b", _D, "github.com/zeebo/blake3", algorithm="BLAKE3"),
    _r(r"\bripemd160\.New\b", _D, "golang.org/x/crypto/ripemd160", algorithm="RIPEMD-160"),
    _r(r"\bsm3\.(?:New|Sum)\b", _D, "sm3", algorithm="SM3"),
    _r(r"\bcrypto\.(MD4|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA512_224|SHA512_256|SHA3_224|SHA3_256|SHA3_384|SHA3_512|RIPEMD160|MD5SHA1|BLAKE2s_256|BLAKE2b_256|BLAKE2b_384|BLAKE2b_512)\b", _D, "crypto", algo_from_group=1, algo_map=_CRYPTO_HASH),
    # ------------------------------------------------------------ stdlib ciphers / modes
    _r(r"\baes\.NewCipher\b", _C, "crypto/aes", algorithm="AES"),
    _r(r"\baes\.NewGCM\b", _C, "crypto/aes", algorithm="AES", mode="GCM"),
    _r(r"\bcipher\.NewGCM(?:WithNonceSize|WithTagSize|WithRandomNonce)?\b", _C, "crypto/cipher", algorithm="AES", mode="GCM", confidence="MEDIUM", confidence_reason="GCM wraps a block cipher (AES unless another block is passed)"),
    _r(r"\bcipher\.NewCBCEncrypter\b|\bcipher\.NewCBCDecrypter\b", _C, "crypto/cipher", algorithm="AES", mode="CBC", confidence="MEDIUM"),
    _r(r"\bcipher\.NewCTR\b", _C, "crypto/cipher", algorithm="AES", mode="CTR", confidence="MEDIUM"),
    _r(r"\bcipher\.NewCFBEncrypter\b|\bcipher\.NewCFBDecrypter\b", _C, "crypto/cipher", algorithm="AES", mode="CFB", confidence="MEDIUM"),
    _r(r"\bcipher\.NewOFB\b", _C, "crypto/cipher", algorithm="AES", mode="OFB", confidence="MEDIUM"),
    _r(r"\bcipher\.StreamReader\b|\bcipher\.StreamWriter\b", _C, "crypto/cipher", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bdes\.NewTripleDESCipher\b", _C, "crypto/des", algorithm="3DES"),
    _r(r"\bdes\.NewCipher\b", _C, "crypto/des", algorithm="DES"),
    _r(r"\brc4\.NewCipher\b", _C, "crypto/rc4", algorithm="RC4"),
    _r(r"\bblowfish\.(?:NewCipher|NewSaltedCipher|ExpandKey)\b", _C, "golang.org/x/crypto/blowfish", algorithm="Blowfish"),
    _r(r"\bcast5\.NewCipher\b", _C, "golang.org/x/crypto/cast5", algorithm="CAST5"),
    _r(r"\btwofish\.NewCipher\b", _C, "golang.org/x/crypto/twofish", algorithm="Twofish"),
    _r(r"\bxtea\.NewCipher\b|\btea\.NewCipher(?:WithRounds)?\b", _C, "golang.org/x/crypto/xtea", algorithm="XTEA"),
    _r(r"\bsalsa20\.XORKeyStream\b|\bsalsa\.XORKeyStream\b|\bsalsa\.HSalsa20\b", _C, "golang.org/x/crypto/salsa20", algorithm="Salsa20"),
    _r(r"\bchacha20\.NewUnauthenticatedCipher\b|\bchacha20\.HChaCha20\b", _C, "golang.org/x/crypto/chacha20", algorithm="ChaCha20"),
    _r(r"\bchacha20poly1305\.NewX\b", _C, "golang.org/x/crypto/chacha20poly1305", algorithm="XChaCha20-Poly1305"),
    _r(r"\bchacha20poly1305\.New\b", _C, "golang.org/x/crypto/chacha20poly1305", algorithm="ChaCha20-Poly1305"),
    _r(r"\bpoly1305\.(?:Sum|Verify|New)\b", _M, "golang.org/x/crypto/poly1305", algorithm="Poly1305"),
    _r(r"\bsecretbox\.(?:Seal|Open|EasySeal|EasyOpen)\b", _C, "golang.org/x/crypto/nacl/secretbox", algorithm="XSalsa20-Poly1305"),
    _r(r"\bbox\.(?:Seal|Open|GenerateKey|Precompute|SealAnonymous|OpenAnonymous|SealAfterPrecomputation|OpenAfterPrecomputation)\b", _C, "golang.org/x/crypto/nacl/box", algorithm="X25519"),
    _r(r"\bbox\.(?:Seal|Open|SealAnonymous|OpenAnonymous)\b", _C, "golang.org/x/crypto/nacl/box", algorithm="XSalsa20-Poly1305"),
    _r(r"\bsign\.(?:GenerateKey|Sign|Open)\b", _S, "golang.org/x/crypto/nacl/sign", algorithm="Ed25519", confidence="MEDIUM"),
    _r(r"\bauth\.(?:Sum|Verify)\b", _M, "golang.org/x/crypto/nacl/auth", algorithm="HMAC-SHA512", confidence="MEDIUM"),
    _r(r"\bsm4\.NewCipher\b", _C, "sm4", algorithm="SM4"),
    _r(r"\bxts\.NewCipher\b", _C, "golang.org/x/crypto/xts", algorithm="AES", mode="XTS", confidence="MEDIUM"),
    _r(r"\bsiv\.NewGCM\b|\bsiv\.NewCMAC\b|\bmiscreant\.\w+", _C, "miscreant", algorithm="AES", mode="SIV"),
    _r(r"\bkeywrap\.(?:Wrap|Unwrap)\b|\bsubtle\.XORBytes\b", _C, "keywrap", algorithm="AES", mode="KW", confidence="MEDIUM"),
    # ------------------------------------------------------------ MAC / KDF
    _r(r"\bhmac\.New\s*\(\s*(md5|sha1|sha256|sha512|sha3|blake2b|blake2s|ripemd160)\.(?:New\w*|Sum\w*)", _M, "crypto/hmac", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bhmac\.New\s*\(\s*func\s*\(\)\s*hash\.Hash\s*\{\s*return\s+(md5|sha1|sha256|sha512|sha3|blake2b)\.", _M, "crypto/hmac", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bhmac\.(?:New|Equal)\b", _M, "crypto/hmac", algorithm="HMAC"),
    _r(r"\bcmac\.New\b|\bcmac\.Sum\b", _M, "cmac", algorithm="CMAC"),
    _r(r"\bpbkdf2\.Key\s*\([^)]*?,\s*(md5|sha1|sha256|sha512|sha3|blake2b)\.New\w*\b", _KDF, "golang.org/x/crypto/pbkdf2", algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bpbkdf2\.Key\s*\(\s*(md5|sha1|sha256|sha512|sha3)\.New\w*\b", _KDF, "crypto/pbkdf2", algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bpbkdf2\.Key\b", _KDF, "golang.org/x/crypto/pbkdf2", algorithm="PBKDF2"),
    _r(r"\bscrypt\.(?:Key|GenerateFromPassword|CompareHashAndPassword)\b", _KDF, "golang.org/x/crypto/scrypt", algorithm="SCRYPT"),
    _r(r"\bargon2\.(?:IDKey|Key)\b|\bargon2id\.(?:CreateHash|ComparePasswordAndHash)\b", _KDF, "golang.org/x/crypto/argon2", algorithm="ARGON2"),
    _r(r"\bbcrypt\.(?:GenerateFromPassword|CompareHashAndPassword|Cost)\b", _KDF, "golang.org/x/crypto/bcrypt", algorithm="BCRYPT"),
    _r(r"\bhkdf\.(?:New|Expand|Extract|Key)\s*\(\s*(md5|sha1|sha256|sha512|sha3|blake2b)\.New\w*\b", _KDF, "golang.org/x/crypto/hkdf", algorithm="HKDF", emit_digest_group=1, purpose="KEY_GENERATION"),
    _r(r"\bhkdf\.(?:New|Expand|Extract|Key)\b", _KDF, "golang.org/x/crypto/hkdf", algorithm="HKDF", purpose="KEY_GENERATION"),
    _r(r"\bcrypt\.(?:Crypt|Sha512Crypt|Sha256Crypt|Md5Crypt|ApR1Crypt)\b|\bsha512_crypt\.\w+|\bsha256_crypt\.\w+|\bmd5_crypt\.\w+|\bapr1_crypt\.\w+", _KDF, "github.com/GehirnInc/crypt", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bmd5_crypt\.\w+|\bapr1_crypt\.\w+", _KDF, "github.com/GehirnInc/crypt", algorithm="MD5"),
    _r(r"\bsha512_crypt\.\w+", _KDF, "github.com/GehirnInc/crypt", algorithm="SHA-512"),
    _r(r"\bsha256_crypt\.\w+", _KDF, "github.com/GehirnInc/crypt", algorithm="SHA-256"),
    _r(r"\bx/crypto/openpgp\b|\bopenpgp\.(?:Encrypt|Decrypt|ReadMessage|NewEntity|DetachSign|CheckDetachedSignature|ReadKeyRing|ReadArmoredKeyRing|Sign)\b", _C, "golang.org/x/crypto/openpgp", algorithm="PGP", confidence="MEDIUM"),
    _r(r"\bpacket\.Config\{[^}]*DefaultCipher\s*:\s*packet\.Cipher(AES128|AES192|AES256|3DES|CAST5)\b", _C, "openpgp", algo_from_group=1, algo_map={"aes128": "AES", "aes192": "AES", "aes256": "AES", "3des": "3DES", "cast5": "CAST5"}),
    _r(r"\bpacket\.Config\{[^}]*DefaultHash\s*:\s*crypto\.(SHA1|SHA256|SHA512|MD5|RIPEMD160)\b", _D, "openpgp", algo_from_group=1, algo_map=_CRYPTO_HASH),
    _r(r"\bage\.(?:Encrypt|Decrypt|NewScryptRecipient|NewScryptIdentity|GenerateX25519Identity|ParseX25519Recipient|ParseX25519Identity|ParseIdentities|ParseRecipients)\b", _C, "filippo.io/age", algorithm="ChaCha20-Poly1305"),
    _r(r"\bage\.(?:GenerateX25519Identity|ParseX25519Recipient|ParseX25519Identity|NewX25519Recipient)\b", _KA, "filippo.io/age", algorithm="X25519"),
    _r(r"\bage\.NewScrypt(?:Recipient|Identity)\b", _KDF, "filippo.io/age", algorithm="SCRYPT"),
    _r(r"\bsio\.(?:Encrypt|Decrypt|EncryptReader|DecryptReader|EncryptWriter|DecryptWriter|Config)\b|\bsio\.(AES_256_GCM|CHACHA20_POLY1305)\b", _C, "github.com/minio/sio", algorithm="AES", mode="GCM", confidence="MEDIUM"),
    _r(r"\bsio\.CHACHA20_POLY1305\b", _C, "github.com/minio/sio", algorithm="ChaCha20-Poly1305"),
    _r(r"\bfernet\.(?:EncryptAndSign|VerifyAndDecrypt|DecodeKey|DecodeKeys|Key)\b", _C, "github.com/fernet/fernet-go", algorithm="AES", mode="CBC"),
    _r(r"\bfernet\.(?:EncryptAndSign|VerifyAndDecrypt)\b", _M, "github.com/fernet/fernet-go", algorithm="HMAC-SHA256"),
    _r(r"\bsecurecookie\.(?:New|GenerateRandomKey|EncodeMulti|DecodeMulti)\b|\bsessions\.NewCookieStore\b", _M, "github.com/gorilla/securecookie", algorithm="HMAC-SHA256", confidence="MEDIUM"),
    _r(r"\bsecurecookie\.New\s*\(\s*[^,]+,\s*[^)n]", _C, "github.com/gorilla/securecookie", algorithm="AES", mode="CTR", confidence="MEDIUM"),
    # ------------------------------------------------------------ Tink / KMS wrappers
    _r(r"\baead\.(?:AES128GCMKeyTemplate|AES256GCMKeyTemplate|AES256GCMNoPrefixKeyTemplate|AES128CTRHMACSHA256KeyTemplate|AES256CTRHMACSHA256KeyTemplate|AES128GCMSIVKeyTemplate|AES256GCMSIVKeyTemplate)\b", _C, "tink", algorithm="AES", mode="GCM"),
    _r(r"\baead\.(?:ChaCha20Poly1305KeyTemplate|XChaCha20Poly1305KeyTemplate)\b", _C, "tink", algorithm="ChaCha20-Poly1305"),
    _r(r"\baead\.New\s*\(|\baead\.NewKMSEnvelopeAEAD2?\b|\bdaead\.New\s*\(|\bdaead\.AESSIVKeyTemplate\b|\bstreamingaead\.\w+KeyTemplate\b|\bhybrid\.\w+KeyTemplate\b|\bhybrid\.NewHybridEncrypt\b|\bhybrid\.NewHybridDecrypt\b", _C, "tink", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bmac\.(?:HMACSHA256Tag128KeyTemplate|HMACSHA256Tag256KeyTemplate|HMACSHA512Tag256KeyTemplate|HMACSHA512Tag512KeyTemplate)\b", _M, "tink", algorithm="HMAC"),
    _r(r"\bmac\.AESCMACTag128KeyTemplate\b", _M, "tink", algorithm="CMAC"),
    _r(r"\bsignature\.(?:ECDSAP256KeyTemplate|ECDSAP256KeyWithoutPrefixTemplate|ECDSAP384KeyTemplate|ECDSAP384SHA384KeyTemplate|ECDSAP521KeyTemplate)\b", _S, "tink", algorithm="ECDSA"),
    _r(r"\bsignature\.ED25519KeyTemplate\b|\bsignature\.ED25519KeyWithoutPrefixTemplate\b", _S, "tink", algorithm="Ed25519"),
    _r(r"\bsignature\.RSA_SSA_\w+KeyTemplate\b|\bsignature\.RSASSAPKCS1\w+KeyTemplate\b|\bsignature\.RSASSAPSS\w+KeyTemplate\b", _S, "tink", algorithm="RSA"),
    _r(r"\bsignature\.NewSigner\b|\bsignature\.NewVerifier\b|\bmac\.New\s*\(|\bprf\.\w+KeyTemplate\b|\bkeyset\.NewHandle\b|\bkeyset\.Read\b|\bkeyset\.Write\b", _S, "tink", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bkms\.(?:New|Encrypt|Decrypt|GenerateDataKey|Sign|Verify)\w*\b|\bkmsClient\.(?:Encrypt|Decrypt|GenerateDataKey|Sign)\b|\bcloudkms\.\w+|\bawskms\.\w+|\bgcpkms\.\w+|\bazurekeyvault\.\w+|\bvault\.NewClient\b|\btransit\.\w+", _C, "kms", algorithm="KMS", confidence="LOW"),
    # ------------------------------------------------------------ asymmetric
    _r(r"\brsa\.GenerateKey\s*\(\s*[^,]+,\s*(\d{3,5})", _K, "crypto/rsa", algorithm="RSA", key_from_group=1),
    _r(r"\brsa\.(?:GenerateKey|GenerateMultiPrimeKey)\b", _K, "crypto/rsa", algorithm="RSA"),
    _r(r"\brsa\.(?:EncryptPKCS1v15|DecryptPKCS1v15|DecryptPKCS1v15SessionKey)\b", _C, "crypto/rsa", algorithm="RSA", padding="PKCS1v15", confidence_reason="rsa-pkcs1v15-padding"),
    _r(r"\brsa\.(?:EncryptOAEP|DecryptOAEP)\s*\(\s*(md5|sha1|sha256|sha512|sha3)\.New\w*\b", _C, "crypto/rsa", algorithm="RSA", padding="OAEP", emit_digest_group=1),
    _r(r"\brsa\.(?:EncryptOAEP|DecryptOAEP)\b", _C, "crypto/rsa", algorithm="RSA", padding="OAEP"),
    _r(r"\brsa\.(?:SignPKCS1v15|VerifyPKCS1v15)\s*\([^,]*,\s*[^,]*,\s*crypto\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|MD5SHA1|RIPEMD160)\b", _S, "crypto/rsa", algorithm="RSA", emit_digest_group=1, padding="PKCS1v15"),
    _r(r"\brsa\.(?:SignPSS|VerifyPSS)\s*\([^,]*,\s*[^,]*,\s*crypto\.(SHA1|SHA224|SHA256|SHA384|SHA512)\b", _S, "crypto/rsa", algorithm="RSA", emit_digest_group=1, padding="PSS"),
    _r(r"\brsa\.(?:SignPKCS1v15|VerifyPKCS1v15|SignPSS|VerifyPSS)\b|\brsa\.PSSOptions\b", _S, "crypto/rsa", algorithm="RSA"),
    _r(r"\brsa\.(?:PrivateKey|PublicKey)\b|\brsa\.(?:PSSSaltLengthAuto|PSSSaltLengthEqualsHash)\b", _K, "crypto/rsa", algorithm="RSA", confidence="MEDIUM"),
    _r(r"\becdsa\.GenerateKey\s*\(\s*elliptic\.(P224|P256|P384|P521)\s*\(", _K, "crypto/ecdsa", algorithm="ECDSA", key_from_group=None),
    _r(r"\becdsa\.GenerateKey\b|\becdsa\.(?:PrivateKey|PublicKey)\b", _K, "crypto/ecdsa", algorithm="ECDSA"),
    _r(r"\becdsa\.(?:Sign|SignASN1|Verify|VerifyASN1)\b", _S, "crypto/ecdsa", algorithm="ECDSA"),
    _r(r"\belliptic\.(?:P224|P256|P384|P521)\s*\(", _K, "crypto/elliptic", algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bsecp256k1\.(?:S256|Sign|VerifySignature|RecoverPubkey|GenerateKey|NewPrivateKey)\b|\bbtcec\.(?:S256|NewPrivateKey|ParsePubKey|SignCompact|RecoverCompact)\b|\bethcrypto\.(?:Sign|SigToPub|Ecrecover|GenerateKey|VerifySignature)\b|\bcrypto\.(?:Sign|SigToPub|Ecrecover|GenerateKey|VerifySignature|Keccak256|Keccak256Hash|ToECDSA|HexToECDSA|PubkeyToAddress)\s*\(", _S, "secp256k1", algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bcrypto\.Keccak256(?:Hash)?\s*\(|\bsha3\.NewLegacyKeccak256\b", _D, "go-ethereum", algorithm="SHA3-256"),
    _r(r"\bed25519\.GenerateKey\b|\bed25519\.NewKeyFromSeed\b|\bed25519\.(?:PrivateKey|PublicKey)\b", _K, "crypto/ed25519", algorithm="Ed25519"),
    _r(r"\bed25519\.(?:Sign|Verify|VerifyWithOptions)\b|\bedwards25519\.\w+", _S, "crypto/ed25519", algorithm="Ed25519"),
    _r(r"\bed448\.\w+\b", _S, "circl/sign/ed448", algorithm="Ed448"),
    _r(r"\bcurve25519\.(?:X25519|ScalarMult|ScalarBaseMult)\b", _KA, "golang.org/x/crypto/curve25519", algorithm="X25519"),
    _r(r"\becdh\.X25519\s*\(", _KA, "crypto/ecdh", algorithm="X25519"),
    _r(r"\becdh\.(?:P256|P384|P521)\s*\(|\becdh\.(?:Curve|PrivateKey|PublicKey)\b", _KA, "crypto/ecdh", algorithm="ECDH"),
    _r(r"\bdsa\.(?:GenerateKey|GenerateParameters|Sign|Verify)\b|\bdsa\.(?:L1024N160|L2048N224|L2048N256|L3072N256)\b", _K, "crypto/dsa", algorithm="DSA"),
    _r(r"\bdh\.(?:GenerateKey|NewParams|RFC3526_\d+|Group\d+)\b|\bdhkx\.(?:GetGroup|GeneratePrivateKey|ComputeKey)\b", _KA, "dh", algorithm="DH"),
    _r(r"\bkyber\d*\.\w+|\bmlkem\d*\.\w+|\bkem/(?:kyber|mlkem)\b|\bhpke\.\w+", _KA, "circl", algorithm="ML-KEM", confidence="MEDIUM"),
    _r(r"\bmlkem\.(?:GenerateKey768|GenerateKey1024|NewDecapsulationKey768|NewEncapsulationKey768|NewDecapsulationKey1024|NewEncapsulationKey1024)\b", _KA, "crypto/mlkem", algorithm="ML-KEM"),
    _r(r"\bdilithium\d*\.\w+|\bmldsa\d+\.\w+|\bsign/(?:dilithium|mldsa)\b", _S, "circl", algorithm="ML-DSA"),
    _r(r"\bsphincs\w*\.\w+|\bslhdsa\.\w+", _S, "circl", algorithm="SLH-DSA"),
    _r(r"\bfalcon\d*\.\w+", _S, "pqc", algorithm="FALCON"),
    _r(r"\bfrodo\w*\.\w+|\bsike\w*\.\w+|\bsidh\.\w+|\bntru\w*\.\w+|\bhqc\w*\.\w+|\bbike\w*\.\w+", _KA, "pqc", algorithm="PQC-KEM", confidence="MEDIUM"),
    _r(r"\bliboqs\b|\boqs\.(?:KeyEncapsulation|Signature)\b|\boqs\.(?:KemInit|SigInit)\b", _KA, "liboqs-go", algorithm="PQC", confidence="MEDIUM"),
    _r(r"\bbls\.\w+\s*\(|\bbls12381\.\w+|\bkyber\.G1\b|\bkilic/bls12-381\b|\bherumi/bls\b", _S, "bls", algorithm="BLS", confidence="MEDIUM"),
    # ------------------------------------------------------------ x509 / SSH / PGP / OCSP
    _r(r"\bx509\.(?:CreateCertificate|ParseCertificate|ParseCertificates|MarshalPKIXPublicKey|ParsePKIXPublicKey|MarshalPKCS1PrivateKey|ParsePKCS1PrivateKey|MarshalPKCS8PrivateKey|ParsePKCS8PrivateKey|MarshalECPrivateKey|ParseECPrivateKey|EncryptPEMBlock|DecryptPEMBlock|NewCertPool|SystemCertPool|CreateCertificateRequest|ParseCertificateRequest|CreateRevocationList|ParseRevocationList|Certificate|CertPool)\b", _X, "crypto/x509", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bx509\.EncryptPEMBlock\s*\(", _C, "crypto/x509", algorithm="DES", confidence="MEDIUM", confidence_reason="EncryptPEMBlock uses legacy PEM encryption (MD5-based KDF)"),
    _r(r"\bx509\.PEMCipher(DES|3DES|AES128|AES192|AES256)\b", _C, "crypto/x509", algo_from_group=1, algo_map={"des": "DES", "3des": "3DES", "aes128": "AES", "aes192": "AES", "aes256": "AES"}),
    _r(r"\bx509\.(MD2WithRSA|MD5WithRSA|SHA1WithRSA|SHA256WithRSA|SHA384WithRSA|SHA512WithRSA|SHA256WithRSAPSS|SHA384WithRSAPSS|SHA512WithRSAPSS)\b", _S, "crypto/x509", algorithm="RSA", emit_digest_group=None),
    _r(r"\bx509\.(?:MD2|MD5|SHA1|SHA256|SHA384|SHA512)With(?:RSA|ECDSA|DSA)(?:PSS)?\b", _S, "crypto/x509", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bx509\.(MD2|MD5|SHA1|SHA256|SHA384|SHA512)With(?:RSA|ECDSA|DSA)(?:PSS)?\b", _D, "crypto/x509", algo_from_group=1, algo_map=_CRYPTO_HASH),
    _r(r"\bx509\.(?:DSAWithSHA1|DSAWithSHA256)\b", _S, "crypto/x509", algorithm="DSA"),
    _r(r"\bx509\.(?:ECDSAWithSHA1|ECDSAWithSHA256|ECDSAWithSHA384|ECDSAWithSHA512)\b", _S, "crypto/x509", algorithm="ECDSA"),
    _r(r"\bx509\.PureEd25519\b", _S, "crypto/x509", algorithm="Ed25519"),
    _r(r"\bx509\.(?:RSA|ECDSA|Ed25519|DSA)\b(?!\w)", _K, "crypto/x509", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bpem\.(?:Decode|Encode|EncodeToMemory)\b", _X, "encoding/pem", algorithm="X509", confidence="LOW"),
    _r(r"\bssh\.(?:NewPublicKey|ParsePrivateKey|ParsePrivateKeyWithPassphrase|ParseRawPrivateKey|ParseAuthorizedKey|ParsePublicKey|NewSignerFromKey|NewSignerFromSigner|FingerprintSHA256|FingerprintLegacyMD5|Dial|NewClient|NewServerConn|NewClientConn|NewSession|ClientConfig|ServerConfig|InsecureIgnoreHostKey|FixedHostKey|PublicKeys|Password|KeyboardInteractive|MarshalAuthorizedKey|MarshalPrivateKey|MarshalPrivateKeyWithPassphrase|CertChecker|NewCertSigner|Certificate)\b", _S, "golang.org/x/crypto/ssh", algorithm="SSH", confidence="MEDIUM"),
    _r(r"\bssh\.InsecureIgnoreHostKey\s*\(", {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}, "golang.org/x/crypto/ssh", algorithm="SSH-HOSTKEY-NONE", confidence_reason="SSH host key verification disabled"),
    _r(r"\bssh\.FingerprintLegacyMD5\b", _D, "golang.org/x/crypto/ssh", algorithm="MD5"),
    _r(r"\bssh\.(?:KeyAlgoRSA|SigAlgoRSA|KeyAlgoRSASHA256|KeyAlgoRSASHA512|SigAlgoRSASHA2256|SigAlgoRSASHA2512|CertAlgoRSAv01)\b|\bssh\.InsecureAlgorithms\b", _S, "golang.org/x/crypto/ssh", algorithm="RSA"),
    _r(r"\bssh\.(?:KeyAlgoDSA|CertAlgoDSAv01)\b", _S, "golang.org/x/crypto/ssh", algorithm="DSA"),
    _r(r"\bssh\.(?:KeyAlgoECDSA256|KeyAlgoECDSA384|KeyAlgoECDSA521|KeyAlgoSKECDSA256|CertAlgoECDSA\w+)\b", _S, "golang.org/x/crypto/ssh", algorithm="ECDSA"),
    _r(r"\bssh\.(?:KeyAlgoED25519|KeyAlgoSKED25519|CertAlgoED25519v01)\b", _S, "golang.org/x/crypto/ssh", algorithm="Ed25519"),
    _r(r"\bknownhosts\.New\b|\bagent\.NewClient\b|\bagent\.NewKeyring\b|\bsftp\.NewClient\b|\bgliderlabs/ssh\b|\bgossh\.\w+", _S, "ssh", algorithm="SSH", confidence="MEDIUM"),
    _r(r"\bocsp\.(?:CreateRequest|ParseResponse|ParseResponseForCert|CreateResponse|ParseRequest)\b", _X, "golang.org/x/crypto/ocsp", algorithm="OCSP", confidence="MEDIUM"),
    _r(r"\bpkcs12\.(?:Decode|ToPEM|Encode|Modern|Legacy|DecodeChain|DecodeTrustStore)\b", _X, "software.sslmate.com/src/go-pkcs12", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bpkcs12\.(?:Decode|ToPEM|Legacy)\b", _C, "go-pkcs12", algorithm="3DES", confidence="MEDIUM", confidence_reason="legacy PKCS#12 uses RC2/3DES PBE"),
    _r(r"\bpkcs7\.(?:Encrypt|Decrypt|Sign|Verify|Parse|NewSignedData)\b|\bpkcs7\.EncryptionAlgorithm(DESCBC|AES128CBC|AES256CBC|AES128GCM|AES256GCM)\b", _C, "go.mozilla.org/pkcs7", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bpkcs7\.EncryptionAlgorithm(DESCBC|AES128CBC|AES256CBC|AES128GCM|AES256GCM)\b", _C, "go.mozilla.org/pkcs7", algo_from_group=1, algo_map={"descbc": "DES", "aes128cbc": "AES", "aes256cbc": "AES", "aes128gcm": "AES", "aes256gcm": "AES"}),
    _r(r"\bpkcs11\.(?:New|Ctx)\b|\bp11\.\w+|\bcrypto11\.\w+|\byubihsm\.\w+|\bpiv\.\w+\s*\(|\btpm2\.\w+|\bgo-tpm\b|\bgo-attestation\b", _K, "pkcs11", algorithm="HSM", confidence="LOW"),
    # ------------------------------------------------------------ TLS
    _r(r"\btls\.(VersionSSL30|VersionTLS10|VersionTLS11|VersionTLS12|VersionTLS13)\b", _TLS, "crypto/tls", algo_from_group=1, algo_map=_TLS_VERSIONS),
    _r(r"\bInsecureSkipVerify\s*:\s*true\b", _TLS, "crypto/tls", algorithm="TLS-CERT-NONE", confidence_reason="certificate verification disabled"),
    _r(r"\bVerifyPeerCertificate\s*:\s*func\s*\([^)]*\)\s*error\s*\{\s*return\s+nil\s*\}", _TLS, "crypto/tls", algorithm="TRUST-ALL", confidence_reason="custom verifier accepts every certificate"),
    _r(r"\btls\.(?:Listen|Dial|DialWithDialer|Server|Client|Config|NewListener|X509KeyPair|LoadX509KeyPair|Certificate|NewLRUClientSessionCache|Dialer|CipherSuites|InsecureCipherSuites|ConnectionState|RequireAndVerifyClientCert|RequireAnyClientCert|VerifyClientCertIfGiven|CurveP256|CurveP384|CurveP521|X25519|X25519MLKEM768|X25519Kyber768Draft00)\b", _TLS, "crypto/tls", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\btls\.(?:X25519MLKEM768|X25519Kyber768Draft00)\b", _KA, "crypto/tls", algorithm="ML-KEM"),
    _r(r"\btls\.(TLS_RSA_WITH_RC4_128_SHA|TLS_ECDHE_RSA_WITH_RC4_128_SHA|TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)\b", _C, "crypto/tls", algorithm="RC4", confidence_reason="RC4 cipher suite"),
    _r(r"\btls\.(TLS_RSA_WITH_3DES_EDE_CBC_SHA|TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)\b", _C, "crypto/tls", algorithm="3DES", confidence_reason="3DES cipher suite"),
    _r(r"\btls\.TLS_(?:RSA|ECDHE_RSA|ECDHE_ECDSA|AES_\d+|CHACHA20)_?\w*WITH_AES_(?:128|256)_(?:GCM|CBC)_SHA\w*\b|\btls\.TLS_AES_(?:128|256)_GCM_SHA\d+\b", _C, "crypto/tls", algorithm="AES", confidence="MEDIUM"),
    _r(r"\btls\.TLS_\w*CHACHA20_POLY1305\w*\b", _C, "crypto/tls", algorithm="ChaCha20-Poly1305", confidence="MEDIUM"),
    _r(r"\btls\.TLS_RSA_WITH_\w+\b", _KA, "crypto/tls", algorithm="RSA", confidence="MEDIUM", confidence_reason="static RSA key exchange (no forward secrecy)"),
    _r(r"\btls\.TLS_ECDHE_\w+\b", _KA, "crypto/tls", algorithm="ECDH", confidence="MEDIUM"),
    _r(r"\btls\.TLS_\w+_SHA\b(?!\d)", _D, "crypto/tls", algorithm="SHA-1", confidence="MEDIUM", confidence_reason="SHA-1 HMAC cipher suite"),
    _r(r"\bcredentials\.(?:NewTLS|NewClientTLSFromFile|NewServerTLSFromFile|NewClientTLSFromCert|NewServerTLSFromCert)\b|\bgrpc\.WithTransportCredentials\b|\bgrpc\.Creds\b|\bcredentials\.NewTLS\b", _TLS, "google.golang.org/grpc/credentials", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bgrpc\.WithInsecure\s*\(|\binsecure\.NewCredentials\s*\(", _TLS, "google.golang.org/grpc", algorithm="TLS-NONE", confidence="HIGH", confidence_reason="gRPC transport without TLS"),
    _r(r"\bhttp\.ListenAndServeTLS\b|\bServer\.ListenAndServeTLS\b|\bhttp\.Server\{[^}]*TLSConfig\s*:|\bTLSConfig\s*:\s*&tls\.Config\b|\bTLSClientConfig\s*:\s*&tls\.Config\b|\bautocert\.(?:NewListener|Manager)\b|\bacme\.\w+|\bcertmagic\.\w+|\blego\.\w+", _TLS, "net/http", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bquic\.(?:Dial|Listen|DialAddr|ListenAddr)\w*\b|\bhttp3\.\w+|\bwebtransport\.\w+", _TLS, "quic-go", algorithm="TLS1.3", confidence="MEDIUM"),
    _r(r"\bnoise\.(?:NewHandshakeState|NewCipherSuite|HandshakeXX|HandshakeIK|HandshakeNK|DH25519|CipherChaChaPoly|CipherAESGCM|HashSHA256|HashBLAKE2b|HashBLAKE2s)\b|\bwgtypes\.GenerateKey\b|\bwgtypes\.GeneratePrivateKey\b", _KA, "noise", algorithm="X25519", confidence="MEDIUM"),
    _r(r"\bwgtypes\.(?:GenerateKey|GeneratePrivateKey|GeneratePresharedKey)\b|\bwgctrl\.New\b|\bdevice\.NewDevice\b|\bwireguard\b", _C, "wireguard", algorithm="ChaCha20-Poly1305", confidence="MEDIUM"),
    _r(r"\butls\.\w+|\btls\.HelloChrome_\w+|\btls\.HelloFirefox_\w+|\btls\.HelloRandomized\b", _TLS, "utls", algorithm="TLS", confidence="LOW"),
    # ------------------------------------------------------------ JWT / JOSE / PASETO
    _r(r"\bjwt\.SigningMethod(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|None)\b", _S, "github.com/golang-jwt/jwt", algo_from_group=1, algo_map=_JWT_METHODS),
    _r(r"\bjwt\.(?:NewWithClaims|New|Parse|ParseWithClaims|ParseRSAPrivateKeyFromPEM|ParseRSAPublicKeyFromPEM|ParseECPrivateKeyFromPEM|ParseECPublicKeyFromPEM|ParseEdPrivateKeyFromPEM|ParseEdPublicKeyFromPEM|NewParser|NewValidator|WithValidMethods|WithLeeway|RegisteredClaims|MapClaims|StandardClaims|Token|Keyfunc|GetSigningMethod|RegisterSigningMethod|UnsafeAllowNoneSignatureType|WithoutClaimsValidation|Sign|Verify|Encrypt|Decrypt|NewSigner|NewEncrypter|ParseSigned|ParseEncrypted|WithKey|WithKeySet)\b|\bjose\.(?:NewSigner|NewEncrypter|ParseSigned|ParseEncrypted|SigningKey|Recipient|JSONWebKey|JSONWebKeySet|HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|RSA_OAEP|RSA_OAEP_256|A128GCM|A256GCM|A128KW|A256KW|ECDH_ES|DIRECT|PBES2_HS256_A128KW|PBES2_HS512_A256KW)\b|\bjwtmiddleware\.\w+|\bechojwt\.\w+|\bginjwt\.\w+|\bjwtauth\.(?:New|Verifier|Authenticator)\b|\bpaseto\.\w+|\bjwk\.(?:Parse|ParseKey|New|Fetch|NewSet|Import|PublicKeyOf|FromRaw)\b|\bjws\.(?:Sign|Verify|Parse)\b|\bjwe\.(?:Encrypt|Decrypt|Parse)\b|\bjwa\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA|RSA_OAEP|A128GCM|A256GCM|ECDH_ES)\b|\bkeyfunc\.(?:Get|New|NewDefault)\b|\boidc\.(?:NewProvider|NewVerifier|NewIDTokenVerifier|Config)\b|\bgocloak\.\w+", _S, "jwt", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bjose\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)\b|\bjwa\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)\b|\bjwt\.(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)\b", _S, "jose", algo_from_group=1, algo_map=_JWT_METHODS),
    _r(r"\bjose\.(?:RSA_OAEP|RSA_OAEP_256|RSA1_5)\b|\bjwa\.(?:RSA_OAEP|RSA_OAEP_256|RSA1_5)\b", _C, "jose", algorithm="RSA"),
    _r(r"\bjose\.(?:A128GCM|A192GCM|A256GCM|A128KW|A192KW|A256KW|A128GCMKW|A256GCMKW|A128CBC_HS256|A192CBC_HS384|A256CBC_HS512)\b|\bjwa\.(?:A128GCM|A192GCM|A256GCM|A128KW|A192KW|A256KW|A128GCMKW|A256GCMKW|A128CBC_HS256|A192CBC_HS384|A256CBC_HS512)\b", _C, "jose", algorithm="AES"),
    _r(r"\bjose\.(?:ECDH_ES|ECDH_ES_A128KW|ECDH_ES_A192KW|ECDH_ES_A256KW)\b|\bjwa\.(?:ECDH_ES|ECDH_ES_A128KW|ECDH_ES_A256KW)\b", _KA, "jose", algorithm="ECDH"),
    _r(r"\bjose\.(?:PBES2_HS256_A128KW|PBES2_HS384_A192KW|PBES2_HS512_A256KW)\b|\bjwa\.(?:PBES2_HS256_A128KW|PBES2_HS384_A192KW|PBES2_HS512_A256KW)\b", _KDF, "jose", algorithm="PBKDF2"),
    _r(r"\bpaseto\.(?:NewV2|NewV3|NewV4|V2Local|V2Public|V3Local|V3Public|V4Local|V4Public|NewV4AsymmetricSecretKey|NewV4SymmetricKey|NewV2AsymmetricSecretKey|NewV2SymmetricKey|NewPasetoV\d)\b", _S, "paseto", algorithm="PASETO", confidence="MEDIUM"),
    _r(r"\bpaseto\.(?:V2Local|V2Public|NewV2\w*|V4Local|V4Public|NewV4\w*)\b", _C, "paseto", algorithm="XChaCha20-Poly1305", confidence="MEDIUM"),
    _r(r"\bpaseto\.(?:V2Public|V4Public|NewV[24]AsymmetricSecretKey)\b", _S, "paseto", algorithm="Ed25519"),
    _r(r"\bbranca\.NewBranca\b|\bbranca\.\w+\s*\(", _C, "branca", algorithm="XChaCha20-Poly1305"),
    _r(r"\bmacaroon\.\w+|\bmacaroons\.\w+", _M, "macaroon", algorithm="HMAC-SHA256", confidence="MEDIUM"),
    _r(r"\btotp\.(?:GenerateCode|Validate|Generate|GenerateCodeCustom|ValidateCustom)\b|\bhotp\.(?:GenerateCode|Validate|GenerateCodeCustom)\b|\botp\.(?:AlgorithmSHA1|AlgorithmSHA256|AlgorithmSHA512|AlgorithmMD5)\b|\bgotp\.\w+|\bdgryski/dgoogauth\b", _M, "github.com/pquerna/otp", algorithm="HMAC", confidence="MEDIUM"),
    _r(r"\botp\.Algorithm(SHA1|SHA256|SHA512|MD5)\b", _D, "github.com/pquerna/otp", algo_from_group=1, algo_map=_CRYPTO_HASH),
    _r(r"\btotp\.(?:GenerateCode|Validate|Generate)\b(?![\s\S]{0,300}Algorithm\s*:)", _D, "github.com/pquerna/otp", algorithm="SHA-1", confidence="MEDIUM", confidence_reason="TOTP default digest is SHA-1"),
    # ------------------------------------------------------------ randomness
    _r(r"\bcrypto/rand\b", _RNG, "crypto/rand", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\brand\.Reader\b|\bcryptorand\.Reader\b|\bcrand\.Reader\b|\bcryptorand\.(?:Read|Int|Prime)\b|\bcrand\.(?:Read|Int|Prime)\b", _RNG, "crypto/rand", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\brand\.(?:Read|Prime|Int|Text)\s*\(", _RNG, "crypto/rand", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bmathrand\.(?:Intn|Int|Read|Seed|Int63|Uint32|Uint64|Float64|Perm|Shuffle|New|NewSource)\b|\bmrand\.(?:Intn|Int|Read|Seed|Int63|Uint32|Uint64|Float64|Perm|New|NewSource)\b|\binsecurerand\.\w+", _RNG, "math/rand", algorithm="PRNG", confidence="MEDIUM", confidence_reason="math/rand is not cryptographically secure"),
    _r(r"\brand\.(?:Seed|Intn|Int63|Int31|Uint32|Uint64|Float64|Perm|Shuffle|NewSource|New)\s*\(", _RNG, "math/rand", algorithm="PRNG", confidence="MEDIUM", confidence_reason="math/rand is not cryptographically secure"),
    _r(r"\buuid\.(?:New|NewRandom|NewV4|Must|NewString)\s*\(|\bulid\.(?:Make|MustNew|New)\s*\(|\bksuid\.New\b|\bxid\.New\b|\bshortid\.\w+|\bnanoid\.\w+\s*\(", _RNG, "uuid", algorithm="CSPRNG", confidence="LOW"),
    _r(r"\bsubtle\.ConstantTimeCompare\b|\bsubtle\.ConstantTimeEq\b|\bsubtle\.ConstantTimeSelect\b|\bsubtle\.ConstantTimeByteEq\b", _M, "crypto/subtle", algorithm="CONSTANT-TIME", confidence="LOW"),
    _r(r"\bcrypto\.SHA\w*\.New\s*\(|\bcrypto\.(MD5|SHA1|SHA256|SHA384|SHA512|SHA3_256)\.New\s*\(", _D, "crypto", algo_from_group=1, algo_map=_CRYPTO_HASH),
    _r(r"\bcrypto\.Hash\b|\bhash\.Hash\b|\bcrypto\.Signer\b|\bcrypto\.Decrypter\b|\bcrypto\.SignerOpts\b|\bcrypto\.PrivateKey\b|\bcrypto\.PublicKey\b", _K, "crypto", algorithm="UNKNOWN", confidence="LOW"),
    # ------------------------------------------------------------ database / storage encryption
    _r(r"\bsqlcipher\b|\bPRAGMA\s+key\s*=|\bgorm\.io/gorm/crypto\b|\bgoose\.\w+Encrypt|\bmongo\.NewClientEncryption\b|\boptions\.ClientEncryption\b|\bAutoEncryptionOptions\b|\bClientSideEncryption\b", _C, "database-encryption", algorithm="AES", confidence="MEDIUM"),
    _r(r"\bs3\.ServerSideEncryption\w*\b|\bSSEKMSKeyId\b|\bServerSideEncryption\s*:\s*aws\.String\(\"(AES256|aws:kms)\"\)|\bs3crypto\.\w+|\bencrypt\.NewSSE(?:C|KMS|S3)\b|\bminio\.NewSSEC\b", _C, "s3-sse", algorithm="AES", confidence="MEDIUM"),
    _r(r"\bsops\.\w+|\bdecrypt\.(?:File|Data)\b|\bsealedsecrets\.\w+|\bvault\.\w+Transit\b|\bsecretsmanager\.\w+|\bparameterstore\.\w+", _C, "secrets", algorithm="KMS", confidence="LOW"),
]

_IMPORT_ALIAS = re.compile(r"^\s*(\w+)\s+\"([A-Za-z0-9_./-]+)\"\s*$", re.M)
_IMPORT_LINE = re.compile(r"^\s*import\s+(\w+)\s+\"([A-Za-z0-9_./-]+)\"", re.M)

_CANONICAL_SUFFIX = {
    "crypto/rand": "rand",
    "math/rand": "mathrand",
    "math/rand/v2": "mathrand",
    "crypto/subtle": "subtle",
    "golang.org/x/crypto/nacl/secretbox": "secretbox",
    "golang.org/x/crypto/nacl/box": "box",
    "golang.org/x/crypto/nacl/sign": "sign",
    "golang.org/x/crypto/nacl/auth": "auth",
    "github.com/golang-jwt/jwt/v5": "jwt",
    "github.com/golang-jwt/jwt/v4": "jwt",
    "github.com/golang-jwt/jwt": "jwt",
    "github.com/dgrijalva/jwt-go": "jwt",
    "gopkg.in/square/go-jose.v2": "jose",
    "github.com/go-jose/go-jose/v3": "jose",
    "github.com/go-jose/go-jose/v4": "jose",
    "github.com/lestrrat-go/jwx/v2/jwt": "jwt",
    "github.com/lestrrat-go/jwx/v2/jwk": "jwk",
    "github.com/lestrrat-go/jwx/v2/jwa": "jwa",
    "github.com/lestrrat-go/jwx/v2/jws": "jws",
    "github.com/lestrrat-go/jwx/v2/jwe": "jwe",
}


def _resolve_import_aliases(text: str) -> str:
    """Rewrite ``alias.Member`` to ``pkg.Member`` for aliased imports so the
    rule table (keyed on canonical package names) sees them.  ``math/rand``
    aliases become ``mathrand`` so they never collide with ``crypto/rand``.
    Line-preserving."""
    aliases: dict[str, str] = {}

    def _canon(path: str) -> str:
        if path in _CANONICAL_SUFFIX:
            return _CANONICAL_SUFFIX[path]
        last = path.rsplit("/", 1)[-1]
        if re.fullmatch(r"v\d+", last) and "/" in path:  # module major-version suffix
            last = path.rsplit("/", 2)[-2]
        return last.replace("-", "").replace(".", "")

    def _collect(m: re.Match) -> None:
        alias, path = m.group(1), m.group(2)
        if alias in {"_", "."}:
            return
        canon = _canon(path)
        if alias != canon:
            aliases[alias] = canon

    block = re.search(r"import\s*\((.*?)\)", text, re.S)
    if block:
        for m in _IMPORT_ALIAS.finditer(block.group(1)):
            _collect(m)
    for m in _IMPORT_LINE.finditer(text):
        _collect(m)
    # un-aliased math/rand: make its members explicit so crypto/rand rules don't fire
    imports_math_rand = bool(re.search(r"\"math/rand(?:/v2)?\"", text))
    imports_crypto_rand = bool(re.search(r"\"crypto/rand\"", text))
    if imports_math_rand and not imports_crypto_rand and "rand" not in aliases.values():
        aliases.setdefault("rand", "mathrand")
    for alias, canon in aliases.items():
        text = re.sub(rf"(?<![\w.\"/]){re.escape(alias)}\.(?=[A-Za-z_])", canon + ".", text)
    return text


def parse_go_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_c_like_comments

    text = _resolve_import_aliases(strip_c_like_comments(raw))
    if "_test.go" in file_path.name:
        pass  # tests are still scanned; consumers can filter via path
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=text,
        rules=RULES,
        language="GO",
        scanner_id=SCANNER_ID,
        confidence_reason="go-stdlib-or-xcrypto",
        strip_comments=False,
    )
