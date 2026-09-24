"""Supplementary regex rules for JavaScript / TypeScript.

Covers Node ``crypto`` APIs beyond ``create*`` (key-pair generation, ECDH/DH,
sign/verify, ``crypto.hash``, WebCrypto option objects), and the popular
third-party ecosystem: tweetnacl, libsodium-wrappers, jose, jsonwebtoken,
node-forge, crypto-js, elliptic/secp256k1/@noble, hash.js/js-sha256/md5,
bcryptjs/argon2/scrypt-js, node-rsa/jsrsasign/sshpk, openpgp, ethers/web3
keccak, TLS agent options and insecure RNG in key contexts.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import CIPHER_TOKENS, DIGEST_TOKENS, Rule, run_rules

_D = {"api_type": "MESSAGE_DIGEST", "purpose": "HASHING"}
_C = {"api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION"}
_K = {"api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION"}
_S = {"api_type": "SIGNATURE", "purpose": "SIGNING"}
_M = {"api_type": "MAC", "purpose": "MAC_GENERATION"}
_KDF = {"api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING"}
_KA = {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}
_TLS = {"api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION"}
_RNG = {"api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION"}
_NODE = "node-crypto"


def _r(pattern: str, base: dict, library: str, **extra) -> Rule:
    return re.compile(pattern, re.M), {**base, "library": library, **extra}


_Q = r"""['"]"""
_KEYPAIR_TYPES = {
    "rsa": "RSA", "rsa-pss": "RSA", "dsa": "DSA", "ec": "ECDSA", "ed25519": "Ed25519", "ed448": "Ed448",
    "x25519": "X25519", "x448": "X448", "dh": "DH",
}
_JWT_ALGS = {
    "hs256": "HS256", "hs384": "HS384", "hs512": "HS512", "rs256": "RS256", "rs384": "RS384", "rs512": "RS512",
    "es256": "ES256", "es256k": "ES256K", "es384": "ES384", "es512": "ES512", "ps256": "PS256", "ps384": "PS384",
    "ps512": "PS512", "eddsa": "EdDSA", "none": "none",
}
_WEBCRYPTO_NAMES = {
    "aes-gcm": "AES", "aes-cbc": "AES", "aes-ctr": "AES", "aes-kw": "AES", "rsa-oaep": "RSA", "rsassa-pkcs1-v1_5": "RSA",
    "rsa-pss": "RSA", "ecdsa": "ECDSA", "ecdh": "ECDH", "hmac": "HMAC", "pbkdf2": "PBKDF2", "hkdf": "HKDF",
    "x25519": "X25519", "ed25519": "Ed25519", "x448": "X448", "ed448": "Ed448", "ml-kem-768": "ML-KEM", "ml-dsa-65": "ML-DSA",
    "sha-1": "SHA-1", "sha-256": "SHA-256", "sha-384": "SHA-384", "sha-512": "SHA-512",
}
_CRYPTOJS = {
    "aes": "AES", "des": "DES", "tripledes": "3DES", "rabbit": "Rabbit", "rc4": "RC4", "rc4drop": "RC4", "blowfish": "Blowfish",
    "md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sha3": "SHA3-256",
    "ripemd160": "RIPEMD-160", "hmacmd5": "HMAC-MD5", "hmacsha1": "HMAC-SHA1", "hmacsha224": "HMAC-SHA224", "hmacsha256": "HMAC-SHA256",
    "hmacsha384": "HMAC-SHA384", "hmacsha512": "HMAC-SHA512", "hmacsha3": "HMAC-SHA3", "hmacripemd160": "HMAC-RIPEMD160",
    "pbkdf2": "PBKDF2", "evpkdf": "EVP_BytesToKey",
}
_FORGE_CIPHERS = {**CIPHER_TOKENS, "3des": "3DES", "des": "DES", "rc2": "RC2"}

RULES: list[Rule] = [
    # ------------------------------------------------------------ Node crypto beyond create*
    _r(rf"\bgenerateKeyPair(?:Sync)?\s*\(\s*{_Q}(rsa|rsa-pss|dsa|ec|ed25519|ed448|x25519|x448|dh){_Q}", _K, _NODE, algo_from_group=1, algo_map=_KEYPAIR_TYPES),
    _r(rf"\bgenerateKeyPair(?:Sync)?\s*\(\s*{_Q}(?:rsa|rsa-pss){_Q}\s*,\s*\{{[^}}]*?modulusLength\s*:\s*(\d+)", _K, _NODE, algorithm="RSA", key_from_group=1),
    _r(rf"\bgenerateKey(?:Sync)?\s*\(\s*{_Q}(hmac|aes){_Q}", _K, _NODE, algo_from_group=1, algo_map={"hmac": "HMAC", "aes": "AES"}),
    _r(rf"\bgenerateKey(?:Sync)?\s*\(\s*{_Q}aes{_Q}\s*,\s*\{{[^}}]*?length\s*:\s*(\d+)", _C, _NODE, algorithm="AES", key_from_group=1),
    _r(rf"\bcreateECDH\s*\(\s*{_Q}([A-Za-z0-9-]+){_Q}", _KA, _NODE, algorithm="ECDH"),
    _r(r"\bcreateECDH\s*\(|\bECDH\.convertKey\s*\(", _KA, _NODE, algorithm="ECDH"),
    _r(r"\bcreateDiffieHellman(?:Group)?\s*\(|\bgetDiffieHellman\s*\(", _KA, _NODE, algorithm="DH"),
    _r(r"\bdiffieHellman\s*\(\s*\{", _KA, _NODE, algorithm="ECDH", confidence="MEDIUM"),
    _r(rf"\bcrypto\.(?:sign|verify)\s*\(\s*{_Q}(RSA-SHA1|RSA-SHA256|RSA-SHA384|RSA-SHA512|sha1|sha256|sha384|sha512|RSA-MD5|md5|sha1WithRSAEncryption|sha256WithRSAEncryption|ecdsa-with-SHA256|ecdsa-with-SHA1){_Q}", _S, _NODE, algorithm="UNKNOWN", emit_digest_group=1, confidence="MEDIUM"),
    _r(rf"\bcrypto\.(?:sign|verify)\s*\(\s*{_Q}(?:RSA-SHA\d+|RSA-MD5|sha\d+WithRSAEncryption){_Q}", _S, _NODE, algorithm="RSA"),
    _r(rf"\bcrypto\.(?:sign|verify)\s*\(\s*{_Q}ecdsa-with-SHA\d+{_Q}", _S, _NODE, algorithm="ECDSA"),
    _r(r"\bcrypto\.(?:sign|verify)\s*\(\s*(?:null|undefined)\s*,", _S, _NODE, algorithm="Ed25519", confidence="MEDIUM", confidence_reason="null digest => EdDSA key in Node crypto.sign"),
    _r(rf"\bcreateSign\s*\(\s*{_Q}(?:RSA-)?(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|sha1|sha256|sha384|sha512|md5){_Q}", _D, _NODE, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(rf"\bcreateSign\s*\(\s*{_Q}RSA-\w+{_Q}|\bcreateVerify\s*\(\s*{_Q}RSA-\w+{_Q}", _S, _NODE, algorithm="RSA"),
    _r(rf"\bcreateVerify\s*\(\s*{_Q}(?:RSA-)?(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|sha1|sha256|sha384|sha512|md5){_Q}", _S, _NODE, algorithm="UNKNOWN", emit_digest_group=1, confidence="MEDIUM"),
    _r(rf"\bcrypto\.hash\s*\(\s*{_Q}([A-Za-z0-9-]+){_Q}", _D, _NODE, algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(rf"\bcrypto\.getHashes\s*\(|\bcrypto\.getCiphers\s*\(", _D, _NODE, algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bhkdf(?:Sync)?\s*\(\s*['\"]([A-Za-z0-9-]+)['\"]", _KDF, _NODE, algorithm="HKDF", emit_digest_group=1, purpose="KEY_GENERATION"),
    _r(r"\bcrypto\.(?:randomBytes|randomFill(?:Sync)?|randomInt|randomUUID|getRandomValues)\s*\(|\bwebcrypto\.getRandomValues\s*\(|\bwindow\.crypto\.getRandomValues\s*\(|\bself\.crypto\.getRandomValues\s*\(|(?<![\w.])getRandomValues\s*\(|(?<![\w.])randomBytes\s*\(|(?<![\w.])randomUUID\s*\(", _RNG, _NODE, algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\b(?:key|iv|salt|nonce|token|secret|password|otp|session)\w*\s*=\s*[^;\n]*\bMath\.random\s*\(", _RNG, "javascript", algorithm="PRNG", confidence="MEDIUM", confidence_reason="Math.random is not a CSPRNG"),
    _r(r"(?is)(?:function\s+\w*(?:token|session|secret|nonce|otp|key|password|salt|iv)\w*\s*\([^)]*\)|\b\w*(?:token|session|secret|nonce|otp|key|password|salt)\w*\s*[:=]\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?)\s*\{[^{}]{0,200}?\bMath\.random\s*\(", _RNG, "javascript", algorithm="PRNG", confidence="MEDIUM", confidence_reason="Math.random used to build a token/secret; not a CSPRNG"),
    _r(rf"\bcreatePrivateKey\s*\(|\bcreatePublicKey\s*\(|\bcreateSecretKey\s*\(|\bKeyObject\.from\s*\(", _K, _NODE, algorithm="UNKNOWN", confidence="LOW"),
    _r(rf"\bprivateEncrypt\s*\(|\bprivateDecrypt\s*\(|\bpublicEncrypt\s*\(|\bpublicDecrypt\s*\(", _C, _NODE, algorithm="RSA"),
    _r(r"\bconstants\.RSA_PKCS1_PADDING\b", _C, _NODE, algorithm="RSA", padding="PKCS1", confidence_reason="rsa-pkcs1v15-padding"),
    _r(r"\bconstants\.RSA_PKCS1_OAEP_PADDING\b", _C, _NODE, algorithm="RSA", padding="OAEP"),
    _r(r"\bconstants\.RSA_NO_PADDING\b", _C, _NODE, algorithm="RSA", padding="NoPadding"),
    _r(rf"(?:\bcrypto\.|(?<![\w.]))createCipher\s*\(\s*{_Q}", _D, _NODE, algorithm="MD5", confidence="MEDIUM", confidence_reason="crypto.createCipher key derivation uses MD5"),
    _r(r"(?<![\w.])keccak256\s*\(|(?<![\w.])keccak_256\s*\(|(?<![\w.])solidityPackedKeccak256\s*\(", _D, "ethers", algorithm="SHA3-256", confidence="MEDIUM", confidence_reason="keccak-256"),
    _r(r"(?<![\w.])(?:Wallet|HDNodeWallet)\.(?:createRandom|fromPhrase|fromMnemonic|fromEncryptedJson(?:Sync)?)\s*\(|(?<![\w.])new\s+SigningKey\s*\(|\bprivateKeyToAccount\s*\(|\bgeneratePrivateKey\s*\(\s*\)", _S, "ethers", algorithm="ECDSA", confidence="MEDIUM", confidence_reason="secp256k1 wallet key"),
    _r(r"\bsession\s*\(\s*\{[^}]*\bsecret\s*:|(?<![\w'\"`])cookieParser\s*\(\s*(?:['\"`][^'\"`]{6,}['\"`]|process\.env|\w+\s*\))|\bcookieSession\s*\(\s*\{[^}]*\b(?:secret|keys)\s*:|\brequire\s*\(\s*['\"]cookie-signature['\"]\s*\)|\bfrom\s+['\"]cookie-signature['\"]", _M, "express", algorithm="HMAC-SHA256", confidence="MEDIUM", confidence_reason="express session/cookie signing uses HMAC-SHA256"),
    _r(r"\brequire\s*\(\s*['\"]jws['\"]\s*\)|\bfrom\s+['\"]jws['\"]|\bjws\.(?:sign|verify|decode|createSign|createVerify)\s*\(|\brequire\s*\(\s*['\"]jsonwebtoken['\"]\s*\)|\bfrom\s+['\"]jsonwebtoken['\"]", _S, "jws", algorithm="JWT", confidence="MEDIUM"),
    _r(r"\bbcrypt(?:js)?\.(?:hash|hashSync|compare|compareSync|genSalt|genSaltSync)\s*=\s*function|\bfunction\s+(?:hashSync|compareSync|genSaltSync)\s*\(\s*(?:s|password|pw|data)\s*,\s*(?:salt|hash|rounds)", _KDF, "bcryptjs", algorithm="BCRYPT", confidence="MEDIUM", confidence_reason="bcrypt implementation (vendored bcryptjs)"),
    _r(rf"\bsignOptions\s*:\s*\{{[^}}]*\balgorithm\s*:\s*{_Q}((?:HS|RS|PS|ES)(?:256|384|512)|EdDSA|none){_Q}|\bJwtModule\.register(?:Async)?\s*\(", _S, "@nestjs/jwt", algorithm="JWT", confidence="MEDIUM"),
    _r(rf"\bsetAuthTag\s*\(|\bgetAuthTag\s*\(", _C, _NODE, algorithm="UNKNOWN", confidence="LOW"),
    _r(rf"\bX509Certificate\s*\(|\bnew\s+crypto\.X509Certificate\s*\(|\bcheckServerIdentity\s*[:=]", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, _NODE, algorithm="X509", confidence="MEDIUM"),
    # ------------------------------------------------------------ WebCrypto option objects
    _r(rf"\bname\s*:\s*{_Q}(AES-GCM|AES-CBC|AES-CTR|AES-KW|RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|HMAC|PBKDF2|HKDF|X25519|Ed25519|X448|Ed448|ML-KEM-768|ML-DSA-65){_Q}", _C, "webcrypto", algo_from_group=1, algo_map=_WEBCRYPTO_NAMES),
    _r(rf"\bhash\s*:\s*(?:\{{\s*name\s*:\s*)?{_Q}(SHA-1|SHA-256|SHA-384|SHA-512){_Q}", _D, "webcrypto", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(rf"\bmodulusLength\s*:\s*(\d+)", _K, "webcrypto", algorithm="RSA", key_from_group=1, confidence="MEDIUM"),
    _r(rf"\bnamedCurve\s*:\s*{_Q}(P-256|P-384|P-521|secp256k1|prime256v1|secp384r1|secp521r1){_Q}", _K, "webcrypto", algorithm="ECDSA", confidence="MEDIUM"),
    _r(rf"\bsubtle\.(?:encrypt|decrypt|sign|verify|digest|generateKey|importKey|exportKey|deriveKey|deriveBits|wrapKey|unwrapKey)\s*\(\s*{_Q}(SHA-1|SHA-256|SHA-384|SHA-512|AES-GCM|AES-CBC|AES-CTR|AES-KW|RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|HMAC|PBKDF2|HKDF|X25519|Ed25519){_Q}", _C, "webcrypto", algo_from_group=1, algo_map=_WEBCRYPTO_NAMES),
    _r(rf"\bsubtle\.(?:wrapKey|unwrapKey)\s*\(", _C, "webcrypto", algorithm="UNKNOWN", confidence="LOW"),
    # ------------------------------------------------------------ tweetnacl / libsodium-wrappers / noble
    _r(r"\bnacl\.secretbox(?:\.open|\.keyLength|\.nonceLength)?\s*\(|\bnacl\.secretbox\b", _C, "tweetnacl", algorithm="XSalsa20-Poly1305"),
    _r(r"\bnacl\.box(?:\.keyPair|\.open|\.before|\.after)?\s*\(|\bnacl\.box\.keyPair\b", _C, "tweetnacl", algorithm="X25519"),
    _r(r"\bnacl\.box(?:\.open|\.after)?\s*\(", _C, "tweetnacl", algorithm="XSalsa20-Poly1305"),
    _r(r"\bnacl\.sign(?:\.keyPair|\.detached|\.open|\.detached\.verify)?\s*\(|\bnacl\.sign\.keyPair\b", _S, "tweetnacl", algorithm="Ed25519"),
    _r(r"\bnacl\.hash\s*\(", _D, "tweetnacl", algorithm="SHA-512"),
    _r(r"\bnacl\.scalarMult(?:\.base)?\s*\(", _KA, "tweetnacl", algorithm="X25519"),
    _r(r"\bnacl\.randomBytes\s*\(", _RNG, "tweetnacl", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bnacl\.auth(?:\.full|\.verify)?\s*\(", _M, "tweetnacl-auth", algorithm="HMAC-SHA512"),
    _r(r"\bsodium\.crypto_secretbox_(?:easy|open_easy|detached|open_detached|keygen)\s*\(", _C, "libsodium-wrappers", algorithm="XSalsa20-Poly1305"),
    _r(r"\bsodium\.crypto_box_(?:easy|open_easy|keypair|seal|seal_open|detached|beforenm)\s*\(", _C, "libsodium-wrappers", algorithm="X25519"),
    _r(r"\bsodium\.crypto_sign(?:_keypair|_detached|_verify_detached|_open|_seed_keypair)?\s*\(", _S, "libsodium-wrappers", algorithm="Ed25519"),
    _r(r"\bsodium\.crypto_aead_chacha20poly1305(?:_ietf)?_\w+\s*\(", _C, "libsodium-wrappers", algorithm="ChaCha20-Poly1305"),
    _r(r"\bsodium\.crypto_aead_xchacha20poly1305_ietf_\w+\s*\(", _C, "libsodium-wrappers", algorithm="XChaCha20-Poly1305"),
    _r(r"\bsodium\.crypto_aead_aes256gcm_\w+\s*\(", _C, "libsodium-wrappers", algorithm="AES", mode="GCM"),
    _r(r"\bsodium\.crypto_pwhash(?:_str|_str_verify)?\s*\(|\bsodium\.crypto_pwhash_ALG_ARGON2\w+", _KDF, "libsodium-wrappers", algorithm="ARGON2"),
    _r(r"\bsodium\.crypto_pwhash_scryptsalsa208sha256\w*\s*\(", _KDF, "libsodium-wrappers", algorithm="SCRYPT"),
    _r(r"\bsodium\.crypto_generichash\w*\s*\(", _D, "libsodium-wrappers", algorithm="BLAKE2b"),
    _r(r"\bsodium\.crypto_hash_sha256\w*\s*\(", _D, "libsodium-wrappers", algorithm="SHA-256"),
    _r(r"\bsodium\.crypto_hash_sha512\w*\s*\(|\bsodium\.crypto_hash\s*\(", _D, "libsodium-wrappers", algorithm="SHA-512"),
    _r(r"\bsodium\.crypto_auth(?:_verify|_keygen)?\s*\(", _M, "libsodium-wrappers", algorithm="HMAC-SHA512"),
    _r(r"\bsodium\.crypto_kdf_\w+\s*\(|\bsodium\.crypto_kx_\w+\s*\(|\bsodium\.crypto_scalarmult\w*\s*\(", _KA, "libsodium-wrappers", algorithm="X25519"),
    _r(r"\bsodium\.randombytes_buf\s*\(|\bsodium\.randombytes_uniform\s*\(", _RNG, "libsodium-wrappers", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"@noble/hashes/(sha256|sha512|sha3|blake2b|blake2s|blake3|ripemd160|sha1|md5|hmac|pbkdf2|scrypt|argon2|hkdf|sha2)\b|\bfrom\s+['\"]@noble/hashes/(sha256|sha512|sha3|blake2b|blake2s|blake3|ripemd160|sha1|md5|hmac|pbkdf2|scrypt|argon2|hkdf|sha2)['\"]", _D, "@noble/hashes", algo_from_group=1,
       algo_map={"sha256": "SHA-256", "sha512": "SHA-512", "sha3": "SHA3-256", "blake2b": "BLAKE2b", "blake2s": "BLAKE2s", "blake3": "BLAKE3", "ripemd160": "RIPEMD-160", "sha1": "SHA-1", "md5": "MD5", "hmac": "HMAC", "pbkdf2": "PBKDF2", "scrypt": "SCRYPT", "argon2": "ARGON2", "hkdf": "HKDF", "sha2": "SHA-256"}),
    _r(r"\bx25519\.(?:getSharedSecret|scalarMult|scalarMultBase|getPublicKey|utils\.randomPrivateKey)\s*\(|\bx448\.getSharedSecret\s*\(", {"api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE"}, "@noble/curves", algorithm="X25519"),
    _r(r"@noble/curves/(secp256k1|p256|p384|p521|ed25519|ed448|bls12-381|bn254|jubjub)\b|@noble/(secp256k1|ed25519)\b", _S, "@noble/curves", algo_from_group=1,
       algo_map={"secp256k1": "ECDSA", "p256": "ECDSA", "p384": "ECDSA", "p521": "ECDSA", "ed25519": "Ed25519", "ed448": "Ed448", "bls12-381": "BLS", "bn254": "BN254", "jubjub": "JubJub"}),
    _r(r"@noble/ciphers/(aes|chacha|salsa)\b|\bfrom\s+['\"]@noble/ciphers/(aes|chacha|salsa)['\"]", _C, "@noble/ciphers", algo_from_group=1, algo_map={"aes": "AES", "chacha": "ChaCha20-Poly1305", "salsa": "XSalsa20-Poly1305"}),
    _r(r"@noble/post-quantum/(ml-kem|ml-dsa|slh-dsa)\b", _KA, "@noble/post-quantum", algo_from_group=1, algo_map={"ml-kem": "ML-KEM", "ml-dsa": "ML-DSA", "slh-dsa": "SLH-DSA"}),
    _r(r"\b(?:new\s+)?(?:elliptic\.)?ec\s*\(\s*['\"](secp256k1|p256|p384|p521|curve25519|ed25519|secp256r1|prime256v1)['\"]\s*\)|\bnew\s+EC\s*\(\s*['\"](secp256k1|p256|p384|p521|curve25519|ed25519)['\"]", _S, "elliptic", algo_from_group=1,
       algo_map={"secp256k1": "ECDSA", "p256": "ECDSA", "p384": "ECDSA", "p521": "ECDSA", "curve25519": "X25519", "ed25519": "Ed25519", "secp256r1": "ECDSA", "prime256v1": "ECDSA"}),
    _r(r"\bnew\s+(?:elliptic\.)?eddsa\s*\(\s*['\"]ed25519['\"]", _S, "elliptic", algorithm="Ed25519"),
    _r(r"\bsecp256k1\.(?:ecdsaSign|ecdsaVerify|publicKeyCreate|privateKeyVerify|sign|verify|ecdh|signSync)\s*\(|\brequire\s*\(\s*['\"]secp256k1['\"]\s*\)|\bfrom\s+['\"]secp256k1['\"]|\bfrom\s+['\"]tiny-secp256k1['\"]|\bfrom\s+['\"]@bitcoinerlab/secp256k1['\"]", _S, "secp256k1", algorithm="ECDSA"),
    _r(r"\bfrom\s+['\"](?:ed25519|@stablelib/ed25519|supercop\.js|ed2curve|tweetnacl-ed25519)['\"]|\brequire\s*\(\s*['\"](?:ed25519|@stablelib/ed25519|supercop\.js)['\"]", _S, "ed25519", algorithm="Ed25519"),
    _r(r"\bfrom\s+['\"]@stablelib/(x25519|xchacha20poly1305|chacha20poly1305|aes-gcm|aes|hmac|sha256|sha512|blake2b|pbkdf2|scrypt|hkdf|salsa20|nacl)['\"]|\brequire\s*\(\s*['\"]@stablelib/(x25519|xchacha20poly1305|chacha20poly1305|aes-gcm|aes|hmac|sha256|sha512|blake2b|pbkdf2|scrypt|hkdf|salsa20|nacl)['\"]", _C, "@stablelib", algo_from_group=1,
       algo_map={"x25519": "X25519", "xchacha20poly1305": "XChaCha20-Poly1305", "chacha20poly1305": "ChaCha20-Poly1305", "aes-gcm": "AES", "aes": "AES", "hmac": "HMAC", "sha256": "SHA-256", "sha512": "SHA-512", "blake2b": "BLAKE2b", "pbkdf2": "PBKDF2", "scrypt": "SCRYPT", "hkdf": "HKDF", "salsa20": "Salsa20", "nacl": "XSalsa20-Poly1305"}),
    # ------------------------------------------------------------ JWT / JOSE
    _r(rf"\balgorithm\s*:\s*{_Q}(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES256K|ES384|ES512|PS256|PS384|PS512|EdDSA|none){_Q}", _S, "jsonwebtoken", algo_from_group=1, algo_map=_JWT_ALGS),
    _r(rf"\balgorithms\s*:\s*\[\s*{_Q}(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES256K|ES384|ES512|PS256|PS384|PS512|EdDSA|none){_Q}", _S, "jsonwebtoken", algo_from_group=1, algo_map=_JWT_ALGS),
    _r(rf"\bsetProtectedHeader\s*\(\s*\{{[^}}]*?\balg\s*:\s*{_Q}(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES256K|ES384|ES512|PS256|PS384|PS512|EdDSA|RSA-OAEP|RSA-OAEP-256|A128KW|A256KW|A128GCMKW|A256GCMKW|ECDH-ES|dir|PBES2-HS256\+A128KW|PBES2-HS512\+A256KW){_Q}", _S, "jose", algo_from_group=1,
       algo_map={**_JWT_ALGS, "rsa-oaep": "RSA", "rsa-oaep-256": "RSA", "a128kw": "AES", "a256kw": "AES", "a128gcmkw": "AES", "a256gcmkw": "AES", "ecdh-es": "ECDH", "dir": "UNKNOWN", "pbes2-hs256+a128kw": "PBKDF2", "pbes2-hs512+a256kw": "PBKDF2"}),
    _r(rf"\benc\s*:\s*{_Q}(A128CBC-HS256|A192CBC-HS384|A256CBC-HS512|A128GCM|A192GCM|A256GCM){_Q}", _C, "jose", algorithm="AES"),
    _r(r"\bnew\s+(?:jose\.)?(?:SignJWT|CompactSign|FlattenedSign|GeneralSign|EncryptJWT|CompactEncrypt|FlattenedEncrypt|GeneralEncrypt|UnsecuredJWT)\s*\(|\b(?:jwtVerify|compactVerify|flattenedVerify|generalVerify|jwtDecrypt|compactDecrypt|createRemoteJWKSet|createLocalJWKSet|importJWK|exportJWK)\s*\(|\bjose\.(?:generateKeyPair|generateSecret|importPKCS8|importSPKI|importX509)\s*\(", _S, "jose", algorithm="JWT", confidence="MEDIUM"),
    _r(rf"\b(?:jose\.)?generateKeyPair\s*\(\s*{_Q}(RS256|RS384|RS512|PS256|PS384|PS512|ES256|ES256K|ES384|ES512|EdDSA|RSA-OAEP|RSA-OAEP-256|ECDH-ES){_Q}", _K, "jose", algo_from_group=1, algo_map={**_JWT_ALGS, "rsa-oaep": "RSA", "rsa-oaep-256": "RSA", "ecdh-es": "ECDH"}),
    _r(r"\bjwt\.(?:sign|verify|decode)\s*\(|\bjsonwebtoken\b|\bjwks-rsa\b|\bjwksClient\s*\(|\bexpressjwt\s*\(|\bexpress-jwt\b|\bpassport-jwt\b|\bExtractJwt\.\w+|\bnew\s+JwtStrategy\s*\(|\bKJUR\.jws\.JWS\.(?:sign|verify|parse)\s*\(|\bjwt-decode\b|\bjwtDecode\s*\(|\bnjwt\.(?:create|verify)\s*\(|\bfastify-jwt\b|\b@fastify/jwt\b|\bnext-auth/jwt\b|\bencode\s*\(\s*\{[^}]*secret[^}]*\}\s*\)", _S, "jwt", algorithm="JWT", confidence="MEDIUM"),
    _r(rf"\bKJUR\.jws\.JWS\.sign\s*\(\s*{_Q}(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|none){_Q}", _S, "jsrsasign", algo_from_group=1, algo_map=_JWT_ALGS),
    # ------------------------------------------------------------ node-forge
    _r(rf"\bforge\.cipher\.create(?:Cipher|Decipher)\s*\(\s*{_Q}([A-Za-z0-9-]+){_Q}", _C, "node-forge", algo_from_group=1, algo_map=_FORGE_CIPHERS, split_cipher=True),
    _r(rf"\bforge\.(?:aes|des|rc2)\.(?:createEncryptionCipher|createDecryptionCipher|startEncrypting|startDecrypting)\s*\(", _C, "node-forge", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bforge\.aes\.\w+\s*\(", _C, "node-forge", algorithm="AES"),
    _r(r"\bforge\.des\.\w+\s*\(", _C, "node-forge", algorithm="DES"),
    _r(r"\bforge\.rc2\.\w+\s*\(", _C, "node-forge", algorithm="RC2"),
    _r(r"\bforge\.md\.(md5|sha1|sha256|sha384|sha512|sha512\.sha256|sha512\.sha224)\.create\s*\(|\bforge\.md\.(md5|sha1|sha256|sha384|sha512)\b", _D, "node-forge", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bforge\.hmac\.create\s*\(", _M, "node-forge", algorithm="HMAC"),
    _r(r"\bforge\.pkcs5\.pbkdf2\s*\(|\bforge\.pbkdf2\s*\(", _KDF, "node-forge", algorithm="PBKDF2"),
    _r(r"\bforge\.pki\.rsa\.(?:generateKeyPair|setPublicKey|setPrivateKey|createKeyPairGenerationState|stepKeyPairGenerationState)\s*\(|\bforge\.pki\.(?:privateKeyFromPem|publicKeyFromPem|privateKeyToPem|publicKeyToPem|encryptRsaPrivateKey|decryptRsaPrivateKey)\s*\(|\bforge\.rsa\.\w+\s*\(", _K, "node-forge", algorithm="RSA"),
    _r(r"\bforge\.pki\.rsa\.generateKeyPair\s*\(\s*(?:\{\s*bits\s*:\s*)?(\d{3,5})", _K, "node-forge", algorithm="RSA", key_from_group=1),
    _r(r"\bforge\.pki\.ed25519\.\w+\s*\(", _S, "node-forge", algorithm="Ed25519"),
    _r(r"\bforge\.pki\.(?:createCertificate|certificateFromPem|certificateToPem|createCertificationRequest|verifyCertificateChain|createCaStore)\s*\(|\bforge\.pkcs12\.\w+\s*\(|\bforge\.pkcs7\.\w+\s*\(", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "node-forge", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bforge\.tls\.createConnection\s*\(|\bforge\.tls\.\w+", _TLS, "node-forge", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bforge\.random\.getBytes(?:Sync)?\s*\(", _RNG, "node-forge", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bforge\.rc4\b|\bforge\.md\.md4\b", _C, "node-forge", algorithm="RC4"),
    # ------------------------------------------------------------ crypto-js / sjcl / jsrsasign / hash libs
    _r(r"\bCryptoJS\.(AES|DES|TripleDES|Rabbit|RC4|RC4Drop|Blowfish|MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160|HmacMD5|HmacSHA1|HmacSHA224|HmacSHA256|HmacSHA384|HmacSHA512|HmacSHA3|HmacRIPEMD160|PBKDF2|EvpKDF)\b", _C, "crypto-js", algo_from_group=1, algo_map=_CRYPTOJS),
    _r(r"\bCryptoJS\.mode\.(ECB|CBC|CFB|OFB|CTR|CTRGladman)\b", _C, "crypto-js", algorithm="AES", confidence="LOW"),
    _r(r"\bCryptoJS\.pad\.(NoPadding|ZeroPadding|Iso10126|Iso97971|AnsiX923|Pkcs7)\b", _C, "crypto-js", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bCryptoJS\.lib\.WordArray\.random\s*\(", _RNG, "crypto-js", algorithm="CSPRNG", confidence="LOW", confidence_reason="crypto-js WordArray.random falls back to Math.random on old builds"),
    _r(r"\bsjcl\.cipher\.aes\b|\bsjcl\.encrypt\s*\(|\bsjcl\.decrypt\s*\(|\bsjcl\.mode\.(?:ccm|gcm|ocb2)\b", _C, "sjcl", algorithm="AES"),
    _r(r"\bsjcl\.hash\.(sha1|sha256|sha512|ripemd160)\b", _D, "sjcl", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bsjcl\.misc\.hmac\b", _M, "sjcl", algorithm="HMAC"),
    _r(r"\bsjcl\.misc\.pbkdf2\s*\(|\bsjcl\.misc\.cachedPbkdf2\s*\(", _KDF, "sjcl", algorithm="PBKDF2"),
    _r(r"\bsjcl\.misc\.scrypt\s*\(", _KDF, "sjcl", algorithm="SCRYPT"),
    _r(r"\bsjcl\.ecc\.(?:ecdsa|elGamal)\b", _S, "sjcl", algorithm="ECDSA"),
    _r(r"\bsjcl\.random\.randomWords\s*\(", _RNG, "sjcl", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(rf"\bKJUR\.crypto\.MessageDigest\s*\(\s*\{{\s*alg\s*:\s*{_Q}(md5|sha1|sha224|sha256|sha384|sha512|ripemd160){_Q}", _D, "jsrsasign", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(rf"\bKJUR\.crypto\.Signature\s*\(\s*\{{\s*alg\s*:\s*{_Q}(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|RIPEMD160)with(RSA|ECDSA|DSA|RSAandMGF1){_Q}", _S, "jsrsasign", algo_from_group=2, algo_map={"rsa": "RSA", "ecdsa": "ECDSA", "dsa": "DSA", "rsaandmgf1": "RSA"}, emit_digest_group=1),
    _r(rf"\bKJUR\.crypto\.Mac\s*\(\s*\{{\s*alg\s*:\s*{_Q}Hmac(MD5|SHA1|SHA224|SHA256|SHA384|SHA512){_Q}", _M, "jsrsasign", algorithm="HMAC", emit_digest_group=1),
    _r(rf"\bKJUR\.crypto\.Cipher\.(?:encrypt|decrypt)\s*\([^)]*{_Q}(RSA|RSAOAEP|RSAOAEP224|RSAOAEP256|RSAOAEP384|RSAOAEP512|aes128-CBC|aes256-CBC|des-EDE3-CBC){_Q}", _C, "jsrsasign", algo_from_group=1,
       algo_map={"rsa": "RSA", "rsaoaep": "RSA", "rsaoaep224": "RSA", "rsaoaep256": "RSA", "rsaoaep384": "RSA", "rsaoaep512": "RSA", "aes128-cbc": "AES", "aes256-cbc": "AES", "des-ede3-cbc": "3DES"}),
    _r(rf"\bKEYUTIL\.generateKeypair\s*\(\s*{_Q}(RSA|EC){_Q}", _K, "jsrsasign", algo_from_group=1, algo_map={"rsa": "RSA", "ec": "ECDSA"}),
    _r(r"\bKEYUTIL\.(?:getKey|getPEM|getKeyFromPlainPrivatePKCS8PEM|getKeyFromEncryptedPKCS8PEM)\s*\(|\bnew\s+RSAKey\s*\(|\bX509\s*\(\s*\)|\bnew\s+X509\s*\(|\bKJUR\.asn1\.x509\.\w+", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "jsrsasign", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bnew\s+RSAKey\s*\(\s*\)\s*;?[\s\S]{0,80}?\.generate\s*\(\s*(\d+)", _K, "jsrsasign", algorithm="RSA", key_from_group=1),
    _r(r"\bnew\s+NodeRSA\s*\(|\brequire\s*\(\s*['\"]node-rsa['\"]\s*\)|\bfrom\s+['\"]node-rsa['\"]", _K, "node-rsa", algorithm="RSA"),
    _r(r"\bnew\s+NodeRSA\s*\(\s*\{\s*b\s*:\s*(\d+)", _K, "node-rsa", algorithm="RSA", key_from_group=1),
    _r(rf"\bsetOptions\s*\(\s*\{{[^}}]*?signingScheme\s*:\s*{_Q}(?:pkcs1-)?(sha1|sha256|sha512|md5){_Q}", _D, "node-rsa", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(rf"\bencryptionScheme\s*:\s*{_Q}(pkcs1_oaep|pkcs1){_Q}", _C, "node-rsa", algorithm="RSA", padding=None),
    _r(r"\bsshpk\.(?:parseKey|parsePrivateKey|generatePrivateKey|parseCertificate|createSelfSignedCertificate)\s*\(", _K, "sshpk", algorithm="SSH", confidence="MEDIUM"),
    _r(rf"\bsshpk\.generatePrivateKey\s*\(\s*{_Q}(rsa|ecdsa|ed25519|dsa){_Q}", _K, "sshpk", algo_from_group=1, algo_map={"rsa": "RSA", "ecdsa": "ECDSA", "ed25519": "Ed25519", "dsa": "DSA"}),
    _r(r"\bfrom\s+['\"]ssh2['\"]|\brequire\s*\(\s*['\"]ssh2['\"]\s*\)|\bnew\s+(?:ssh2\.)?Client\s*\(\s*\)[\s\S]{0,300}?\.connect\s*\(\s*\{[^}]*(?:privateKey|password)|\bnode-ssh\b|\bnew\s+NodeSSH\s*\(|\bssh2-sftp-client\b|\bssh2\.utils\.generateKeyPair(?:Sync)?\s*\(", _TLS, "ssh2", algorithm="SSH", confidence="MEDIUM"),
    _r(rf"\bssh2\.utils\.generateKeyPair(?:Sync)?\s*\(\s*{_Q}(rsa|ecdsa|ed25519){_Q}|\bgenerateKeyPair(?:Sync)?\s*\(\s*{_Q}(rsa|ecdsa|ed25519){_Q}\s*,\s*\{{[^}}]*?(?:bits|comment|cipher|passphrase)", _K, "ssh2", algo_from_group=1, algo_map={"rsa": "RSA", "ecdsa": "ECDSA", "ed25519": "Ed25519"}),
    _r(r"\b(?:hash|hashjs)\.(sha1|sha224|sha256|sha384|sha512|ripemd160)\s*\(\s*\)|\brequire\s*\(\s*['\"]hash\.js['\"]\s*\)\s*\.(sha1|sha224|sha256|sha384|sha512|ripemd160)\b", _D, "hash.js", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\b(?:hash|hashjs)\.hmac\s*\(", _M, "hash.js", algorithm="HMAC"),
    _r(r"\brequire\s*\(\s*['\"](md5|sha1|js-sha1|js-sha256|js-sha512|js-sha3|js-md5|spark-md5|blueimp-md5|md5\.js|sha\.js|ripemd160|keccak|js-md4|md4|crypto-md5|object-hash|hash-wasm)['\"]\s*\)|\bfrom\s+['\"](md5|sha1|js-sha1|js-sha256|js-sha512|js-sha3|js-md5|spark-md5|blueimp-md5|md5\.js|sha\.js|ripemd160|keccak|js-md4|md4|crypto-md5|hash-wasm)['\"]", _D, "npm-hash", algo_from_group=1,
       algo_map={"md5": "MD5", "sha1": "SHA-1", "js-sha1": "SHA-1", "js-sha256": "SHA-256", "js-sha512": "SHA-512", "js-sha3": "SHA3-256", "js-md5": "MD5", "spark-md5": "MD5", "blueimp-md5": "MD5", "md5.js": "MD5", "sha.js": "SHA-256", "ripemd160": "RIPEMD-160", "keccak": "SHA3-256", "js-md4": "MD4", "md4": "MD4", "crypto-md5": "MD5", "hash-wasm": "UNKNOWN"}),
    _r(r"\bSparkMD5\.(?:hash|hashBinary|ArrayBuffer)\b|\bnew\s+SparkMD5(?:\.ArrayBuffer)?\s*\(", _D, "spark-md5", algorithm="MD5"),
    _r(r"(?<![\w.])(sha256|sha512|sha1|md5|keccak256)\s*\(\s*(?:['\"`]|\w+\s*\))", _D, "js-sha", algo_from_group=1, algo_map={"sha256": "SHA-256", "sha512": "SHA-512", "sha1": "SHA-1", "md5": "MD5", "keccak256": "SHA3-256"}, confidence="MEDIUM"),
    _r(r"\bethers\.(?:utils\.)?(keccak256|sha256|sha512|ripemd160|computeHmac|pbkdf2|scrypt|scryptSync|randomBytes|id|solidityKeccak256|solidityPackedKeccak256)\s*\(|\bWeb3\.utils\.(keccak256|sha3|soliditySha3)\s*\(|\bweb3\.utils\.(keccak256|sha3|soliditySha3)\s*\(", _D, "ethers", algo_from_group=1,
       algo_map={"keccak256": "SHA3-256", "sha256": "SHA-256", "sha512": "SHA-512", "ripemd160": "RIPEMD-160", "computehmac": "HMAC", "pbkdf2": "PBKDF2", "scrypt": "SCRYPT", "scryptsync": "SCRYPT", "randombytes": "CSPRNG", "id": "SHA3-256", "soliditykeccak256": "SHA3-256", "soliditypackedkeccak256": "SHA3-256", "sha3": "SHA3-256", "soliditysha3": "SHA3-256"}),
    _r(r"\bethers\.(?:Wallet\.createRandom|Wallet\.fromMnemonic|Wallet\.fromPhrase|SigningKey|utils\.SigningKey|HDNodeWallet)\b|\bnew\s+(?:ethers\.)?Wallet\s*\(|\bsecp256k1\.sign\b|\becsign\s*\(|\becrecover\s*\(|\bsignTypedData\s*\(|\bsignMessage\s*\(", _S, "ethers", algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bbip39\.(?:generateMnemonic|mnemonicToSeed(?:Sync)?|validateMnemonic)\s*\(|\bHDKey\.fromMasterSeed\s*\(|\bbip32\.fromSeed\s*\(", _KDF, "bip39", algorithm="PBKDF2", confidence="MEDIUM"),
    # ------------------------------------------------------------ password hashing
    _r(r"\bbcrypt(?:js)?\.(?:hash|hashSync|compare|compareSync|genSalt|genSaltSync)\s*\(|\brequire\s*\(\s*['\"](?:bcrypt|bcryptjs|bcrypt-nodejs|twin-bcrypt)['\"]\s*\)|\bfrom\s+['\"](?:bcrypt|bcryptjs)['\"]", _KDF, "bcrypt", algorithm="BCRYPT"),
    _r(r"\bargon2\.(?:hash|verify|needsRehash)\s*\(|\bargon2\.argon2(?:id|i|d)\b|\brequire\s*\(\s*['\"](?:argon2|argon2-browser|argon2-wasm|hash-wasm/argon2)['\"]\s*\)|\bfrom\s+['\"](?:argon2|argon2-browser)['\"]|\bargon2id\s*\(|\bargon2i\s*\(|\bargon2d\s*\(", _KDF, "argon2", algorithm="ARGON2"),
    _r(r"\bscrypt(?:\.scrypt|\.hash|\.verify|\.kdf|Sync|Async)?\s*\(|\brequire\s*\(\s*['\"](?:scrypt-js|scryptsy|scrypt-async|scrypt|scrypt-kdf)['\"]\s*\)|\bfrom\s+['\"](?:scrypt-js|scryptsy|scrypt-async|scrypt-kdf)['\"]", _KDF, "scrypt", algorithm="SCRYPT"),
    _r(r"\bpbkdf2(?:Sync)?\s*\(|\brequire\s*\(\s*['\"]pbkdf2['\"]\s*\)|\bfrom\s+['\"]pbkdf2['\"]", _KDF, "pbkdf2", algorithm="PBKDF2"),
    _r(rf"\bpbkdf2(?:Sync)?\s*\((?:[^;()]*?,){{4}}\s*{_Q}(sha1|sha224|sha256|sha384|sha512|md5|sha3-256|ripemd160){_Q}", _D, "pbkdf2", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bhkdf(?:Sync)?\s*\(|\brequire\s*\(\s*['\"](?:futoin-hkdf|@panva/hkdf|hkdf)['\"]\s*\)|\bfrom\s+['\"](?:futoin-hkdf|@panva/hkdf)['\"]", _KDF, "hkdf", algorithm="HKDF", purpose="KEY_GENERATION"),
    _r(r"\bcredential\.hash\s*\(|\brequire\s*\(\s*['\"]credential['\"]\s*\)|\bpassword-hash\b|\bpasswordHash\.(?:generate|verify)\s*\(|\bunixcrypt\b|\bcrypt3\b|\bmd5-crypt\b|\bsha512crypt\b|\bapache-md5\b|\bapache-crypt\b|\bhtpasswd\b", _KDF, "password-hash", algorithm="UNKNOWN", confidence="MEDIUM"),
    _r(r"\bfrom\s+['\"]md5-crypt['\"]|\bmd5crypt\s*\(", _KDF, "md5-crypt", algorithm="MD5", confidence_reason="md5-crypt password hashing"),
    _r(r"\bfrom\s+['\"](?:sha512crypt|sha512-crypt)['\"]|\bsha512crypt\s*\(", _KDF, "sha512-crypt", algorithm="SHA-512"),
    _r(r"\bdes(?:-crypt)?\.crypt\s*\(|\bunixcrypt\.crypt\s*\(|\bcrypt3\s*\(", _KDF, "des-crypt", algorithm="DES"),
    # ------------------------------------------------------------ OpenPGP / age / misc
    _r(r"\bopenpgp\.(?:encrypt|decrypt|sign|verify|generateKey|readKey|readPrivateKey|readMessage|createMessage|decryptKey|encryptKey|reformatKey|revokeKey)\s*\(", _C, "openpgpjs", algorithm="PGP", confidence="MEDIUM"),
    _r(rf"\bopenpgp\.generateKey\s*\(\s*\{{[^}}]*?\btype\s*:\s*{_Q}(rsa|ecc|curve25519){_Q}", _K, "openpgpjs", algo_from_group=1, algo_map={"rsa": "RSA", "ecc": "ECDSA", "curve25519": "Ed25519"}),
    _r(rf"\bopenpgp\.generateKey\s*\(\s*\{{[^}}]*?\brsaBits\s*:\s*(\d+)", _K, "openpgpjs", algorithm="RSA", key_from_group=1),
    _r(rf"\bcurve\s*:\s*{_Q}(curve25519|ed25519|p256|p384|p521|secp256k1|brainpoolP256r1|brainpoolP384r1|brainpoolP512r1){_Q}", _K, "openpgpjs", algo_from_group=1, algo_map={"curve25519": "X25519", "ed25519": "Ed25519", "p256": "ECDSA", "p384": "ECDSA", "p521": "ECDSA", "secp256k1": "ECDSA", "brainpoolp256r1": "ECDSA", "brainpoolp384r1": "ECDSA", "brainpoolp512r1": "ECDSA"}, confidence="MEDIUM"),
    _r(r"\bage\.(?:Encrypter|Decrypter)\s*\(|\bnew\s+age\.(?:Encrypter|Decrypter)\s*\(|\bage-encryption\b", _C, "age-encryption", algorithm="ChaCha20-Poly1305", confidence="MEDIUM"),
    _r(r"\bnew\s+(?:Fernet|fernet\.Secret|fernet\.Token)\s*\(|\brequire\s*\(\s*['\"]fernet['\"]\s*\)", _C, "fernet", algorithm="AES", mode="CBC"),
    _r(r"\bnew\s+(?:Fernet|fernet\.Secret|fernet\.Token)\s*\(", _M, "fernet", algorithm="HMAC-SHA256"),
    _r(r"\bcryptr\b|\bnew\s+Cryptr\s*\(", _C, "cryptr", algorithm="AES", mode="GCM"),
    _r(r"\bsimple-encryptor\b|\bsimpleEncryptor\s*\(|\bencryptor\.(?:encrypt|decrypt)\s*\(", _C, "simple-encryptor", algorithm="AES", mode="CBC", confidence="MEDIUM"),
    _r(r"\bcrypto-random-string\b|\bcryptoRandomString\s*\(|\bnanoid\s*\(|\buuid\.v4\s*\(|\buuidv4\s*\(", _RNG, "npm-random", algorithm="CSPRNG", confidence="LOW"),
    _r(r"\bseedrandom\s*\(|\brequire\s*\(\s*['\"]seedrandom['\"]\s*\)|\bchance\.(?:string|guid|hash)\s*\(|\bfaker\.(?:random|string|datatype)\.\w+\s*\(", _RNG, "seedrandom", algorithm="PRNG", confidence="LOW", confidence_reason="deterministic/insecure RNG; not for key material"),
    # ------------------------------------------------------------ TLS
    _r(rf"\bsecureProtocol\s*:\s*{_Q}(SSLv2_method|SSLv3_method|TLSv1_method|TLSv1_1_method|TLSv1_2_method|TLSv1_3_method|SSLv23_method|TLS_method){_Q}", _TLS, "node-tls", algo_from_group=1,
       algo_map={"sslv2_method": "SSLv2", "sslv3_method": "SSLv3", "tlsv1_method": "TLS1.0", "tlsv1_1_method": "TLS1.1", "tlsv1_2_method": "TLS1.2", "tlsv1_3_method": "TLS1.3", "sslv23_method": "TLS", "tls_method": "TLS"}),
    _r(rf"\b(?:minVersion|maxVersion)\s*:\s*{_Q}(TLSv1|TLSv1\.1|TLSv1\.2|TLSv1\.3){_Q}", _TLS, "node-tls", algo_from_group=1, algo_map={"tlsv1": "TLS1.0", "tlsv1.1": "TLS1.1", "tlsv1.2": "TLS1.2", "tlsv1.3": "TLS1.3"}),
    _r(rf"\bciphers\s*:\s*{_Q}([^'\"]+){_Q}", _TLS, "node-tls", algorithm="TLS-CIPHERS", confidence="MEDIUM"),
    _r(r"\brejectUnauthorized\s*:\s*false\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*(?:=|\]\s*=)\s*['\"]?0\b|\bprocess\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|\bstrictSSL\s*:\s*false\b|\binsecureHTTPParser\s*:\s*true\b|\bcheckServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:undefined|null|\{\s*\})", _TLS, "node-tls", algorithm="TLS-CERT-NONE", confidence_reason="certificate verification disabled"),
    _r(r"\btls\.(?:connect|createServer|createSecureContext|TLSSocket|getCiphers|DEFAULT_MIN_VERSION|DEFAULT_MAX_VERSION)\b|\bhttps\.(?:createServer|request|get|Agent)\s*\(|\bnew\s+https\.Agent\s*\(|\bnew\s+Agent\s*\(\s*\{[^}]*(?:rejectUnauthorized|ca|cert|key|minVersion|ciphers)|\bcreateSecureContext\s*\(|\bsecureContext\s*:", _TLS, "node-tls", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\btls\.DEFAULT_MIN_VERSION\s*=\s*['\"](TLSv1|TLSv1\.1)['\"]", _TLS, "node-tls", algo_from_group=1, algo_map={"tlsv1": "TLS1.0", "tlsv1.1": "TLS1.1"}),
    _r(r"\bhonorCipherOrder\s*:|\becdhCurve\s*:\s*['\"]([A-Za-z0-9:_-]+)['\"]|\bdhparam\s*:", _TLS, "node-tls", algorithm="TLS", confidence="LOW"),
    _r(r"\bnew\s+WebSocket\s*\(\s*['\"]wss://|\bnew\s+WebSocketServer\s*\(\s*\{[^}]*server\s*:\s*https", _TLS, "ws", algorithm="TLS", confidence="LOW"),
    _r(r"\bhttps?\.globalAgent\.options\.(?:rejectUnauthorized|ca|secureProtocol|ciphers)\s*=", _TLS, "node-tls", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\bpem\.(?:createCertificate|createPrivateKey|createCSR|readCertificateInfo|getPublicKey|createDhparam|createEcparam)\s*\(|\bselfsigned\.generate\s*\(|\bmkcert\b|\bdevcert\b|\bacme-client\b|\bgreenlock\b", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "pem", algorithm="X509", confidence="MEDIUM"),
    # ------------------------------------------------------------ React Native / Expo / Browser extras
    _r(r"\bexpo-crypto\b|\bCrypto\.digestStringAsync\s*\(\s*(?:Crypto\.)?CryptoDigestAlgorithm\.(MD2|MD4|MD5|SHA1|SHA256|SHA384|SHA512)\b|\bCryptoDigestAlgorithm\.(MD2|MD4|MD5|SHA1|SHA256|SHA384|SHA512)\b", _D, "expo-crypto", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bCrypto\.getRandomBytes(?:Async)?\s*\(|\bCrypto\.randomUUID\s*\(|\bexpo-random\b|\bRandom\.getRandomBytes(?:Async)?\s*\(|\breact-native-get-random-values\b|\breact-native-randombytes\b", _RNG, "expo-crypto", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\breact-native-aes-crypto\b|\bAes\.(?:encrypt|decrypt|pbkdf2|hmac256|hmac512|sha1|sha256|sha512|randomKey)\s*\(|\breact-native-quick-crypto\b|\breact-native-rsa-native\b|\bRSA\.(?:generateKeys|encrypt|decrypt|sign|verify)\s*\(|\bRSAKeychain\.(?:generateKeys|sign|encrypt)\s*\(", _C, "react-native-crypto", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bAes\.(?:encrypt|decrypt|randomKey)\s*\(", _C, "react-native-aes-crypto", algorithm="AES"),
    _r(r"\bAes\.pbkdf2\s*\(", _KDF, "react-native-aes-crypto", algorithm="PBKDF2"),
    _r(r"\bAes\.hmac256\s*\(", _M, "react-native-aes-crypto", algorithm="HMAC-SHA256"),
    _r(r"\bAes\.hmac512\s*\(", _M, "react-native-aes-crypto", algorithm="HMAC-SHA512"),
    _r(r"\bAes\.sha1\s*\(", _D, "react-native-aes-crypto", algorithm="SHA-1"),
    _r(r"\bAes\.sha256\s*\(", _D, "react-native-aes-crypto", algorithm="SHA-256"),
    _r(r"\bAes\.sha512\s*\(", _D, "react-native-aes-crypto", algorithm="SHA-512"),
    _r(r"\bRSA\.(?:generateKeys|encrypt|decrypt|sign|verify|sign64|verify64|encrypt64)\s*\(|\bRSAKeychain\.(?:generateKeys|generateKeyPair|sign|verify|encrypt|decrypt)\s*\(", _K, "react-native-rsa-native", algorithm="RSA"),
    _r(r"\bRSA\.generateKeys\s*\(\s*(\d+)", _K, "react-native-rsa-native", algorithm="RSA", key_from_group=1),
    _r(r"\bKeychain\.(?:setGenericPassword|getGenericPassword|setInternetCredentials)\s*\(|\bSecureStore\.(?:setItemAsync|getItemAsync)\s*\(|\bEncryptedStorage\.(?:setItem|getItem)\s*\(|\bMMKV\s*\(\s*\{[^}]*encryptionKey", _C, "secure-storage", algorithm="AES", confidence="LOW"),
    _r(r"\bnew\s+(?:Web)?Crypto\s*\(\s*\)|\bwebcrypto\b\s*=\s*require\s*\(\s*['\"](?:node:)?crypto['\"]\s*\)\.webcrypto|\bglobalThis\.crypto\.subtle\b|\bself\.crypto\.subtle\b", _C, "webcrypto", algorithm="UNKNOWN", confidence="LOW"),
]


def run_javascript_rules(file_path: Path, repo_root: Path | None, source: str, language: str, scanner_id: str, seen: set[tuple[int, str]] | None = None) -> list[RawFinding]:
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=source,
        rules=RULES,
        language=language,
        scanner_id=scanner_id,
        confidence_reason="javascript-library-api",
        strip_comments=False,  # caller already stripped and desugared
        seen=seen,
    )
