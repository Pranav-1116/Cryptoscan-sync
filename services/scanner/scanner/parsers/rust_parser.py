"""Rust crypto detector (ring, RustCrypto crates, openssl, rustls, dalek, sodiumoxide, orion)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.rule_engine import CIPHER_TOKENS, DIGEST_TOKENS, Rule, run_rules

SCANNER_ID = "static-rust-scanner-v1.0"

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


_RING_SIG = {
    "ed25519": "Ed25519",
    "ecdsa": "ECDSA",
    "rsa": "RSA",
}
_RING_DIGEST = {
    "sha1_for_legacy_use_only": "SHA-1",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha512_256": "SHA-512",
}

_RULES: list[Rule] = [
    _r(r"\bKey::(?:derive_from|generate|from)\s*\(|\bCookieJar::private\b|\bPrivateJar\b|\bSignedJar\b|\bjar\.private(?:_mut)?\s*\(|\bjar\.signed(?:_mut)?\s*\(", _M, "cookie", algorithm="HMAC-SHA256", confidence="MEDIUM", confidence_reason="cookie crate signed/private jars use HMAC-SHA256"),
    _r(r"\bKey::(?:derive_from|generate|from)\s*\(|\bCookieJar::private\b|\bPrivateJar\b|\bjar\.private(?:_mut)?\s*\(|\bSessionMiddleware::new\s*\(", _C, "cookie", algorithm="AES", mode="GCM", confidence="MEDIUM", confidence_reason="cookie crate private jars use AES-256-GCM"),
    _r(r"\bsslmode=(?:disable|allow|prefer)\b|\bssl-mode=(?:DISABLED|PREFERRED)\b|\bsslmode=disable\b|\bPgSslMode::(?:Disable|Allow|Prefer)\b|\bMySqlSslMode::(?:Disabled|Preferred)\b", _TLS, "sqlx", algorithm="TLS-DISABLED", confidence="MEDIUM", confidence_reason="database connection without TLS (ssl mode)"),
    # ------------------------------------------------------------ RustCrypto hashes
    _r(r"\bMd5::|\bmd5::(?:Md5|compute|Digest)|\buse md5\b", _D, "md-5", algorithm="MD5"),
    _r(r"\bMd4::|\bmd4::", _D, "md4", algorithm="MD4"),
    _r(r"\bSha1::|\bsha1::(?:Sha1|Digest)|\bsha1_smol::", _D, "sha1", algorithm="SHA-1"),
    _r(r"\bSha224::|\bsha2::Sha224", _D, "sha2", algorithm="SHA-224"),
    _r(r"\bSha256::|\bsha2::Sha256|\bsha2::\{[^}]*\bSha256\b", _D, "sha2", algorithm="SHA-256"),
    _r(r"\bSha384::|\bsha2::Sha384", _D, "sha2", algorithm="SHA-384"),
    _r(r"\bSha512::|\bsha2::Sha512|\bsha2::\{[^}]*\bSha512\b", _D, "sha2", algorithm="SHA-512"),
    _r(r"\bSha3_256::|\bsha3::Sha3_256|\bKeccak256::", _D, "sha3", algorithm="SHA3-256"),
    _r(r"\bSha3_512::|\bsha3::Sha3_512", _D, "sha3", algorithm="SHA3-512"),
    _r(r"\bBlake2b(?:512|256)?::|\bblake2::|\bblake2b_simd::", _D, "blake2", algorithm="BLAKE2b"),
    _r(r"\bblake3::", _D, "blake3", algorithm="BLAKE3"),
    _r(r"\bRipemd160::|\bripemd::", _D, "ripemd", algorithm="RIPEMD-160"),
    # ------------------------------------------------------------ RustCrypto ciphers / AEAD
    _r(r"\bAes(128|192|256)Gcm(?:Siv)?\b", _C, "aes-gcm", algorithm="AES", mode="GCM"),
    _r(r"\bAes(128|192|256)Ccm\b", _C, "ccm", algorithm="AES", mode="CCM"),
    _r(r"\bAes(128|192|256)(?:Enc|Dec)?\b|\baes::(?:Aes|cipher)|\buse aes\b", _C, "aes", algorithm="AES"),
    _r(r"\bAes(?:128|256)Siv\b|\baes_siv::", _C, "aes-siv", algorithm="AES", mode="SIV"),
    _r(r"\bTdesEde[23]\b|\bTdesEee[23]\b", _C, "des", algorithm="3DES"),
    _r(r"\bDes\b(?=::|>|,|\))|\bdes::Des\b|\buse des\b", _C, "des", algorithm="DES"),
    _r(r"\bRc4\b|\brc4::", _C, "rc4", algorithm="RC4"),
    _r(r"\bRc2\b|\brc2::", _C, "rc2", algorithm="RC2"),
    _r(r"\bBlowfish\b(?=::|>|,|\))|\bblowfish::", _C, "blowfish", algorithm="Blowfish"),
    _r(r"\bCast5\b|\bcast5::", _C, "cast5", algorithm="CAST5"),
    _r(r"\bTwofish\b(?=::|>)|\btwofish::", _C, "twofish", algorithm="Twofish"),
    _r(r"\bSerpent\b(?=::|>)|\bserpent::", _C, "serpent", algorithm="Serpent"),
    _r(r"\bCamellia(?:128|192|256)?\b(?=::|>)|\bcamellia::", _C, "camellia", algorithm="Camellia"),
    _r(r"\bIdea\b(?=::|>)|\bidea::", _C, "idea", algorithm="IDEA"),
    _r(r"\bXChaCha20Poly1305\b|\bXChaCha8Poly1305\b|\bXChaCha12Poly1305\b", _C, "chacha20poly1305", algorithm="XChaCha20-Poly1305"),
    _r(r"\bChaCha20Poly1305\b|\bChaCha8Poly1305\b|\bChaCha12Poly1305\b|\bchacha20poly1305::", _C, "chacha20poly1305", algorithm="ChaCha20-Poly1305"),
    _r(r"\bChaCha20\b(?=::|>|,|\))|\bchacha20::(?:ChaCha20|cipher)|\bXChaCha20\b(?=::|>)", _C, "chacha20", algorithm="ChaCha20"),
    _r(r"\bSalsa20\b(?=::|>)|\bsalsa20::|\bXSalsa20\b", _C, "salsa20", algorithm="Salsa20"),
    # ------------------------------------------------------------ RustCrypto asymmetric
    _r(r"\bRsaPrivateKey::new\([^,]+,\s*(\d+)", _K, "rsa", algorithm="RSA", key_from_group=1),
    _r(r"\bRsaPrivateKey\b|\bRsaPublicKey\b|\brsa::(?:Rsa|pkcs1v15|pss|Oaep|Pkcs1v15)|\bPkcs1v15(?:Encrypt|Sign)\b|\bOaep::new", _K, "rsa", algorithm="RSA"),
    _r(r"\bp256::ecdsa|\bp384::ecdsa|\bp521::ecdsa|\bk256::ecdsa|\becdsa::(?:SigningKey|VerifyingKey|Signature|signature)", _S, "ecdsa", algorithm="ECDSA"),
    _r(r"\bp256::(?:SecretKey|PublicKey|ecdh)|\bp384::(?:SecretKey|ecdh)|\bk256::(?:SecretKey|ecdh)", _K, "elliptic-curve", algorithm="ECDSA"),
    _r(r"\becdh::(?:EphemeralSecret|diffie_hellman)", _KA, "elliptic-curve", algorithm="ECDH"),
    _r(r"\bEd25519\b|\bed25519_dalek::|\bed25519::|\bEd25519KeyPair\b|\bSigningKey::generate\b", _S, "ed25519", algorithm="Ed25519"),
    _r(r"\bed448\b|\bEd448\b", _S, "ed448", algorithm="Ed448"),
    _r(r"\bx25519_dalek::|\bX25519\b|\bx25519::", _KA, "x25519", algorithm="X25519"),
    _r(r"\bEphemeralSecret::(?:random_from_rng|new|random)\b|\bStaticSecret::(?:random_from_rng|new|random)\b", _KA, "x25519-dalek", algorithm="X25519"),
    _r(r"\bcurve25519_dalek::", _KA, "curve25519-dalek", algorithm="X25519", confidence="MEDIUM"),
    _r(r"\bdsa::(?:SigningKey|Components|KeySize)", _K, "dsa", algorithm="DSA"),
    _r(r"\bpqcrypto_kyber::|\bpqc_kyber::|\bml_kem::|\bMlKem(?:512|768|1024)\b|\bkyber(?:512|768|1024)\b", _KA, "pqcrypto", algorithm="ML-KEM"),
    _r(r"\bpqcrypto_dilithium::|\bml_dsa::|\bMlDsa(?:44|65|87)\b|\bdilithium[235]\b", _S, "pqcrypto", algorithm="ML-DSA"),
    _r(r"\bpqcrypto_sphincsplus::|\bslh_dsa::", _S, "pqcrypto", algorithm="SLH-DSA"),
    # ------------------------------------------------------------ MAC / KDF / password hashing
    _r(r"\bHmac\s*<\s*(\w+)\s*>|\bhmac::(?:Hmac|SimpleHmac|Mac)", _M, "hmac", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bCmac\s*<|\bcmac::", _M, "cmac", algorithm="CMAC"),
    _r(r"\bPoly1305\b(?=::|>)|\bpoly1305::", _M, "poly1305", algorithm="Poly1305"),
    _r(r"\bHkdf\s*<\s*(\w+)\s*>|\bhkdf::(?:Hkdf|HkdfExtract)", _KDF, "hkdf", algorithm="HKDF", emit_digest_group=1, purpose="KEY_GENERATION"),
    _r(r"\bpbkdf2::(?:pbkdf2|pbkdf2_hmac|pbkdf2_array|Pbkdf2)|\bpbkdf2_hmac\s*::\s*<\s*(\w+)\s*>", _KDF, "pbkdf2", algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bscrypt::(?:scrypt|Scrypt|Params)", _KDF, "scrypt", algorithm="SCRYPT"),
    _r(r"\bargon2::|\bArgon2::(?:default|new)\b|\bArgon2\b(?=::|,|\))", _KDF, "argon2", algorithm="ARGON2"),
    _r(r"\bbcrypt::(?:hash|verify|hash_with_salt|DEFAULT_COST)|\bbcrypt_pbkdf::", _KDF, "bcrypt", algorithm="BCRYPT"),
    _r(r"\bballoon_hash::", _KDF, "balloon-hash", algorithm="BALLOON"),
    # ------------------------------------------------------------ ring
    _r(r"\bring::aead::\{[^}]*\b(AES_128_GCM|AES_256_GCM)\b|\bring::aead::(AES_128_GCM|AES_256_GCM)\b|\baead::(AES_128_GCM|AES_256_GCM)\b", _C, "ring", algorithm="AES", mode="GCM"),
    _r(r"\bring::aead::\{[^}]*\bCHACHA20_POLY1305\b|\bring::aead::CHACHA20_POLY1305\b|\baead::CHACHA20_POLY1305\b", _C, "ring", algorithm="ChaCha20-Poly1305"),
    _r(r"&\s*(AES_128_GCM|AES_256_GCM)\b", _C, "ring", algorithm="AES", mode="GCM"),
    _r(r"&\s*CHACHA20_POLY1305\b", _C, "ring", algorithm="ChaCha20-Poly1305"),
    _r(r"\bring::aead::", _C, "ring", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bring::digest::\{[^}]*\b(SHA1_FOR_LEGACY_USE_ONLY|SHA1|SHA256|SHA384|SHA512|SHA512_256)\b", _D, "ring", algo_from_group=1, algo_map=_RING_DIGEST),
    _r(r"\bring::digest::(SHA1_FOR_LEGACY_USE_ONLY|SHA1|SHA256|SHA384|SHA512|SHA512_256)\b|\bdigest::(SHA1_FOR_LEGACY_USE_ONLY|SHA1|SHA256|SHA384|SHA512|SHA512_256)\b", _D, "ring", algo_from_group=1, algo_map=_RING_DIGEST),
    _r(r"\bdigest\(\s*&\s*(SHA1_FOR_LEGACY_USE_ONLY|SHA1|SHA256|SHA384|SHA512|SHA512_256)\b|\bContext::new\(\s*&\s*(SHA1_FOR_LEGACY_USE_ONLY|SHA1|SHA256|SHA384|SHA512)\b", _D, "ring", algo_from_group=1, algo_map=_RING_DIGEST),
    _r(r"\bHMAC_(SHA1_FOR_LEGACY_USE_ONLY|SHA1|SHA256|SHA384|SHA512)\b", _M, "ring", algorithm="HMAC", emit_digest_group=1),
    _r(r"\bECDSA_P(?:256|384)_(SHA256|SHA384)_(?:ASN1|FIXED)(?:_SIGNING)?\b", _S, "ring", algorithm="ECDSA", emit_digest_group=1),
    _r(r"\bRSA_(?:PKCS1|PSS)_(?:2048_8192_)?(SHA256|SHA384|SHA512)\b|\bRSA_PKCS1_(?:1024_8192_|2048_8192_)?SHA1(?:_FOR_LEGACY_USE_ONLY)?\b|\bRsaKeyPair::from_(?:pkcs8|der)\b", _S, "ring", algorithm="RSA", emit_digest_group=1),
    _r(r"\bRSA_PKCS1_(?:1024_8192_|2048_8192_)?SHA1(?:_FOR_LEGACY_USE_ONLY)?\b", _D, "ring", algorithm="SHA-1"),
    _r(r"\bsignature::\{[^}]*\bED25519\b|\bsignature::ED25519\b|\bEd25519KeyPair::(?:generate_pkcs8|from_pkcs8|from_seed_and_public_key)\b", _S, "ring", algorithm="Ed25519"),
    _r(r"\bring::signature::", _S, "ring", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bring::agreement::(?:X25519|ECDH_P256|ECDH_P384)\b|\bagreement::(X25519|ECDH_P256|ECDH_P384)\b|\bEphemeralPrivateKey::generate\(\s*&\s*(X25519|ECDH_P256|ECDH_P384)\b", _KA, "ring", algo_from_group=1,
       algo_map={"x25519": "X25519", "ecdh_p256": "ECDH", "ecdh_p384": "ECDH"}),
    _r(r"\bring::agreement::X25519\b", _KA, "ring", algorithm="X25519"),
    _r(r"\bring::agreement::ECDH_P(?:256|384)\b", _KA, "ring", algorithm="ECDH"),
    _r(r"\bring::pbkdf2::|\bPBKDF2_HMAC_(SHA1|SHA256|SHA384|SHA512)\b", _KDF, "ring", algorithm="PBKDF2", emit_digest_group=1),
    _r(r"\bPBKDF2_HMAC_(?:SHA1|SHA256|SHA384|SHA512)\b", _M, "ring", algorithm="HMAC", confidence="MEDIUM", confidence_reason="PBKDF2 PRF is HMAC"),
    _r(r"\bring::hkdf::|\bHKDF_(SHA256|SHA384|SHA512)\b", _KDF, "ring", algorithm="HKDF", emit_digest_group=1, purpose="KEY_GENERATION"),
    _r(r"\bring::rand::SystemRandom\b|\bSystemRandom::new\(\)", _RNG, "ring", algorithm="CSPRNG", confidence="MEDIUM"),
    # ------------------------------------------------------------ openssl crate
    _r(r"\bCipher::(aes_\d{3}_\w+|des_ede3_\w+|des_ede_\w+|des_\w+|rc4(?:_40)?|rc2_\w+|bf_\w+|cast5_\w+|idea_\w+|seed_\w+|camellia_\d{3}_\w+|chacha20_poly1305|chacha20|sm4_\w+|aria_\d{3}_\w+)\s*\(", _C, "openssl", algo_from_group=1, algo_map=CIPHER_TOKENS, split_cipher=True),
    _r(r"\bMessageDigest::(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|ripemd160|sm3)\s*\(", _D, "openssl", algo_from_group=1, algo_map=DIGEST_TOKENS),
    _r(r"\bopenssl::sha::(sha1|sha224|sha256|sha384|sha512|Sha1|Sha256|Sha512)\b|\bopenssl::md5::\w+|\bopenssl::sha::\{[^}]*\b(sha1|sha256|sha512)\b", _D, "openssl", algo_from_group=1, algo_map={**DIGEST_TOKENS, "sha1": "SHA-1"}),
    _r(r"\bopenssl::hash::(?:hash|Hasher|MessageDigest)", _D, "openssl", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bopenssl::symm::(?:encrypt|decrypt|Cipher|Crypter)", _C, "openssl", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bRsa::generate\(\s*(\d+)", _K, "openssl", algorithm="RSA", key_from_group=1),
    _r(r"\bopenssl::rsa::(?:Rsa|Padding)|\bRsa::(?:generate|private_key_from_pem|public_key_from_pem|from_private_components)\b|\bPadding::PKCS1(?:_OAEP|_PSS)?\b", _K, "openssl", algorithm="RSA"),
    _r(r"\bopenssl::ec::(?:EcKey|EcGroup)|\bEcKey::generate\b|\bEcGroup::from_curve_name\b|\bopenssl::ecdsa::EcdsaSig\b|\bEcdsaSig::sign\b", _S, "openssl", algorithm="ECDSA"),
    _r(r"\bNid::(?:X9_62_PRIME256V1|SECP256K1|SECP384R1|SECP521R1)\b", _S, "openssl", algorithm="ECDSA", confidence="MEDIUM"),
    _r(r"\bopenssl::dsa::Dsa\b|\bDsa::generate\b", _K, "openssl", algorithm="DSA"),
    _r(r"\bopenssl::dh::Dh\b|\bDh::(?:get_2048_256|from_pqg|generate_params)\b", _KA, "openssl", algorithm="DH"),
    _r(r"\bopenssl::derive::Deriver\b", _KA, "openssl", algorithm="ECDH", confidence="MEDIUM"),
    _r(r"\bPKey::generate_ed25519\b|\bId::ED25519\b", _S, "openssl", algorithm="Ed25519"),
    _r(r"\bPKey::generate_x25519\b|\bId::X25519\b", _KA, "openssl", algorithm="X25519"),
    _r(r"\bopenssl::sign::(?:Signer|Verifier)|\bSigner::new\(\s*MessageDigest::(md5|sha1|sha224|sha256|sha384|sha512)\s*\(", _S, "openssl", algorithm="UNKNOWN", confidence="LOW", emit_digest_group=1),
    _r(r"\bopenssl::pkcs5::(?:pbkdf2_hmac|scrypt|bytes_to_key)|\bpbkdf2_hmac\(", _KDF, "openssl", algorithm="PBKDF2"),
    _r(r"\bopenssl::pkcs5::scrypt\b", _KDF, "openssl", algorithm="SCRYPT"),
    _r(r"\bopenssl::rand::rand_bytes\b|\brand_bytes\(", _RNG, "openssl", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bopenssl::ssl::(?:SslContext|SslAcceptor|SslConnector|SslMethod|SslContextBuilder)|\bSslMethod::tls(?:_client|_server)?\(\)|\bSslConnector::builder\b|\bSslAcceptor::mozilla_\w+\b", _TLS, "openssl", algorithm="TLS"),
    _r(r"\bSslVersion::SSL3\b", _TLS, "openssl", algorithm="SSLv3"),
    _r(r"\bSslVersion::TLS1\b", _TLS, "openssl", algorithm="TLS1.0"),
    _r(r"\bSslVersion::TLS1_1\b", _TLS, "openssl", algorithm="TLS1.1"),
    _r(r"\bSslVersion::TLS1_2\b", _TLS, "openssl", algorithm="TLS1.2"),
    _r(r"\bSslVersion::TLS1_3\b", _TLS, "openssl", algorithm="TLS1.3"),
    _r(r"\bSslVerifyMode::NONE\b|\bset_verify\(\s*SslVerifyMode::NONE", _TLS, "openssl", algorithm="TLS-CERT-NONE"),
    _r(r"\bopenssl::x509::(?:X509|X509Builder|X509Req)\b|\bX509::from_pem\b|\bX509Builder::new\b", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "openssl", algorithm="X509", confidence="MEDIUM"),
    # ------------------------------------------------------------ rustls / native-tls / tokio-rustls
    _r(r"\brustls::(?:ServerConfig|ClientConfig|RootCertStore|ServerConnection|ClientConnection|StreamOwned)|\buse rustls\b|\btokio_rustls::|\brustls_pemfile::", _TLS, "rustls", algorithm="TLS"),
    _r(r"\b(?:ClientConfig|ServerConfig)::builder(?:_with_protocol_versions)?\(", _TLS, "rustls", algorithm="TLS"),
    _r(r"\bRootCertStore::empty\(\)|\bwith_root_certificates\(|\bwith_no_client_auth\(\)|\bwith_safe_defaults\(\)|\bdangerous\(\)\s*\.\s*set_certificate_verifier", _TLS, "rustls", algorithm="TLS", confidence="MEDIUM"),
    _r(r"\brustls::version::TLS12\b", _TLS, "rustls", algorithm="TLS1.2"),
    _r(r"\brustls::version::TLS13\b", _TLS, "rustls", algorithm="TLS1.3"),
    _r(r"\bnative_tls::(?:TlsConnector|TlsAcceptor|Identity)|\bTlsConnector::(?:new|builder)\b", _TLS, "native-tls", algorithm="TLS"),
    _r(r"\bdanger_accept_invalid_certs\(\s*true\s*\)|\bdanger_accept_invalid_hostnames\(\s*true\s*\)", _TLS, "native-tls", algorithm="TLS-CERT-NONE"),
    _r(r"\bwebpki::|\bwebpki_roots::", {"api_type": "SIGNATURE", "purpose": "VERIFICATION"}, "webpki", algorithm="X509", confidence="MEDIUM"),
    _r(r"\bthrussh::|\brussh::|\bssh2::Session\b|\bssh_key::", _TLS, "ssh", algorithm="SSH", confidence="MEDIUM"),
    # ------------------------------------------------------------ sodiumoxide / orion / dryoc / age / jwt
    _r(r"\bsodiumoxide::crypto::secretbox\b|\bsecretbox::(?:seal|open|gen_key|Key)\b", _C, "sodiumoxide", algorithm="XSalsa20-Poly1305"),
    _r(r"\bsodiumoxide::crypto::box_\b|\bbox_::(?:seal|open|gen_keypair)\b", _C, "sodiumoxide", algorithm="X25519"),
    _r(r"\bsodiumoxide::crypto::sign\b|\bsign::(?:gen_keypair|sign_detached|verify_detached)\b", _S, "sodiumoxide", algorithm="Ed25519"),
    _r(r"\bsodiumoxide::crypto::aead::(?:chacha20poly1305|chacha20poly1305_ietf|xchacha20poly1305_ietf)\b", _C, "sodiumoxide", algorithm="ChaCha20-Poly1305"),
    _r(r"\bsodiumoxide::crypto::aead::aes256gcm\b", _C, "sodiumoxide", algorithm="AES", mode="GCM"),
    _r(r"\bsodiumoxide::crypto::pwhash\b|\bpwhash::(?:argon2id13|argon2i13|scryptsalsa208sha256)\b", _KDF, "sodiumoxide", algorithm="ARGON2"),
    _r(r"\bsodiumoxide::crypto::hash::sha256\b", _D, "sodiumoxide", algorithm="SHA-256"),
    _r(r"\bsodiumoxide::crypto::hash::sha512\b|\bsodiumoxide::crypto::hash::hash\b", _D, "sodiumoxide", algorithm="SHA-512"),
    _r(r"\bsodiumoxide::crypto::auth\b", _M, "sodiumoxide", algorithm="HMAC"),
    _r(r"\bsodiumoxide::crypto::", _C, "sodiumoxide", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\borion::aead\b|\borion::hazardous::aead::xchacha20poly1305\b", _C, "orion", algorithm="XChaCha20-Poly1305"),
    _r(r"\borion::hazardous::aead::chacha20poly1305\b", _C, "orion", algorithm="ChaCha20-Poly1305"),
    _r(r"\borion::pwhash\b|\borion::hazardous::kdf::argon2i\b", _KDF, "orion", algorithm="ARGON2"),
    _r(r"\borion::kdf\b|\borion::hazardous::kdf::pbkdf2\b", _KDF, "orion", algorithm="PBKDF2"),
    _r(r"\borion::auth\b|\borion::hazardous::mac::hmac\b", _M, "orion", algorithm="HMAC"),
    _r(r"\borion::hash\b|\borion::hazardous::hash::blake2\b", _D, "orion", algorithm="BLAKE2b"),
    _r(r"\borion::hazardous::hash::sha2::sha256\b", _D, "orion", algorithm="SHA-256"),
    _r(r"\borion::hazardous::hash::sha2::sha512\b", _D, "orion", algorithm="SHA-512"),
    _r(r"\borion::hazardous::ecc::x25519\b", _KA, "orion", algorithm="X25519"),
    _r(r"\borion::hazardous::aead", _C, "orion", algorithm="UNKNOWN", confidence="LOW"),
    _r(r"\bage::(?:Encryptor|Decryptor|x25519)", _C, "age", algorithm="ChaCha20-Poly1305", confidence="MEDIUM"),
    _r(r"\bjsonwebtoken::(?:encode|decode|Header|EncodingKey|DecodingKey|Validation)|\bAlgorithm::(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|PS256|PS384|PS512|EdDSA)\b", _S, "jsonwebtoken", algo_from_group=1,
       algo_map={"hs256": "HS256", "hs384": "HS384", "hs512": "HS512", "rs256": "RS256", "rs384": "RS384", "rs512": "RS512", "es256": "ES256", "es384": "ES384", "ps256": "PS256", "ps384": "PS384", "ps512": "PS512", "eddsa": "EdDSA"}),
    _r(r"\bjsonwebtoken::(?:encode|decode|Header|EncodingKey|DecodingKey|Validation)\b|\bjwt_simple::|\bbiscuit::|\bjwt::", _S, "jsonwebtoken", algorithm="JWT"),
    # ------------------------------------------------------------ randomness
    _r(r"\brand::rngs::OsRng\b|\bOsRng\b|\bgetrandom::|\brand_core::OsRng\b|\brand::thread_rng\(\)|\bthread_rng\(\)|\bStdRng::from_entropy\b|\brand::random::<", _RNG, "rand", algorithm="CSPRNG", confidence="MEDIUM"),
    _r(r"\bStdRng::seed_from_u64\b|\bSmallRng::|\bXorShiftRng\b|\bPcg\d+\b|\brand::rngs::mock::StepRng\b", _RNG, "rand", algorithm="PRNG", confidence="MEDIUM", confidence_reason="deterministic/insecure RNG; not for key material"),
]

_ALL_RULES = [(re.compile(p.pattern, p.flags | re.M), s) for p, s in _RULES]


def parse_rust_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return run_rules(
        file_path=file_path,
        repo_root=repo_root,
        text=raw,
        rules=_ALL_RULES,
        language="RUST",
        scanner_id=SCANNER_ID,
        confidence_reason="rust-crypto-crate",
        strip_comments=True,
    )
