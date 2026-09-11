"""Rust crypto detector (ring, rustls, openssl, aes, rsa, md-5, sha2)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-rust-scanner-v1.0"

_RULES = [
    (re.compile(r"\bMd5::|\bmd5::"), "MD5", "MESSAGE_DIGEST", "HASHING", "md-5", None),
    (re.compile(r"\bSha1::|\bsha1::"), "SHA-1", "MESSAGE_DIGEST", "HASHING", "sha1", None),
    (re.compile(r"\bSha256::|\bsha2::Sha256"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "sha2", None),
    (re.compile(r"\bSha384::|\bsha2::Sha384"), "SHA-384", "MESSAGE_DIGEST", "HASHING", "sha2", None),
    (re.compile(r"\bSha512::|\bsha2::Sha512"), "SHA-512", "MESSAGE_DIGEST", "HASHING", "sha2", None),
    (re.compile(r"\bSha3_256::|\bsha3::Sha3_256"), "SHA3-256", "MESSAGE_DIGEST", "HASHING", "sha3", None),
    (re.compile(r"\bBlake2b(?:512|256)?::|\bblake2::"), "BLAKE2b", "MESSAGE_DIGEST", "HASHING", "blake2", None),
    (re.compile(r"\bAes256Gcm\b|\baes_gcm::Aes256Gcm"), "AES", "CIPHER_INSTANCE", "ENCRYPTION", "aes-gcm", "GCM"),
    (re.compile(r"\bAes128Gcm\b|\baes_gcm::Aes128Gcm"), "AES", "CIPHER_INSTANCE", "ENCRYPTION", "aes-gcm", "GCM"),
    (re.compile(r"\bAes256\b|\bAes128\b|\baes::"), "AES", "CIPHER_INSTANCE", "ENCRYPTION", "aes", None),
    (re.compile(r"\bDes\b|\bTdesEde3\b|\bdes::"), "DES", "CIPHER_INSTANCE", "ENCRYPTION", "des", None),
    (re.compile(r"\bRc4\b|\brc4::"), "RC4", "CIPHER_INSTANCE", "ENCRYPTION", "rc4", None),
    (re.compile(r"\bRsaPrivateKey\b|\brsa::Rsa|rsa::pkcs1v15"), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "rsa", None),
    (re.compile(r"\bring::aead::"), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "ring", None),
    (re.compile(r"\bring::digest::SHA1\b"), "SHA-1", "MESSAGE_DIGEST", "HASHING", "ring", None),
    (re.compile(r"\bring::digest::SHA256\b"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "ring", None),
    (re.compile(r"\bring::digest::SHA512\b"), "SHA-512", "MESSAGE_DIGEST", "HASHING", "ring", None),
    (re.compile(r"\bring::signature::"), "UNKNOWN", "SIGNATURE", "SIGNING", "ring", None),
    (re.compile(r"\bChaCha20Poly1305\b"), "ChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "chacha20poly1305", None),
    (re.compile(r"\bXChaCha20Poly1305\b"), "XChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "chacha20poly1305", None),
    (re.compile(r"\bargon2::|\bArgon2\b"), "ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2", None),
    (re.compile(r"\bbcrypt::"), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt", None),
    (re.compile(r"\bHmac::<|\bhmac::"), "HMAC", "MAC", "MAC_GENERATION", "hmac", None),
    (re.compile(r"\bHkdf::<|\bhkdf::"), "HKDF", "KEY_GENERATOR", "KEY_GENERATION", "hkdf", None),
    (re.compile(r"\bEd25519|ed25519_dalek"), "Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "ed25519", None),
    (re.compile(r"\bx25519_dalek|\bX25519"), "X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "x25519", None),
    (re.compile(r"\bpbkdf2::"), "PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "pbkdf2", None),
    (re.compile(r"\bscrypt::"), "SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "scrypt", None),
    (re.compile(r"\brustls::(ServerConfig|ClientConfig|RootCertStore)"), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "rustls", None),
    (re.compile(r"\bopenssl::ssl::(SslContext|SslAcceptor|SslConnector)"), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "openssl", None),
    (re.compile(r"\bopenssl::symm::(encrypt|decrypt|Cipher)"), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "openssl", None),
    (re.compile(r"\bopenssl::hash::(hash|Hasher|MessageDigest)"), "UNKNOWN", "MESSAGE_DIGEST", "HASHING", "openssl", None),
    (re.compile(r"\bopenssl::sha::sha1\b"), "SHA-1", "MESSAGE_DIGEST", "HASHING", "openssl", None),
    (re.compile(r"\bopenssl::sha::md5\b"), "MD5", "MESSAGE_DIGEST", "HASHING", "openssl", None),
    (re.compile(r"\bopenssl::sha::sha256\b"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "openssl", None),
    (re.compile(r"\bopenssl::rsa::Rsa"), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl", None),
    (re.compile(r"\borion::hazardous::aead"), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "orion", None),
    (re.compile(r"\bsodiumoxide::crypto::"), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "sodiumoxide", None),
    (re.compile(r"\brand::rngs::OsRng|\bgetrandom::"), "CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "getrandom", None),
]
_RSA_BITS = re.compile(r"RsaPrivateKey::new\([^,]+,\s*(\d+)|Rsa::generate\(\s*(\d+)")


def parse_rust_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_c_like_comments

    text = strip_c_like_comments(raw)
    findings: list[RawFinding] = []
    seen: set[tuple[int, str]] = set()
    for pattern, algo, api_type, purpose, library, mode in _RULES:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            key = (line, algo)
            if key in seen:
                continue
            seen.add(key)
            resolved_mode = mode
            if resolved_mode is None and ("Gcm" in match.group(0) or "gcm" in match.group(0)):
                resolved_mode = "GCM"
            findings.append(
                make_finding(
                    file_path=file_path,
                    repo_root=repo_root,
                    line_number=line,
                    language="RUST",
                    scanner_id=SCANNER_ID,
                    api_type=api_type,
                    algorithm=algo,
                    purpose=purpose,
                    library=library,
                    mode=resolved_mode,
                    confidence="HIGH",
                    confidence_reason="rust-crypto-crate",
                    raw_transformation=match.group(0)[:80],
                )
            )
    for match in _RSA_BITS.finditer(text):
        line = text[: match.start()].count("\n") + 1
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language="RUST",
                scanner_id=SCANNER_ID,
                api_type="KEY_PAIR_GENERATOR",
                algorithm="RSA",
                purpose="KEY_GENERATION",
                library="rsa",
                key_size=int(next(g for g in match.groups() if g)),
                confidence="HIGH",
                confidence_reason="rust-rsa-bits",
                raw_transformation=match.group(0)[:80],
            )
        )
    return findings
