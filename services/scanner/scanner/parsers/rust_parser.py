"""Rust crypto detector (ring, rust-crypto, aes, rsa, md-5, sha1)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-rust-scanner-v1.0"

_RULES = [
    (re.compile(r"\bMd5::|\bmd5::"), "MD5", "MESSAGE_DIGEST", "HASHING", "md-5"),
    (re.compile(r"\bSha1::|\bsha1::"), "SHA-1", "MESSAGE_DIGEST", "HASHING", "sha1"),
    (re.compile(r"\bSha256::|\bsha2::Sha256"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "sha2"),
    (re.compile(r"\bAes256Gcm\b|\baes_gcm::"), "AES", "CIPHER_INSTANCE", "ENCRYPTION", "aes-gcm"),
    (re.compile(r"\bAes256\b|\bAes128\b|\baes::"), "AES", "CIPHER_INSTANCE", "ENCRYPTION", "aes"),
    (re.compile(r"\bDes\b|\bTdesEde3\b|\bdes::"), "DES", "CIPHER_INSTANCE", "ENCRYPTION", "des"),
    (re.compile(r"\bRc4\b|\brc4::"), "RC4", "CIPHER_INSTANCE", "ENCRYPTION", "rc4"),
    (re.compile(r"\bRsaPrivateKey\b|\brsa::"), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "rsa"),
    (re.compile(r"\bring::aead::|ring::signature::"), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "ring"),
    (re.compile(r"\bChaCha20Poly1305\b"), "ChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "chacha20poly1305"),
    (re.compile(r"\bargon2::|\bArgon2\b"), "ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "argon2"),
    (re.compile(r"\bbcrypt::"), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt"),
    (re.compile(r"\bHmac::<|\bhmac::"), "HMAC", "MAC", "MAC_GENERATION", "hmac"),
    (re.compile(r"\bHkdf::<|\bhkdf::"), "HKDF", "KEY_GENERATOR", "KEY_GENERATION", "hkdf"),
    (re.compile(r"\bEd25519|ed25519_dalek"), "Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "ed25519"),
    (re.compile(r"\bx25519_dalek|\bX25519"), "X25519", "KEY_AGREEMENT", "KEY_EXCHANGE", "x25519"),
    (re.compile(r"\bpbkdf2::"), "PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "pbkdf2"),
]


def parse_rust_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []
    seen: set[tuple[int, str]] = set()
    for pattern, algo, api_type, purpose, library in _RULES:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            key = (line, algo)
            if key in seen:
                continue
            seen.add(key)
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
                    mode="GCM" if "Gcm" in match.group(0) or "gcm" in match.group(0) else None,
                    confidence="HIGH",
                    confidence_reason="rust-crypto-crate",
                    raw_transformation=match.group(0)[:80],
                )
            )
    return findings
