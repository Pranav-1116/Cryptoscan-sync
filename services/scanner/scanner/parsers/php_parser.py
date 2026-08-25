"""PHP crypto detector (openssl, hash, mcrypt, password_hash)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-php-scanner-v1.0"

_OPENSSL = re.compile(
    r"openssl_encrypt\s*\(\s*[^,]+,\s*['\"]([A-Za-z0-9_-]+)['\"]",
    re.IGNORECASE,
)
_HASH = re.compile(r"\bhash\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_SIMPLE = [
    (re.compile(r"\bmd5\s*\("), "MD5", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bsha1\s*\("), "SHA-1", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bcrc32\s*\("), "CRC32", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bmcrypt_", re.IGNORECASE), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "mcrypt"),
    (re.compile(r"\bpassword_hash\s*\("), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "password_hash"),
    (re.compile(r"\bopenssl_pkey_new\s*\("), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"\bopenssl_sign\s*\("), "RSA", "SIGNATURE", "SIGNING", "openssl"),
    (re.compile(r"\bopenssl_decrypt\s*\("), "UNKNOWN", "CIPHER_INSTANCE", "DECRYPTION", "openssl"),
    (re.compile(r"\bsodium_crypto_secretbox"), "XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_box"), "X25519", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_pwhash"), "ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "libsodium"),
    (re.compile(r"\bhash_hmac\s*\("), "HMAC", "MAC", "MAC_GENERATION", "php-hash"),
]


def _split_openssl(name: str) -> tuple[str, str | None]:
    upper = name.upper().replace("_", "-")
    mode = None
    for token in ("GCM", "CCM", "CTR", "CBC", "ECB", "CFB", "OFB"):
        if token in upper:
            mode = token
            break
    if "AES" in upper:
        return "AES", mode
    if "DES-EDE" in upper or "DES3" in upper or "3DES" in upper:
        return "3DES", mode
    if upper.startswith("DES") or "-DES" in upper:
        return "DES", mode
    if "RC4" in upper:
        return "RC4", mode
    if "CHACHA" in upper:
        return "ChaCha20", mode
    return upper, mode


def parse_php_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []

    def add(line: int, **kwargs) -> None:
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language="PHP",
                scanner_id=SCANNER_ID,
                confidence="HIGH",
                confidence_reason="php-crypto-api",
                **kwargs,
            )
        )

    for match in _OPENSSL.finditer(text):
        algo, mode = _split_openssl(match.group(1))
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            purpose="ENCRYPTION",
            library="openssl",
            raw_transformation=match.group(1),
        )
    for match in _HASH.finditer(text):
        raw = match.group(1).upper().replace("_", "-")
        mapped = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512"}.get(raw, raw)
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MESSAGE_DIGEST",
            algorithm=mapped,
            purpose="HASHING",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for pattern, algo, api_type, purpose, library in _SIMPLE:
        for match in pattern.finditer(text):
            add(
                text[: match.start()].count("\n") + 1,
                api_type=api_type,
                algorithm=algo,
                purpose=purpose,
                library=library,
            )
    return findings
