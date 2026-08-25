"""PHP crypto detector (openssl, hash, mcrypt, password_hash, libsodium)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-php-scanner-v1.0"

_OPENSSL = re.compile(
    r"openssl_(?:encrypt|decrypt)\s*\(\s*[^,]+,\s*['\"]([A-Za-z0-9_-]+)['\"]",
    re.IGNORECASE,
)
_HASH = re.compile(r"\bhash\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_HASH_HMAC = re.compile(r"\bhash_hmac\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_HASH_PBKDF2 = re.compile(r"\bhash_pbkdf2\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_OPENSSL_DIGEST = re.compile(r"\bopenssl_digest\s*\(\s*[^,]+,\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_OPENSSL_PKEY = re.compile(
    r"openssl_pkey_new\s*\(\s*(?:\[[^\]]*['\"]private_key_bits['\"]\s*=>\s*(\d+))?",
    re.IGNORECASE | re.DOTALL,
)
_MCRYPT = re.compile(r"\bmcrypt_encrypt\s*\(\s*['\"]?([A-Za-z0-9_-]+)", re.IGNORECASE)
_PASSWORD = re.compile(r"\bpassword_hash\s*\(\s*[^,]+,\s*(PASSWORD_[A-Z0-9_]+)", re.IGNORECASE)
_SIMPLE = [
    (re.compile(r"\bmd5\s*\("), "MD5", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bsha1\s*\("), "SHA-1", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bcrc32\s*\("), "CRC32", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bmcrypt_", re.IGNORECASE), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "mcrypt"),
    (re.compile(r"\bpassword_hash\s*\("), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "password_hash"),
    (re.compile(r"\bopenssl_pkey_new\s*\("), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"\bopenssl_sign\s*\("), "RSA", "SIGNATURE", "SIGNING", "openssl"),
    (re.compile(r"\bopenssl_verify\s*\("), "RSA", "SIGNATURE", "VERIFICATION", "openssl"),
    (re.compile(r"\bopenssl_random_pseudo_bytes\s*\("), "CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"\brandom_bytes\s*\("), "CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "php-random"),
    (re.compile(r"\bsodium_crypto_secretbox"), "XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_aead_xchacha20poly1305"), "XChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_aead_chacha20poly1305"), "ChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_box"), "X25519", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_sign"), "Ed25519", "SIGNATURE", "SIGNING", "libsodium"),
    (re.compile(r"\bsodium_crypto_pwhash"), "ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "libsodium"),
    (re.compile(r"\bsodium_crypto_generichash"), "BLAKE2b", "MESSAGE_DIGEST", "HASHING", "libsodium"),
    (re.compile(r"\bhash_hmac\s*\("), "HMAC", "MAC", "MAC_GENERATION", "php-hash"),
    (re.compile(r"\bcrypt\s*\("), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "php-crypt"),
]


def _split_openssl(name: str) -> tuple[str, str | None, int | None]:
    upper = name.upper().replace("_", "-")
    mode = None
    for token in ("GCM", "CCM", "CTR", "CBC", "ECB", "CFB", "OFB"):
        if token in upper:
            mode = token
            break
    key_size = None
    bits = re.search(r"(\d{3,4})", upper)
    if bits:
        key_size = int(bits.group(1))
    if "AES" in upper:
        return "AES", mode, key_size
    if "DES-EDE" in upper or "DES3" in upper or "3DES" in upper:
        return "3DES", mode, key_size
    if upper.startswith("DES") or "-DES" in upper:
        return "DES", mode, key_size
    if "RC4" in upper:
        return "RC4", mode, key_size
    if "CHACHA" in upper:
        return "ChaCha20", mode, key_size
    if "BF" in upper or "BLOWFISH" in upper:
        return "Blowfish", mode, key_size
    if "CAMELLIA" in upper:
        return "Camellia", mode, key_size
    return upper, mode, key_size


def _map_hash(raw: str) -> str:
    key = raw.upper().replace("_", "-")
    return {
        "SHA1": "SHA-1",
        "SHA256": "SHA-256",
        "SHA384": "SHA-384",
        "SHA512": "SHA-512",
        "SHA3-256": "SHA3-256",
        "WHIRLPOOL": "WHIRLPOOL",
        "RIPEMD160": "RIPEMD-160",
    }.get(key, key)


def parse_php_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []
    claimed: set[tuple[int, str]] = set()

    def add(line: int, **kwargs) -> None:
        key = (line, str(kwargs.get("algorithm")))
        if key in claimed:
            return
        claimed.add(key)
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language="PHP",
                scanner_id=SCANNER_ID,
                confidence=kwargs.pop("confidence", "HIGH"),
                confidence_reason=kwargs.pop("confidence_reason", "php-crypto-api"),
                **kwargs,
            )
        )

    for match in _OPENSSL.finditer(text):
        algo, mode, key_size = _split_openssl(match.group(1))
        purpose = "DECRYPTION" if "decrypt" in match.group(0).lower() else "ENCRYPTION"
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=key_size,
            purpose=purpose,
            library="openssl",
            raw_transformation=match.group(1),
        )
    for match in _HASH.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MESSAGE_DIGEST",
            algorithm=_map_hash(match.group(1)),
            purpose="HASHING",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for match in _HASH_HMAC.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MAC",
            algorithm=f"HMAC-{_map_hash(match.group(1))}",
            purpose="MAC_GENERATION",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for match in _HASH_PBKDF2.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_GENERATOR",
            algorithm="PBKDF2",
            purpose="PASSWORD_HASHING",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for match in _OPENSSL_DIGEST.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MESSAGE_DIGEST",
            algorithm=_map_hash(match.group(1)),
            purpose="HASHING",
            library="openssl",
        )
    for match in _OPENSSL_PKEY.finditer(text):
        bits = None
        if match.lastindex and match.group(1):
            try:
                bits = int(match.group(1))
            except ValueError:
                bits = None
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_PAIR_GENERATOR",
            algorithm="RSA",
            purpose="KEY_GENERATION",
            library="openssl",
            key_size=bits,
        )
    for match in _MCRYPT.finditer(text):
        algo, mode, _ = _split_openssl(match.group(1))
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            purpose="ENCRYPTION",
            library="mcrypt",
        )
    for match in _PASSWORD.finditer(text):
        algo = "ARGON2" if "ARGON" in match.group(1).upper() else "BCRYPT"
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_GENERATOR",
            algorithm=algo,
            purpose="PASSWORD_HASHING",
            library="password_hash",
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
