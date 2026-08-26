"""Ruby OpenSSL / Digest / ActiveSupport crypto detector."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-ruby-scanner-v1.0"

_RULES = [
    (re.compile(r"Digest::MD5"), "MD5", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA1"), "SHA-1", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA256|Digest::SHA2\.new\(\s*256"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA384|Digest::SHA2\.new\(\s*384"), "SHA-384", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA512|Digest::SHA2\.new\(\s*512"), "SHA-512", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"OpenSSL::Digest(?:::SHA256|::SHA1|::MD5)?"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "openssl"),
    (re.compile(r"OpenSSL::HMAC"), "HMAC", "MAC", "MAC_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::KDF\.pbkdf2_hmac"), "PBKDF2", "KEY_GENERATOR", "PASSWORD_HASHING", "openssl"),
    (re.compile(r"OpenSSL::KDF\.scrypt"), "SCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "openssl"),
    (re.compile(r"OpenSSL::KDF\.hkdf"), "HKDF", "KEY_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::PKey::RSA"), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::PKey::EC"), "ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::PKey::DSA"), "DSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::PKey::ED25519|OpenSSL::PKey::Ed25519"), "Ed25519", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::SSL::SSLContext|OpenSSL::SSL::SSLSocket"), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "openssl"),
    (re.compile(r"OpenSSL::Random\.(random_bytes|pseudo_bytes)"), "CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"BCrypt::Password"), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt"),
    (re.compile(r"ActiveSupport::MessageEncryptor"), "AES", "CIPHER_INSTANCE", "ENCRYPTION", "activesupport"),
    (re.compile(r"ActiveSupport::KeyGenerator|ActiveSupport::CachingKeyGenerator"), "PBKDF2", "KEY_GENERATOR", "KEY_GENERATION", "activesupport"),
    (re.compile(r"Devise::Encryptor|Devise::Encryptable"), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "devise"),
    (re.compile(r"RbNaCl::SecretBox|RbNaCl::SimpleBox"), "XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "rbnacl"),
    (re.compile(r"RbNaCl::Signatures::Ed25519"), "Ed25519", "SIGNATURE", "SIGNING", "rbnacl"),
]
_CIPHER = re.compile(r"OpenSSL::Cipher(?:::AES(?:128|192|256))?(?:\.new)?\(\s*['\"]([^'\"]+)['\"]")
_CIPHER_CONST = re.compile(r"OpenSSL::Cipher::AES(?:128|192|256)\.(encrypt|decrypt|new)")
_RSA_BITS = re.compile(r"OpenSSL::PKey::RSA\.new\(\s*(\d+)")


def parse_ruby_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_ruby_comments

    text = strip_ruby_comments(raw)
    findings: list[RawFinding] = []
    seen: set[tuple[int, str]] = set()

    def add(line: int, **kwargs) -> None:
        key = (line, str(kwargs.get("algorithm")))
        if key in seen:
            return
        seen.add(key)
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language="RUBY",
                scanner_id=SCANNER_ID,
                confidence="HIGH",
                confidence_reason="ruby-openssl",
                **kwargs,
            )
        )

    for match in _CIPHER.finditer(text):
        raw = match.group(1).upper()
        algo = (
            "AES"
            if "AES" in raw
            else (
                "3DES"
                if "DES-EDE" in raw or "3DES" in raw
                else ("DES" if "DES" in raw else ("RC4" if "RC4" in raw else ("Blowfish" if "BF" in raw or "BLOWFISH" in raw else raw)))
            )
        )
        mode = next((m for m in ("GCM", "CCM", "CTR", "CBC", "ECB", "CFB", "OFB") if m in raw), None)
        bits = None
        found = re.search(r"(\d{3,4})", raw)
        if found:
            bits = int(found.group(1))
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=bits,
            purpose="ENCRYPTION",
            library="openssl",
            raw_transformation=match.group(1),
        )
    for match in _CIPHER_CONST.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm="AES",
            purpose="ENCRYPTION" if match.group(1) != "decrypt" else "DECRYPTION",
            library="openssl",
        )
    for match in _RSA_BITS.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_PAIR_GENERATOR",
            algorithm="RSA",
            purpose="KEY_GENERATION",
            library="openssl",
            key_size=int(match.group(1)),
        )
    for pattern, algo, api_type, purpose, library in _RULES:
        for match in pattern.finditer(text):
            add(
                text[: match.start()].count("\n") + 1,
                api_type=api_type,
                algorithm=algo,
                purpose=purpose,
                library=library,
            )
    return findings
