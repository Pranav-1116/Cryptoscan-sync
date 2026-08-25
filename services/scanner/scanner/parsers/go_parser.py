"""Go crypto detector (stdlib crypto/*, x/crypto). Regex fallback, no extra parser deps."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-go-scanner-v1.0"

_RULES: list[tuple[re.Pattern[str], dict]] = [
    (re.compile(r"\bmd5\.(Sum|New|SumHex)\b"), {"algorithm": "MD5", "api_type": "MESSAGE_DIGEST", "purpose": "HASHING", "library": "crypto/md5"}),
    (re.compile(r"\bsha1\.(Sum|New)\b"), {"algorithm": "SHA-1", "api_type": "MESSAGE_DIGEST", "purpose": "HASHING", "library": "crypto/sha1"}),
    (re.compile(r"\bsha256\.(Sum|New)\b"), {"algorithm": "SHA-256", "api_type": "MESSAGE_DIGEST", "purpose": "HASHING", "library": "crypto/sha256"}),
    (re.compile(r"\bsha512\.(Sum|New)\b"), {"algorithm": "SHA-512", "api_type": "MESSAGE_DIGEST", "purpose": "HASHING", "library": "crypto/sha512"}),
    (re.compile(r"\baes\.NewGCM\b"), {"algorithm": "AES", "mode": "GCM", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "crypto/aes"}),
    (re.compile(r"\baes\.NewCipher\b"), {"algorithm": "AES", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "crypto/aes"}),
    (re.compile(r"\bdes\.NewTripleDESCipher\b"), {"algorithm": "3DES", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "crypto/des"}),
    (re.compile(r"\bdes\.NewCipher\b"), {"algorithm": "DES", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "crypto/des"}),
    (re.compile(r"\brc4\.NewCipher\b"), {"algorithm": "RC4", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "crypto/rc4"}),
    (re.compile(r"\bhmac\.New\b"), {"algorithm": "HMAC", "api_type": "MAC", "purpose": "MAC_GENERATION", "library": "crypto/hmac"}),
    (re.compile(r"\brsa\.GenerateKey\([^,]+,\s*(\d+)"), {"algorithm": "RSA", "api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION", "library": "crypto/rsa", "key_from_group": 1}),
    (re.compile(r"\brsa\.(EncryptPKCS1v15|EncryptOAEP|SignPKCS1v15|SignPSS|GenerateMultiPrimeKey)\b"), {"algorithm": "RSA", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "crypto/rsa"}),
    (re.compile(r"\becdsa\.GenerateKey\b"), {"algorithm": "ECDSA", "api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION", "library": "crypto/ecdsa"}),
    (re.compile(r"\bed25519\.GenerateKey\b"), {"algorithm": "Ed25519", "api_type": "KEY_PAIR_GENERATOR", "purpose": "KEY_GENERATION", "library": "crypto/ed25519"}),
    (re.compile(r"\bcurve25519\.(X25519|ScalarMult)\b"), {"algorithm": "X25519", "api_type": "KEY_AGREEMENT", "purpose": "KEY_EXCHANGE", "library": "crypto/ecdh"}),
    (re.compile(r"\bpbkdf2\.Key\b"), {"algorithm": "PBKDF2", "api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING", "library": "golang.org/x/crypto/pbkdf2"}),
    (re.compile(r"\bscrypt\.Key\b"), {"algorithm": "SCRYPT", "api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING", "library": "golang.org/x/crypto/scrypt"}),
    (re.compile(r"\bhkdf\.New\b"), {"algorithm": "HKDF", "api_type": "KEY_GENERATOR", "purpose": "KEY_GENERATION", "library": "golang.org/x/crypto/hkdf"}),
    (re.compile(r"\btls\.VersionSSL30\b"), {"algorithm": "SSLv3", "api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION", "library": "crypto/tls"}),
    (re.compile(r"\btls\.VersionTLS10\b"), {"algorithm": "TLS1.0", "api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION", "library": "crypto/tls"}),
    (re.compile(r"\btls\.VersionTLS11\b"), {"algorithm": "TLS1.1", "api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION", "library": "crypto/tls"}),
    (re.compile(r"\btls\.(Listen|Dial|Server|Client|Config)\b"), {"algorithm": "TLS", "api_type": "KEY_AGREEMENT", "purpose": "NETWORK_ENCRYPTION", "library": "crypto/tls", "confidence": "MEDIUM"}),
    (re.compile(r"\bbcrypt\.(GenerateFromPassword|CompareHashAndPassword)\b"), {"algorithm": "BCRYPT", "api_type": "KEY_GENERATOR", "purpose": "PASSWORD_HASHING", "library": "golang.org/x/crypto/bcrypt"}),
    (re.compile(r"\bchacha20poly1305\.New\b"), {"algorithm": "ChaCha20-Poly1305", "api_type": "CIPHER_INSTANCE", "purpose": "ENCRYPTION", "library": "golang.org/x/crypto"}),
]


def parse_go_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []
    seen: set[tuple[int, str]] = set()
    for pattern, spec in _RULES:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            key = (line, spec["algorithm"])
            if key in seen:
                continue
            seen.add(key)
            key_size = None
            if spec.get("key_from_group"):
                try:
                    key_size = int(match.group(spec["key_from_group"]))
                except (IndexError, TypeError, ValueError):
                    key_size = None
            findings.append(
                make_finding(
                    file_path=file_path,
                    repo_root=repo_root,
                    line_number=line,
                    language="GO",
                    scanner_id=SCANNER_ID,
                    api_type=spec["api_type"],
                    algorithm=spec["algorithm"],
                    purpose=spec["purpose"],
                    library=spec["library"],
                    mode=spec.get("mode"),
                    key_size=key_size,
                    confidence=spec.get("confidence", "HIGH"),
                    confidence_reason="go-stdlib-or-xcrypto",
                    raw_transformation=match.group(0)[:80],
                )
            )
    return findings
