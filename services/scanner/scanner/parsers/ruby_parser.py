"""Ruby OpenSSL / Digest crypto detector."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-ruby-scanner-v1.0"

_RULES = [
    (re.compile(r"Digest::MD5"), "MD5", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA1"), "SHA-1", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA256"), "SHA-256", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"Digest::SHA512"), "SHA-512", "MESSAGE_DIGEST", "HASHING", "digest"),
    (re.compile(r"OpenSSL::HMAC"), "HMAC", "MAC", "MAC_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::PKey::RSA"), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::PKey::EC"), "ECDSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"OpenSSL::SSL::SSLContext|OpenSSL::SSL::SSLSocket"), "TLS", "KEY_AGREEMENT", "NETWORK_ENCRYPTION", "openssl"),
    (re.compile(r"BCrypt::Password"), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "bcrypt"),
]
_CIPHER = re.compile(r"OpenSSL::Cipher(?:\.new)?\(\s*['\"]([^'\"]+)['\"]")


def parse_ruby_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
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
                language="RUBY",
                scanner_id=SCANNER_ID,
                confidence="HIGH",
                confidence_reason="ruby-openssl",
                **kwargs,
            )
        )

    for match in _CIPHER.finditer(text):
        raw = match.group(1).upper()
        algo = "AES" if "AES" in raw else ("3DES" if "DES-EDE" in raw or "3DES" in raw else ("DES" if "DES" in raw else ("RC4" if "RC4" in raw else raw)))
        mode = next((m for m in ("GCM", "CCM", "CTR", "CBC", "ECB") if m in raw), None)
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            purpose="ENCRYPTION",
            library="openssl",
            raw_transformation=match.group(1),
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
