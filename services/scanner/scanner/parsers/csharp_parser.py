"""C# cryptographic API parser (regex, no Roslyn required)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-csharp-scanner-v1.0"

PATTERNS = [
    (re.compile(r"\bAes(?:Gcm|Cng|Managed)?\.Create\s*\("), "CIPHER_INSTANCE", "AES", "ENCRYPTION", None, None),
    (re.compile(r"\bnew\s+AesGcm\s*\("), "CIPHER_INSTANCE", "AES", "ENCRYPTION", "GCM", None),
    (re.compile(r"\bDES(?:CryptoServiceProvider)?\.Create\s*\("), "CIPHER_INSTANCE", "DES", "ENCRYPTION", None, None),
    (re.compile(r"\bTripleDES(?:CryptoServiceProvider)?\.Create\s*\("), "CIPHER_INSTANCE", "3DES", "ENCRYPTION", None, None),
    (re.compile(r"\bRC2(?:CryptoServiceProvider)?\.Create\s*\("), "CIPHER_INSTANCE", "RC2", "ENCRYPTION", None, None),
    (re.compile(r"\bMD5(?:CryptoServiceProvider)?\.Create\s*\("), "MESSAGE_DIGEST", "MD5", "HASHING", None, None),
    (re.compile(r"\bSHA1(?:CryptoServiceProvider|Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-1", "HASHING", None, None),
    (re.compile(r"\bSHA256(?:CryptoServiceProvider|Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-256", "HASHING", None, None),
    (re.compile(r"\bSHA384(?:Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-384", "HASHING", None, None),
    (re.compile(r"\bSHA512(?:Managed)?\.Create\s*\("), "MESSAGE_DIGEST", "SHA-512", "HASHING", None, None),
    (re.compile(r"\bHMACSHA256\.Create\s*\("), "MAC", "HMAC-SHA256", "MAC_GENERATION", None, None),
    (re.compile(r"\bHMACSHA1\.Create\s*\("), "MAC", "HMAC-SHA1", "MAC_GENERATION", None, None),
    (re.compile(r"\bHMACSHA384\.Create\s*\("), "MAC", "HMAC-SHA384", "MAC_GENERATION", None, None),
    (re.compile(r"\bHMACSHA512\.Create\s*\("), "MAC", "HMAC-SHA512", "MAC_GENERATION", None, None),
    (re.compile(r"\bnew\s+HMACSHA256\s*\("), "MAC", "HMAC-SHA256", "MAC_GENERATION", None, None),
    (re.compile(r"\bnew\s+HMACSHA1\s*\("), "MAC", "HMAC-SHA1", "MAC_GENERATION", None, None),
    (re.compile(r"\bRSA\.Create\s*\(\s*(\d+)\s*\)"), "KEY_PAIR_GENERATOR", "RSA", "KEY_GENERATION", None, "group1"),
    (re.compile(r"\bRSA\.Create\s*\("), "KEY_PAIR_GENERATOR", "RSA", "KEY_GENERATION", None, None),
    (re.compile(r"\bECDsa\.Create\s*\("), "KEY_PAIR_GENERATOR", "ECDSA", "KEY_GENERATION", None, None),
    (re.compile(r"\bnew\s+Rfc2898DeriveBytes\s*\("), "KEY_GENERATOR", "PBKDF2", "PASSWORD_HASHING", None, None),
    (re.compile(r"\bRandomNumberGenerator\.Create\s*\("), "KEY_GENERATOR", "CSPRNG", "KEY_GENERATION", None, None),
    (re.compile(r"\bnew\s+RNGCryptoServiceProvider\s*\("), "KEY_GENERATOR", "CSPRNG", "KEY_GENERATION", None, None),
]

CIPHERMODE = re.compile(r"CipherMode\.(ECB|CBC|CFB|OFB|CTS)", re.IGNORECASE)
HARDCODED = re.compile(
    r"""(?:Key|IV)\s*=\s*new\s+byte\s*\[\s*\]\s*\{([^}]+)\}""",
    re.IGNORECASE,
)
BCRYPT = re.compile(r"BCrypt\.Net\.BCrypt\.(HashPassword|Verify)\s*\(", re.IGNORECASE)
IDENTITY = re.compile(r"PasswordHasher<\w+>", re.IGNORECASE)
NSEC_AEAD = re.compile(
    r"\b(?:NSec\.Cryptography\.)?(AeadAlgorithm\.(ChaCha20Poly1305|Aes256Gcm|XChaCha20Poly1305)|Aes256Gcm|ChaCha20Poly1305|XChaCha20Poly1305)\b"
)
NSEC_HASH = re.compile(
    r"\b(?:NSec\.Cryptography\.)?(Blake2b|Sha256|Sha512|Sha512256|HmacSha256|HmacSha512|Ed25519|X25519)\b"
)


def parse_csharp_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []

    def add(match: re.Match, **kwargs) -> None:
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=source[: match.start()].count("\n") + 1,
                language="CSHARP",
                scanner_id=SCANNER_ID,
                library="System.Security.Cryptography",
                **kwargs,
            )
        )

    claimed: set[int] = set()
    for pattern, api_type, algorithm, purpose, mode, key_flag in PATTERNS:
        for match in pattern.finditer(source):
            if match.start() in claimed:
                continue
            key_size = None
            if key_flag == "group1" and match.lastindex:
                try:
                    key_size = int(match.group(1))
                except (TypeError, ValueError):
                    key_size = None
            claimed.add(match.start())
            add(
                match,
                api_type=api_type,
                algorithm=algorithm,
                purpose=purpose,
                mode=mode,
                key_size=key_size,
            )
    for match in CIPHERMODE.finditer(source):
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm="AES",
            purpose="ENCRYPTION",
            mode=match.group(1).upper(),
            confidence="MEDIUM",
            confidence_reason="CipherMode assignment",
        )
    for match in HARDCODED.finditer(source):
        raw = match.group(1)
        length = len([part for part in raw.split(",") if part.strip()])
        add(
            match,
            api_type="HARDCODED_KEY",
            algorithm="UNKNOWN",
            purpose="KEY_GENERATION",
            is_hardcoded_key=True,
            hardcoded_key_length=length,
            confidence="HIGH",
            confidence_reason="byte-array Key/IV initializer",
        )
    for match in BCRYPT.finditer(source):
        add(
            match,
            api_type="KEY_GENERATOR",
            algorithm="BCRYPT",
            purpose="PASSWORD_HASHING",
        )
        findings[-1].metadata.library = "BCrypt.Net"
    for match in IDENTITY.finditer(source):
        add(
            match,
            api_type="KEY_GENERATOR",
            algorithm="PBKDF2",
            purpose="PASSWORD_HASHING",
            confidence="MEDIUM",
            confidence_reason="ASP.NET Identity password hasher",
        )
        findings[-1].metadata.library = "ASP.NET Identity"
    for match in NSEC_AEAD.finditer(source):
        token = match.group(0)
        algorithm = "AES"
        mode = "GCM"
        if "ChaCha20" in token:
            algorithm = "ChaCha20-Poly1305"
            mode = None
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algorithm,
            mode=mode,
            purpose="ENCRYPTION",
        )
        findings[-1].metadata.library = "NSec"
    for match in NSEC_HASH.finditer(source):
        name = match.group(1)
        mapping = {
            "Blake2b": ("MESSAGE_DIGEST", "BLAKE2b", "HASHING"),
            "Sha256": ("MESSAGE_DIGEST", "SHA-256", "HASHING"),
            "Sha512": ("MESSAGE_DIGEST", "SHA-512", "HASHING"),
            "Sha512256": ("MESSAGE_DIGEST", "SHA-512/256", "HASHING"),
            "HmacSha256": ("MAC", "HMAC-SHA256", "MAC_GENERATION"),
            "HmacSha512": ("MAC", "HMAC-SHA512", "MAC_GENERATION"),
            "Ed25519": ("SIGNATURE", "Ed25519", "SIGNING"),
            "X25519": ("KEY_PAIR_GENERATOR", "X25519", "KEY_EXCHANGE"),
        }
        api_type, algorithm, purpose = mapping.get(name, ("MESSAGE_DIGEST", name.upper(), "HASHING"))
        add(match, api_type=api_type, algorithm=algorithm, purpose=purpose)
        findings[-1].metadata.library = "NSec"
    return findings
