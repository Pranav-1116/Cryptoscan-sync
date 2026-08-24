"""JavaScript / TypeScript cryptographic API parser (regex, no tree-sitter required)."""

from __future__ import annotations

import re
from pathlib import Path

from scanner.extractors.entropy_calculator import looks_like_secret
from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-js-scanner-v1.0"

NODE_CIPHER = re.compile(
    r"""crypto\.createCipher(?:iv)?\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_DECIPHER = re.compile(
    r"""crypto\.createDecipher(?:iv)?\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_HASH = re.compile(
    r"""crypto\.createHash\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_HMAC = re.compile(
    r"""crypto\.createHmac\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_SIGN = re.compile(
    r"""crypto\.createSign\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
NODE_PBKDF = re.compile(r"""crypto\.pbkdf2(?:Sync)?\s*\(""", re.IGNORECASE)
NODE_SCRYPT = re.compile(r"""crypto\.scrypt(?:Sync)?\s*\(""", re.IGNORECASE)
NODE_RANDOM = re.compile(r"""crypto\.randomBytes\s*\(""", re.IGNORECASE)
WEBCRYPTO = re.compile(
    r"""(?:crypto\.subtle|window\.crypto\.subtle)\.(\w+)\s*\(""",
    re.IGNORECASE,
)
JWT_SIGN = re.compile(
    r"""jwt\.sign\s*\((?:[^;]{0,200}?algorithm\s*:\s*['"]([^'"]+)['"])?""",
    re.IGNORECASE | re.DOTALL,
)
BCRYPT = re.compile(r"""bcrypt\.(?:hash|compare|genSalt)\s*\(""", re.IGNORECASE)
ARGON = re.compile(r"""argon2\.(?:hash|verify)\s*\(""", re.IGNORECASE)
SJCL = re.compile(r"""sjcl\.(?:encrypt|decrypt|codec)\b""", re.IGNORECASE)
CRYPTOJS = re.compile(
    r"""CryptoJS\.(AES|DES|TripleDES|MD5|SHA1|SHA256|SHA512|HmacSHA256)\b""",
    re.IGNORECASE,
)
SECRET_ASSIGN = re.compile(
    r"""(?:const|let|var)\s+(secret|password|apiKey|api_key|token|privateKey)\s*=\s*['"]([^'"]{12,})['"]""",
    re.IGNORECASE,
)

HASH_MAP = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3-256": "SHA3-256",
}


def parse_javascript_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []
    language = "TYPESCRIPT" if file_path.suffix.lower() in {".ts", ".tsx"} else "JAVASCRIPT"

    def add(match: re.Match, **kwargs) -> None:
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=source[: match.start()].count("\n") + 1,
                language=language,
                scanner_id=SCANNER_ID,
                **kwargs,
            )
        )

    for match in NODE_CIPHER.finditer(source):
        algo, mode, key_size = _parse_node_cipher(match.group(1))
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=key_size,
            purpose="ENCRYPTION",
            library="node-crypto",
            raw_transformation=match.group(1),
        )
    for match in NODE_DECIPHER.finditer(source):
        algo, mode, key_size = _parse_node_cipher(match.group(1))
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=key_size,
            purpose="DECRYPTION",
            library="node-crypto",
            raw_transformation=match.group(1),
        )
    for match in NODE_HASH.finditer(source):
        raw = match.group(1)
        add(
            match,
            api_type="MESSAGE_DIGEST",
            algorithm=HASH_MAP.get(raw.lower(), raw.upper()),
            purpose="HASHING",
            library="node-crypto",
        )
    for match in NODE_HMAC.finditer(source):
        raw = match.group(1)
        add(
            match,
            api_type="MAC",
            algorithm=HASH_MAP.get(raw.lower(), raw.upper()),
            purpose="MAC_GENERATION",
            library="node-crypto",
        )
    for match in NODE_SIGN.finditer(source):
        add(
            match,
            api_type="SIGNATURE",
            algorithm=match.group(1).upper(),
            purpose="SIGNING",
            library="node-crypto",
        )
    for match in NODE_PBKDF.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="PBKDF2", purpose="PASSWORD_HASHING", library="node-crypto")
    for match in NODE_SCRYPT.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="SCRYPT", purpose="PASSWORD_HASHING", library="node-crypto")
    for match in NODE_RANDOM.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="CSPRNG", purpose="KEY_GENERATION", library="node-crypto")
    for match in WEBCRYPTO.finditer(source):
        method = match.group(1)
        purpose = {
            "encrypt": "ENCRYPTION",
            "decrypt": "DECRYPTION",
            "sign": "SIGNING",
            "verify": "VERIFICATION",
            "digest": "HASHING",
            "generateKey": "KEY_GENERATION",
            "deriveBits": "KEY_EXCHANGE",
        }.get(method, "UNKNOWN")
        add(
            match,
            api_type="CIPHER_INSTANCE" if method in {"encrypt", "decrypt"} else "KEY_GENERATOR",
            algorithm="WebCrypto",
            purpose=purpose,
            library="Web Crypto API",
            confidence="MEDIUM",
            confidence_reason="WebCrypto call without algorithm object inspection",
        )
    for match in JWT_SIGN.finditer(source):
        add(
            match,
            api_type="SIGNATURE",
            algorithm=match.group(1) or "HS256",
            purpose="SIGNING",
            library="jsonwebtoken",
        )
    for match in BCRYPT.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="BCRYPT", purpose="PASSWORD_HASHING", library="bcrypt")
    for match in ARGON.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="ARGON2", purpose="PASSWORD_HASHING", library="argon2")
    for match in SJCL.finditer(source):
        add(match, api_type="CIPHER_INSTANCE", algorithm="AES", purpose="ENCRYPTION", library="sjcl")
    for match in CRYPTOJS.finditer(source):
        name = match.group(1).upper()
        algo_map = {"TRIPLEDES": "3DES", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA512": "SHA-512", "HMACSHA256": "HMAC-SHA256"}
        purpose = "HASHING" if name in {"MD5", "SHA1", "SHA256", "SHA512"} else "ENCRYPTION"
        add(
            match,
            api_type="MESSAGE_DIGEST" if purpose == "HASHING" else "CIPHER_INSTANCE",
            algorithm=algo_map.get(name, name),
            purpose=purpose,
            library="crypto-js",
        )
    for match in SECRET_ASSIGN.finditer(source):
        value = match.group(2)
        if looks_like_secret(value):
            add(
                match,
                api_type="HARDCODED_KEY",
                algorithm="UNKNOWN",
                purpose="KEY_GENERATION",
                library="javascript-literal",
                is_hardcoded_key=True,
                hardcoded_key_length=len(value),
                confidence="MEDIUM",
                confidence_reason="high-entropy secret assignment",
            )
    return findings


def _parse_node_cipher(spec: str) -> tuple[str, str | None, int | None]:
    parts = spec.lower().replace("_", "-").split("-")
    algo = parts[0].upper()
    if algo == "DES3" or spec.lower().startswith("des-ede"):
        algo = "3DES"
    key_size = None
    mode = None
    for part in parts[1:]:
        if part.isdigit():
            key_size = int(part)
        elif part.upper() in {"CBC", "GCM", "CTR", "ECB", "CFB", "OFB", "CCM"}:
            mode = part.upper()
    return algo, mode, key_size
