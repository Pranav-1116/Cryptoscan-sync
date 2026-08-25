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
WEBCRYPTO_NAMED = re.compile(
    r"""(?:crypto\.subtle|window\.crypto\.subtle)\.(\w+)\(\s*\{\s*name\s*:\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
WEBCRYPTO_DIGEST = re.compile(
    r"""(?:crypto\.subtle|window\.crypto\.subtle)\.digest\(\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
FORGE_MD = re.compile(r"""forge\.md\.(md5|sha1|sha256|sha384|sha512)\b""", re.IGNORECASE)
FORGE_CIPHER = re.compile(
    r"""forge\.cipher\.createCipher\(\s*['\"]([^'\"]+)['\"]""",
    re.IGNORECASE,
)
FORGE_RSA = re.compile(r"""forge\.pki\.rsa\.(generateKeyPair|setPublicKey|setPrivateKey)\b""", re.IGNORECASE)
FORGE_HMAC = re.compile(r"""forge\.hmac\.(create|start)\b""", re.IGNORECASE)
FORGE_PBKDF = re.compile(r"""forge\.pkcs5\.pbkdf2\b""", re.IGNORECASE)
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
    claimed_webcrypto: set[int] = set()
    for match in WEBCRYPTO_NAMED.finditer(source):
        method, raw_algo = match.group(1), match.group(2)
        claimed_webcrypto.add(match.start())
        algo, mode, purpose, api_type = _webcrypto_spec(method, raw_algo)
        add(
            match,
            api_type=api_type,
            algorithm=algo,
            mode=mode,
            purpose=purpose,
            library="Web Crypto API",
            raw_transformation=raw_algo,
        )
    for match in WEBCRYPTO_DIGEST.finditer(source):
        claimed_webcrypto.add(match.start())
        add(
            match,
            api_type="MESSAGE_DIGEST",
            algorithm=HASH_MAP.get(match.group(1).lower(), match.group(1).upper()),
            purpose="HASHING",
            library="Web Crypto API",
        )
    for match in WEBCRYPTO.finditer(source):
        if match.start() in claimed_webcrypto:
            continue
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
    for match in FORGE_MD.finditer(source):
        add(
            match,
            api_type="MESSAGE_DIGEST",
            algorithm=HASH_MAP.get(match.group(1).lower(), match.group(1).upper()),
            purpose="HASHING",
            library="node-forge",
        )
    for match in FORGE_CIPHER.finditer(source):
        raw = match.group(1)
        algo = "AES" if "AES" in raw.upper() else ("3DES" if "3DES" in raw.upper() or "DES-EDE" in raw.upper() else raw.upper())
        mode = None
        for item in ("GCM", "CBC", "ECB", "CFB", "OFB", "CTR"):
            if item in raw.upper():
                mode = item
                break
        add(
            match,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            purpose="ENCRYPTION",
            library="node-forge",
            raw_transformation=raw,
        )
    for match in FORGE_RSA.finditer(source):
        add(match, api_type="KEY_PAIR_GENERATOR", algorithm="RSA", purpose="KEY_GENERATION", library="node-forge")
    for match in FORGE_HMAC.finditer(source):
        add(match, api_type="MAC", algorithm="HMAC", purpose="MAC_GENERATION", library="node-forge")
    for match in FORGE_PBKDF.finditer(source):
        add(match, api_type="KEY_GENERATOR", algorithm="PBKDF2", purpose="PASSWORD_HASHING", library="node-forge")
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




def _webcrypto_spec(method: str, raw_algo: str) -> tuple[str, str | None, str, str]:
    upper = raw_algo.upper().replace("_", "-")
    purpose = {
        "encrypt": "ENCRYPTION",
        "decrypt": "DECRYPTION",
        "sign": "SIGNING",
        "verify": "VERIFICATION",
        "digest": "HASHING",
        "generateKey": "KEY_GENERATION",
        "importKey": "KEY_GENERATION",
        "deriveBits": "KEY_EXCHANGE",
        "deriveKey": "KEY_EXCHANGE",
    }.get(method, "UNKNOWN")
    mode = None
    if "GCM" in upper:
        mode = "GCM"
    elif "CBC" in upper:
        mode = "CBC"
    elif "CTR" in upper:
        mode = "CTR"
    if "AES" in upper:
        return "AES", mode, purpose, "CIPHER_INSTANCE" if purpose in {"ENCRYPTION", "DECRYPTION"} else "KEY_GENERATOR"
    if "RSA" in upper:
        return "RSA", None, purpose, "KEY_PAIR_GENERATOR" if purpose == "KEY_GENERATION" else "SIGNATURE"
    if "ECDSA" in upper or "ECDH" in upper:
        return "ECDSA" if "ECDSA" in upper else "ECDH", None, purpose, "KEY_PAIR_GENERATOR"
    if upper.startswith("SHA"):
        return HASH_MAP.get(raw_algo.lower(), upper), None, "HASHING", "MESSAGE_DIGEST"
    if "HMAC" in upper:
        return "HMAC", None, "MAC_GENERATION", "MAC"
    if "PBKDF2" in upper:
        return "PBKDF2", None, "PASSWORD_HASHING", "KEY_GENERATOR"
    return raw_algo, mode, purpose, "CIPHER_INSTANCE"

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
