"""W3C XML-DSig / XML-Enc algorithm URIs as they appear in *source code* (C#, Java, Python, Go).

`xml_parser.py` handles the same identifiers inside XML documents; here they are string constants in code —
SAML / WS-Security / XAdES / Peppol AS4 profiles spell their algorithms this way and nothing else on the line
names the primitive. Shared table, one regex, used by every source-code parser through ``xmlsec_uri_findings``.
"""

from __future__ import annotations

import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

URI = re.compile(r"https?://www\.w3\.org/(?:2000/09/xmldsig|2001/04/xmldsig-more|2001/04/xmlenc|2009/xmlenc11|2007/05/xmldsig-more|2021/04/xmldsig-more)#([A-Za-z0-9_.-]+)")

# suffix → (algorithm, digest, api_type, purpose)
TABLE: dict[str, tuple[str, str | None, str, str]] = {
    "rsa-sha1": ("RSA", "SHA-1", "SIGNATURE", "SIGNING"), "rsa-sha224": ("RSA", "SHA-224", "SIGNATURE", "SIGNING"), "rsa-sha256": ("RSA", "SHA-256", "SIGNATURE", "SIGNING"),
    "rsa-sha384": ("RSA", "SHA-384", "SIGNATURE", "SIGNING"), "rsa-sha512": ("RSA", "SHA-512", "SIGNATURE", "SIGNING"), "rsa-md5": ("RSA", "MD5", "SIGNATURE", "SIGNING"),
    "rsa-sha256-mgf1": ("RSA", "SHA-256", "SIGNATURE", "SIGNING"), "rsa-sha384-mgf1": ("RSA", "SHA-384", "SIGNATURE", "SIGNING"), "rsa-sha512-mgf1": ("RSA", "SHA-512", "SIGNATURE", "SIGNING"),
    "rsa-pss": ("RSA", None, "SIGNATURE", "SIGNING"), "dsa-sha1": ("DSA", "SHA-1", "SIGNATURE", "SIGNING"), "dsa-sha256": ("DSA", "SHA-256", "SIGNATURE", "SIGNING"),
    "ecdsa-sha1": ("ECDSA", "SHA-1", "SIGNATURE", "SIGNING"), "ecdsa-sha224": ("ECDSA", "SHA-224", "SIGNATURE", "SIGNING"), "ecdsa-sha256": ("ECDSA", "SHA-256", "SIGNATURE", "SIGNING"),
    "ecdsa-sha384": ("ECDSA", "SHA-384", "SIGNATURE", "SIGNING"), "ecdsa-sha512": ("ECDSA", "SHA-512", "SIGNATURE", "SIGNING"), "eddsa-ed25519": ("Ed25519", None, "SIGNATURE", "SIGNING"),
    "hmac-sha1": ("HMAC", "SHA-1", "MAC", "MAC_GENERATION"), "hmac-sha256": ("HMAC", "SHA-256", "MAC", "MAC_GENERATION"), "hmac-sha384": ("HMAC", "SHA-384", "MAC", "MAC_GENERATION"),
    "hmac-sha512": ("HMAC", "SHA-512", "MAC", "MAC_GENERATION"), "hmac-md5": ("HMAC", "MD5", "MAC", "MAC_GENERATION"),
    "sha1": ("SHA-1", None, "MESSAGE_DIGEST", "HASHING"), "sha224": ("SHA-224", None, "MESSAGE_DIGEST", "HASHING"), "sha256": ("SHA-256", None, "MESSAGE_DIGEST", "HASHING"),
    "sha384": ("SHA-384", None, "MESSAGE_DIGEST", "HASHING"), "sha512": ("SHA-512", None, "MESSAGE_DIGEST", "HASHING"), "md5": ("MD5", None, "MESSAGE_DIGEST", "HASHING"),
    "sha3-256": ("SHA3-256", None, "MESSAGE_DIGEST", "HASHING"), "sha3-384": ("SHA3-384", None, "MESSAGE_DIGEST", "HASHING"), "sha3-512": ("SHA3-512", None, "MESSAGE_DIGEST", "HASHING"),
    "aes128-cbc": ("AES", None, "CIPHER_INSTANCE", "ENCRYPTION"), "aes192-cbc": ("AES", None, "CIPHER_INSTANCE", "ENCRYPTION"), "aes256-cbc": ("AES", None, "CIPHER_INSTANCE", "ENCRYPTION"),
    "aes128-gcm": ("AES", None, "CIPHER_INSTANCE", "ENCRYPTION"), "aes192-gcm": ("AES", None, "CIPHER_INSTANCE", "ENCRYPTION"), "aes256-gcm": ("AES", None, "CIPHER_INSTANCE", "ENCRYPTION"),
    "tripledes-cbc": ("3DES", None, "CIPHER_INSTANCE", "ENCRYPTION"), "kw-tripledes": ("3DES", None, "KEY_GENERATOR", "KEY_WRAPPING"),
    "kw-aes128": ("AES", None, "KEY_GENERATOR", "KEY_WRAPPING"), "kw-aes192": ("AES", None, "KEY_GENERATOR", "KEY_WRAPPING"), "kw-aes256": ("AES", None, "KEY_GENERATOR", "KEY_WRAPPING"),
    "rsa-1_5": ("RSA", None, "CIPHER_INSTANCE", "KEY_WRAPPING"), "rsa-oaep-mgf1p": ("RSA", None, "CIPHER_INSTANCE", "KEY_WRAPPING"), "rsa-oaep": ("RSA", None, "CIPHER_INSTANCE", "KEY_WRAPPING"),
    "dh": ("DH", None, "KEY_AGREEMENT", "KEY_EXCHANGE"), "dh-es": ("DH", None, "KEY_AGREEMENT", "KEY_EXCHANGE"), "ecdh-es": ("ECDH", None, "KEY_AGREEMENT", "KEY_EXCHANGE"),
    "ConcatKDF": ("HKDF", None, "KEY_GENERATOR", "KEY_DERIVATION"), "pbkdf2": ("PBKDF2", None, "KEY_GENERATOR", "KEY_DERIVATION"),
}

_MODE = {"cbc": "CBC", "gcm": "GCM"}


def xmlsec_uri_findings(source: str, *, file_path: Path, repo_root: Path | None, language: str, scanner_id: str, library: str = "xmldsig") -> list[RawFinding]:
    """Findings for every XML-DSig / XML-Enc algorithm URI literal in ``source`` (comments already stripped by the caller)."""
    out: list[RawFinding] = []
    seen: set[tuple[int, str]] = set()
    for m in URI.finditer(source):
        entry = TABLE.get(m.group(1)) or TABLE.get(m.group(1).lower())
        if not entry:
            continue
        algorithm, digest, api_type, purpose = entry
        line = source[: m.start()].count("\n") + 1
        mode = next((v for k, v in _MODE.items() if m.group(1).lower().endswith("-" + k)), None)
        for algo, api, purp in ((algorithm, api_type, purpose), (digest, "MESSAGE_DIGEST", "HASHING")):
            if not algo or (line, algo) in seen:
                continue
            seen.add((line, algo))
            out.append(make_finding(file_path=file_path, repo_root=repo_root, line_number=line, language=language, api_type=api, algorithm=algo,
                                    purpose=purp, library=library, scanner_id=scanner_id, mode=mode if algo == algorithm else None,
                                    raw_transformation=m.group(0), confidence="HIGH", confidence_reason="xmldsig-algorithm-uri"))
    return out
