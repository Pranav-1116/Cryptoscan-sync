"""Extract algorithm mentions from vendor security documentation text."""

from __future__ import annotations

import re
from typing import Any

PATTERNS = re.compile(
    r"\b(AES-?256(?:-GCM)?|AES-?128(?:-CBC)?|TLS\s*v?\s*1\.[0-3]|RSA-?(?:1024|2048|4096)|"
    r"ML-KEM(?:-768|-1024)?|ML-DSA(?:-65|-87)?|ChaCha20|SHA-?(?:1|256|384|512))\b",
    re.IGNORECASE,
)


def extract_crypto_mentions(text: str, *, vendor: str | None = None) -> dict[str, Any]:
    found = []
    seen = set()
    for match in PATTERNS.finditer(text or ""):
        token = match.group(1).upper().replace(" ", "")
        tls_match = re.fullmatch(r"TLSV?1\.([0-3])", token)
        if tls_match:
            token = f"TLS 1.{tls_match.group(1)}"
        else:
            compact = token.replace("-", "")
            aes_match = re.fullmatch(r"AES(128|256)(GCM|CBC)?", compact)
            rsa_match = re.fullmatch(r"RSA(1024|2048|4096)", compact)
            sha_match = re.fullmatch(r"SHA(1|256|384|512)", compact)
            if aes_match:
                token = f"AES-{aes_match.group(1)}" + (
                    f"-{aes_match.group(2)}" if aes_match.group(2) else "")
            elif rsa_match:
                token = f"RSA-{rsa_match.group(1)}"
            elif sha_match:
                token = f"SHA-{sha_match.group(1)}"
        if token in seen:
            continue
        seen.add(token)
        found.append(
            {
                "crypto_use_case": "PUBLIC_DOCUMENTATION",
                "algorithm": token,
                "discovery_method": "PUBLIC_DOCUMENTATION",
                "confidence": "LOW",
            }
        )
    return {
        "vendor": vendor,
        "source": "PUBLIC_DOCUMENTATION",
        "crypto_mentioned": found,
        "confidence": "LOW",
        "inventory": found,
    }
