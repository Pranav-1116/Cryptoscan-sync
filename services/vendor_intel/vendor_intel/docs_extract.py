"""Extract algorithm mentions from vendor security documentation text."""

from __future__ import annotations

import re
from typing import Any

PATTERNS = re.compile(
    r"\b(AES-?256(?:-GCM)?|AES-?128(?:-CBC)?|TLS\s*1\.[0-3]|RSA-?(?:1024|2048|4096)|"
    r"ML-KEM(?:-768|-1024)?|ML-DSA(?:-65|-87)?|ChaCha20|SHA-?(?:1|256|384|512))\b",
    re.IGNORECASE,
)


def extract_crypto_mentions(text: str, *, vendor: str | None = None) -> dict[str, Any]:
    found = []
    seen = set()
    for match in PATTERNS.finditer(text or ""):
        token = match.group(1).upper().replace(" ", "")
        if token.startswith("TLS1"):
            token = "TLS " + token[3] + "." + token[4:] if len(token) >= 5 else token
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
