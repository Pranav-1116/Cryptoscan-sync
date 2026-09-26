"""§21 Hard-coded crypto detection.

Finds hardcoded algorithms, key sizes, curves, cipher suites, certificates
and crypto providers. Hard-coded crypto ⇒ MIGRATION_RISK = HIGH (an
algorithm swap requires a code change, not a config change).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

#: source patterns that indicate hard-coding (deterministic catalog)
_PATTERNS: list[tuple[str, str]] = [
    ("hardcoded_algorithm", r"(?:algorithm|algo|cipher)\s*=\s*['\"][^'\"]+['\"]"),
    ("hardcoded_algorithm", r"getInstance\(\s*['\"](?:AES|RSA|SHA|ECDSA|DES|ChaCha20|ML-KEM|ML-DSA)"),
    ("hardcoded_key_size", r"(?:key_size|keysize|keylen|bits)\s*=\s*\d{3,4}\b"),
    ("hardcoded_key_size", r"KeyGenerator\.getInstance.*\d{3,4}"),
    ("hardcoded_key_size", r"generateKey\(\s*\d{3,4}\s*\)"),
    ("hardcoded_curve", r"(?:curve|namedCurve)\s*=\s*['\"](?:P-256|P-384|P-521|secp256k1|X25519)['\"]"),
    ("hardcoded_curve", r"new\s+ECGenParameterSpec\(\s*['\"](?:P-256|P-384|P-521)['\"]"),
    ("hardcoded_cipher_suite", r"(?:cipher_suites|ciphers)\s*=\s*\[[^\]]*TLS_"),
    ("hardcoded_cipher_suite", r"setCipherSuites\(\s*['\"]TLS_"),
    ("hardcoded_certificate", r"(?:certificate|cert_pem|CERTIFICATE)\s*=\s*['\"]-----BEGIN"),
    ("hardcoded_certificate", r"-----BEGIN CERTIFICATE-----"),
    ("hardcoded_provider", r"(?:provider)\s*=\s*['\"](?:SunJCE|BC|OpenSSL|mbedTLS)['\"]"),
    ("hardcoded_kem", r"(?:kem|key_encapsulation)\s*=\s*['\"]ML-KEM"),
]

#: lines that are documentation rather than code (suppressed, §30)
_COMMENT_RE = re.compile(r"^\s*(#|//|/\*|\*|--|<!--|\"\"\"|')")


class HardcodedCryptoDetector:
    """§21 detection over source lines."""

    def detect(self, lines: Iterable[str], *, asset_id: str = "default",
               location: str = "") -> dict[str, Any]:
        findings: dict[str, list[dict[str, Any]]] = {}
        for lineno, line in enumerate(lines, start=1):
            if _COMMENT_RE.match(line):
                continue
            for kind, pattern in _PATTERNS:
                if re.search(pattern, line):
                    findings.setdefault(kind, []).append({
                        "line": lineno,
                        "text": line.strip()[:120],
                        "location": f"{location}:{lineno}" if location else str(lineno),
                    })
        return {
            "asset_id": asset_id,
            "hardcoded": findings,
            "migration_risk": "HIGH" if findings else "LOW",
            "count": sum(len(v) for v in findings.values()),
        }
