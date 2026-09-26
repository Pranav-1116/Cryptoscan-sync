"""Shared helpers for vendor plugins — banner detection, config parsing,
algorithm extraction. All parsing is read-only and metadata-only.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from universal_vendor.models import ConnectionResult, DetectionResult
from universal_vendor.plugin import UniversalVendorPlugin

_ALGORITHM_TOKENS = (
    "AES", "AES-128", "AES-192", "AES-256", "AES-GCM", "AES-CBC", "AES-CCM",
    "AES128-GCM", "AES192-GCM", "AES256-GCM", "AES128-CBC", "AES256-CBC",
    "AES128-CCM", "AES256-CCM", "AES256-GCM-SHA384", "AES128-GCM-SHA256",
    "DES", "3DES", "DESede", "RC4", "ARCFOUR", "BLOWFISH", "CHACHA20",
    "CHACHA20-POLY1305", "RSA", "DSA", "ECDSA", "ECDH", "DH", "EC", "ED25519",
    "ED448", "X25519", "X448", "ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA",
    "MD5", "SHA-1", "SHA1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
    "SHA-512/256", "SHA3-256", "SHA3-512", "HMAC", "HMAC-SHA256", "HMAC-SHA1",
    "HKDF", "PBKDF2", "SCRYPT", "ARGON2", "CURVE25519", "P-256", "P-384",
    "P-521", "SECP256R1", "SECP384R1", "SECP521R1", "BRAINPOOLP256R1",
    "SPHINCS+", "SPHINCS", "KYBER", "DILITHIUM", "FALCON", "XMSS", "LMS",
    "GOST", "SM2", "SM3", "SM4", "ARIA", "CAMELLIA", "SEED",
)

_ALGORITHM_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9+/_.-]*[A-Za-z][A-Za-z0-9+/_.-]*)(?![A-Za-z0-9])")


def extract_algorithms(text: str, known: Iterable[str] = _ALGORITHM_TOKENS) -> list[str]:
    """Find known crypto algorithm tokens in configuration text."""
    upper = text.upper()
    found: list[str] = []
    for token in known:
        pattern = re.compile(r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])")
        if pattern.search(upper):
            if token not in found:
                found.append(token)
    return found


def parse_kv_lines(text: str) -> dict[str, Any]:
    """Parse 'key value' or 'key = value' lines into a dict (first wins)."""
    out: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "!")):
            continue
        match = re.match(r"([A-Za-z0-9_.\-]+)\s*[=:]\s*(.+)$", stripped)
        if match:
            key, value = match.group(1), match.group(2).strip()
            value = re.sub(r"[\"']", "", value)
            out.setdefault(key, value)
            continue
        match = re.match(r"([A-Za-z0-9_.\-]+)\s+(.+)$", stripped)
        if match:
            key, value = match.group(1), match.group(2).strip()
            out.setdefault(key, value)
    return out


def parse_ssl_blocks(text: str, marker: str) -> list[dict[str, Any]]:
    """Parse indented blocks introduced by `marker` (e.g. 'ssl' / 'crypto')."""
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if indent == 0 and stripped.lower() == marker:
            current = {}
            blocks.append(current)
            continue
        if current is not None and indent == 0 and stripped:
            current = None
            continue
        if current is not None and stripped and not stripped.startswith(("#", "//", "!")):
            match = re.match(r"([A-Za-z0-9_.\-]+)\s+(.+)$", stripped)
            if match:
                current[match.group(1)] = match.group(2)
    return blocks


class BannerPluginBase(UniversalVendorPlugin):
    """Base for banner/config-detected plugins with a standard detect().

    Subclasses set ``_patterns`` (regex, vendor, product, weight) and
    ``_config_keys`` (context keys that must be present to be connected).
    """

    _patterns: list[tuple[str, str, str, float]] = []
    _config_keys: tuple[str, ...] = ("config",)

    def detect(self, context: dict[str, Any]) -> DetectionResult:
        return self._detect_banner(
            context,
            banner_fields=("banner", "ssh_banner", "server_header", "config"),
            patterns=self._patterns,
        )

    def validate_connection(self, context: dict[str, Any]) -> ConnectionResult:
        missing = [key for key in self._config_keys if key not in context]
        if missing:
            return ConnectionResult(
                connected=False,
                message=f"missing artifact(s): {', '.join(missing)}",
            )
        if not self.detect(context).detected:
            return ConnectionResult(
                connected=False,
                message=f"artifact does not match {self.vendor} {self.product}",
            )
        return ConnectionResult(connected=True, message="artifact present and recognized")
