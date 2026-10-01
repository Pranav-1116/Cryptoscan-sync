"""Shared helpers for vendor plugins — banner detection, config parsing,
algorithm extraction. All parsing is read-only and metadata-only.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

from universal_vendor.models import ConnectionResult, DetectionResult
from universal_vendor.plugin import UniversalVendorPlugin

_ALGORITHM_TOKENS = (
    "AES", "AES-128", "AES-192", "AES-256", "AES128", "AES192", "AES256",
    "AES-GCM", "AES-CBC", "AES-CCM",
    "AES128-GCM", "AES192-GCM", "AES256-GCM", "AES128-CBC", "AES256-CBC",
    "RSA-1024", "RSA-2048", "RSA-4096",
    "AES128-CCM", "AES256-CCM", "AES256-GCM-SHA384", "AES128-GCM-SHA256",
    "AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC",
    "AES_128_GCM_SHA256", "AES_256_GCM_SHA384", "TLSv1_0", "TLSv1_1",
    "TLSv1_2", "TLSv1_3",
    "DES", "3DES", "DESede", "RC4", "ARCFOUR", "BLOWFISH", "CHACHA20",
    "CHACHA20-POLY1305", "RSA", "DSA", "ECDSA", "ECDH", "DH", "EC", "ED25519",
    "ED448", "X25519", "X448", "ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA",
    "MD5", "SHA-1", "SHA1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
    "SHA-512/256", "SHA3-256", "SHA3-512", "HMAC", "HMAC-SHA256", "HMAC-SHA1",
    "HKDF", "PBKDF2", "SCRYPT", "ARGON2", "CURVE25519", "P-256", "P-384",
    "P-521", "SECP256R1", "SECP384R1", "SECP521R1", "BRAINPOOLP256R1",
    "SPHINCS+", "SPHINCS", "KYBER", "DILITHIUM", "FALCON", "XMSS", "LMS",
    "GOST", "SM2", "SM3", "SM4", "ARIA", "CAMELLIA", "SEED",
    # Protocol versions and negotiated key-exchange names are crypto evidence,
    # but only when they occur as complete configuration tokens.
    "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3", "TLS1.0", "TLS1.1",
    "TLS1.2", "TLS1.3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3",
)


def _text(value: Any) -> str:
    """Turn structured vendor metadata into deterministic searchable text.

    Vendor APIs often return dictionaries/lists rather than configuration
    strings. ``str(dict)`` is order-dependent and can make scans disagree;
    JSON with sorted keys gives the extractor stable input while retaining
    algorithm fields nested in the response.
    """
    if isinstance(value, str):
        return value

    def stable(item: Any) -> Any:
        if isinstance(item, dict):
            return {str(key): stable(item[key])
                    for key in sorted(item, key=str)}
        if isinstance(item, (list, tuple)):
            return [stable(child) for child in item]
        if isinstance(item, set):
            return [stable(child) for child in sorted(item, key=str)]
        return item

    try:
        return json.dumps(stable(value), sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def extract_algorithms(text: Any, known: Iterable[str] = _ALGORITHM_TOKENS) -> list[str]:
    """Find complete, known crypto tokens in text or structured metadata.

    Matches are case-insensitive and longest-first. A generic token such as
    ``AES`` is suppressed when the same span contains the more specific
    ``AES-GCM`` or ``AES-256`` token. This avoids reporting both a family and
    a fabricated second algorithm for one configuration value.
    """
    source = _text(text)
    candidates: list[tuple[int, int, int, int, str]] = []
    tokens = list(dict.fromkeys(str(token) for token in known if str(token)))
    for order, token in enumerate(tokens):
        pattern = re.compile(
            r"(?<![A-Za-z0-9])" + re.escape(token) + r"(?![A-Za-z0-9])",
            re.IGNORECASE,
        )
        for match in pattern.finditer(source):
            # A punctuation-delimited suffix is part of the same algorithm
            # token (AES_256, CHACHA20-POLY1305X). Do not downgrade that
            # value to a generic family when the complete variant is unknown.
            if re.match(r"[-_/][A-Za-z0-9]", source[match.end():]):
                continue
            candidates.append((match.start(), match.end(), -len(token), order, token))

    # At one location prefer the longest complete token. Then retain the
    # original configuration order so output is deterministic and explainable.
    candidates.sort(key=lambda row: (row[0], row[2], row[3]))
    accepted: list[tuple[int, int, str]] = []
    for start, end, _negative_length, _order, token in candidates:
        if any(start < other_end and end > other_start
               for other_start, other_end, _ in accepted):
            continue
        accepted.append((start, end, token))
    accepted.sort(key=lambda row: (row[0], row[1]))
    result: list[str] = []
    seen: set[str] = set()
    for _start, _end, token in accepted:
        canonical = re.sub(
            r"^TLSv?1[._]([0-3])$", r"TLS 1.\1", token,
            flags=re.IGNORECASE,
        )
        canonical = re.sub(
            r"^TLS1[._]([0-3])$", r"TLS 1.\1", canonical,
            flags=re.IGNORECASE,
        )
        if not canonical.upper().startswith("TLS "):
            canonical = canonical.replace("_", "-")
        aes_alias = re.fullmatch(r"AES(128|192|256)", canonical, re.IGNORECASE)
        if aes_alias:
            canonical = f"AES-{aes_alias.group(1)}"
        else:
            canonical = re.sub(r"^AES(128|192|256)-", r"AES-\1-", canonical,
                               flags=re.IGNORECASE)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


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
