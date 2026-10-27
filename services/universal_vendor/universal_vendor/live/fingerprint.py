"""Vendor Configuration Monitoring (24/7 spec §12).

Configuration fingerprints: current config → canonical serializer →
configuration hash → compare with previous hash. If HASH_CHANGED, compute a
diff and decide whether the change is crypto-relevant — only then trigger a
deep crypto analysis. This prevents expensive deep scanning for irrelevant
changes.
"""

from __future__ import annotations

import hashlib
from typing import Any, Optional

from universal_vendor.plugin import canonical_json

# Tokens that mark a config change as crypto-relevant. Cheap and conservative:
# if any appear in the changed lines, the change may affect crypto posture.
_CRYPTO_TOKENS = (
    "crypto", "ssl", "tls", "certificate", "cert", "ike", "ipsec", "ssh",
    "cipher", "encryption", "encrypt", "key", "aes", "rsa", "ecdsa", "dsa",
    "hash", "sha", "md5", "trustpoint", "trust-store", "truststore", "pki",
    "hsm", "pkcs", "hmac", "vpn", "dtls", "sni", "ocsp", "crl",
)


def canonical_serialize(config: Any) -> str:
    """Deterministic canonical serialization for hashing."""
    if isinstance(config, str):
        return config
    return canonical_json(config)


def config_hash(config: Any) -> str:
    return hashlib.sha256(canonical_serialize(config).encode("utf-8")).hexdigest()


def _line_diff(old: str, new: str) -> list[str]:
    old_lines = set(old.splitlines())
    new_lines = set(new.splitlines())
    return [line for line in new_lines - old_lines if line.strip()]


def crypto_relevant_diff(old_config: Any, new_config: Any) -> dict[str, Any]:
    """Diff two configs and judge crypto relevance.

    Returns {hash_changed, crypto_relevant, changed_lines, matching_tokens}.
    """
    old_text = canonical_serialize(old_config)
    new_text = canonical_serialize(new_config)
    changed = old_text != new_text
    changed_lines = _line_diff(old_text, new_text) if changed else []
    lowered = "\n".join(changed_lines).lower()
    matched = [token for token in _CRYPTO_TOKENS if token in lowered]
    return {
        "hash_changed": changed,
        "crypto_relevant": bool(matched),
        "changed_lines": changed_lines,
        "matching_tokens": matched,
    }


class ConfigFingerprintTracker:
    """Per-asset fingerprint history."""

    def __init__(self) -> None:
        self._current: dict[str, str] = {}
        self._previous: dict[str, str] = {}

    def observe(self, asset_id: str, config: Any) -> dict[str, Any]:
        """Record a new config observation. Returns the diff verdict."""
        digest = config_hash(config)
        previous = self._current.get(asset_id)
        self._previous[asset_id] = previous or digest
        self._current[asset_id] = digest
        return {
            "asset_id": asset_id,
            "config_hash": digest,
            "previous_hash": self._previous[asset_id],
            "hash_changed": previous is not None and previous != digest,
            "first_seen": previous is None,
        }

    def current(self, asset_id: str) -> Optional[str]:
        return self._current.get(asset_id)
