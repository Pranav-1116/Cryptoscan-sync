"""Weak-crypto concentration per system (word-boundary matched, no substring hits)."""

from __future__ import annotations

# Word boundaries matter: \bEC\b must NOT match AES-128-ECB.
CRYPTO_HOTSPOTS = """
// cryptoscan.query=crypto_hotspots
MATCH (s:System)-[:USES]->(a:CryptoAsset)
WITH s, collect(a) AS assets
RETURN s.system_id AS system_id,
       s.name AS name,
       s.criticality AS criticality,
       size(assets) AS total_assets,
       size([a IN assets WHERE a.algorithm =~ '(?i).*\\b(RSA|EC|ECC|ECDH|ECDSA|DSA|DH|X25519|Ed25519|Ed448|Diffie|Hellman|secp[a-zA-Z0-9]*|elliptic)\\b.*' | a.algorithm]) AS quantum_vulnerable_assets,
       [a IN assets WHERE a.algorithm =~ '(?i).*\\b(RSA|EC|ECC|ECDH|ECDSA|DSA|DH|X25519|Ed25519|Ed448|Diffie|Hellman|secp[a-zA-Z0-9]*|elliptic)\\b.*' | a.algorithm] AS vulnerable_algorithms
ORDER BY quantum_vulnerable_assets DESC, total_assets DESC, name
"""
