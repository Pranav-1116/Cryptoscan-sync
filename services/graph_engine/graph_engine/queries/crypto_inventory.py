"""Crypto assets used by a system."""

from __future__ import annotations

CRYPTO_FOR_SYSTEM = """
// cryptoscan.query=crypto_inventory
MATCH (s:System)-[r:USES]->(a:CryptoAsset)
WHERE s.system_id = $start OR s.name = $start
RETURN a.asset_id AS id,
       a.algorithm AS algorithm,
       a.purpose AS purpose,
       a.confidence AS confidence,
       a.key_size AS key_size,
       r.usage_type AS usage_type
"""
