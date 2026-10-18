"""Downstream CALLS traversal."""

from __future__ import annotations

from shared_models.dependency_semantics import cypher_dependency_predicate

BLAST_RADIUS = """
// cryptoscan.query=blast_radius
MATCH (s:System)
WHERE s.system_id = $start OR s.name = $start
MATCH path = (s)-[:CALLS*1..12]->(downstream:System)
WHERE downstream <> s AND length(path) <= $hops
  AND all(n IN nodes(path) WHERE n:System)
  AND all(r IN relationships(path) WHERE __DEPENDENCY_POLICY__)
WITH downstream, min(length(path)) AS hops
RETURN downstream.system_id AS id,
       downstream.name AS name,
       downstream.criticality AS criticality,
       hops
ORDER BY hops, name, id
""".replace("__DEPENDENCY_POLICY__", cypher_dependency_predicate())

SYSTEMS_USING_ASSET = """
// cryptoscan.query=systems_using_asset
MATCH (s:System)-[:USES]->(a:CryptoAsset)
WHERE a.asset_id = $start OR a.algorithm = $start
RETURN DISTINCT s.system_id AS id, s.name AS name
"""

ORIGIN_SYSTEM = """
// cryptoscan.query=origin_system
MATCH (s:System)
WHERE s.system_id = $start OR s.name = $start
RETURN s.system_id AS id, s.name AS name
LIMIT 1
"""
