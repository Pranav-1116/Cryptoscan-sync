"""Shortest path from a system to an external vendor."""

from __future__ import annotations

VENDOR_PATH = """
// cryptoscan.query=vendor_path
MATCH (s:System)
WHERE s.system_id = $start OR s.name = $start
OPTIONAL MATCH path = shortestPath(
  (s)-[:CALLS*0..10]->(vendor_sys:System)-[:DEPENDS_ON_VENDOR]->(v:Vendor)
)
WHERE path IS NOT NULL
RETURN [n IN nodes(path) | coalesce(n.name, n.system_id, n.vendor_id)] AS names,
       length(path) AS hops,
       v.name AS vendor,
       v.vendor_id AS vendor_id
LIMIT 1
"""
