"""Upstream dependents (reverse blast radius) and shortest dependency paths."""

from __future__ import annotations

DEPENDENTS = """
// cryptoscan.query=dependents
MATCH (s:System)
WHERE s.system_id = $start OR s.name = $start
OPTIONAL MATCH path = (up:System)-[:CALLS*1..12]->(s)
WITH s, up, path
WHERE up IS NOT NULL AND length(path) <= $hops
RETURN DISTINCT up.system_id AS id,
                up.name AS name,
                up.criticality AS criticality,
                length(path) AS hops
ORDER BY hops, name
"""

SHORTEST_PATH_DOWNSTREAM = """
// cryptoscan.query=shortest_path_downstream
MATCH (s:System), (t:System)
WHERE (s.system_id = $start OR s.name = $start)
  AND (t.system_id = $target OR t.name = $target)
OPTIONAL MATCH path = shortestPath((s)-[:CALLS*0..10]->(t))
RETURN [n IN nodes(path) | coalesce(n.name, n.system_id)] AS names,
       length(path) AS hops
"""

SHORTEST_PATH_UPSTREAM = """
// cryptoscan.query=shortest_path_upstream
MATCH (s:System), (t:System)
WHERE (s.system_id = $start OR s.name = $start)
  AND (t.system_id = $target OR t.name = $target)
OPTIONAL MATCH path = shortestPath((s)<-[:CALLS*0..10]-(t))
RETURN [n IN nodes(path) | coalesce(n.name, n.system_id)] AS names,
       length(path) AS hops
"""
