"""Upstream dependents (reverse blast radius) and shortest dependency paths."""

from __future__ import annotations

from shared_models.dependency_semantics import cypher_dependency_predicate

DEPENDENTS = """
// cryptoscan.query=dependents
MATCH (s:System)
WHERE s.system_id = $start OR s.name = $start
MATCH path = (up:System)-[:CALLS*1..12]->(s)
WHERE up <> s AND length(path) <= $hops
  AND all(n IN nodes(path) WHERE n:System)
  AND all(r IN relationships(path) WHERE __DEPENDENCY_POLICY__)
WITH up, min(length(path)) AS hops
RETURN up.system_id AS id,
       up.name AS name,
       up.criticality AS criticality,
       hops
ORDER BY hops, name, id
""".replace("__DEPENDENCY_POLICY__", cypher_dependency_predicate())

SHORTEST_PATH_DOWNSTREAM = """
// cryptoscan.query=shortest_path_downstream
MATCH (s:System), (t:System)
WHERE (s.system_id = $start OR s.name = $start)
  AND (t.system_id = $target OR t.name = $target)
OPTIONAL MATCH path = shortestPath((s)-[:CALLS*0..12]->(t))
WHERE all(n IN nodes(path) WHERE n:System)
  AND all(r IN relationships(path) WHERE __DEPENDENCY_POLICY__)
RETURN [n IN nodes(path) | coalesce(n.name, n.system_id)] AS names,
       length(path) AS hops
""".replace("__DEPENDENCY_POLICY__", cypher_dependency_predicate())

SHORTEST_PATH_UPSTREAM = """
// cryptoscan.query=shortest_path_upstream
MATCH (s:System), (t:System)
WHERE (s.system_id = $start OR s.name = $start)
  AND (t.system_id = $target OR t.name = $target)
OPTIONAL MATCH path = shortestPath((s)<-[:CALLS*0..12]-(t))
WHERE all(n IN nodes(path) WHERE n:System)
  AND all(r IN relationships(path) WHERE __DEPENDENCY_POLICY__)
RETURN [n IN nodes(path) | coalesce(n.name, n.system_id)] AS names,
       length(path) AS hops
""".replace("__DEPENDENCY_POLICY__", cypher_dependency_predicate())
