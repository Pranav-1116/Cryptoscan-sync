"""Nearest external vendor via a policy-permitted system dependency prefix."""

from __future__ import annotations

from shared_models.dependency_semantics import cypher_dependency_predicate
from graph_engine.queries.traversal_evidence import PATH_NODES, PATH_EDGES

# The final edge is domain linkage, not an additional system propagation hop.
# List slices exclude the Vendor node and DEPENDS_ON_VENDOR relationship.
VENDOR_PATH = """
// cryptoscan.query=vendor_path
MATCH (s:System)
WHERE s.system_id = $start OR s.name = $start
OPTIONAL MATCH path = (s)-[:CALLS*0..12]->(vendor_sys:System)-[:DEPENDS_ON_VENDOR]->(v:Vendor)
WHERE all(n IN nodes(path)[0..-1] WHERE n:System)
  AND all(r IN relationships(path)[0..-1] WHERE __DEPENDENCY_POLICY__)
RETURN [n IN nodes(path) | coalesce(n.name, n.system_id, n.vendor_id)] AS names,
       length(path) AS hops,
       v.name AS vendor,
       v.vendor_id AS vendor_id,
       __PATH_NODES__ AS path_nodes, __PATH_EDGES__ AS path_edges
ORDER BY hops, vendor_id
LIMIT 1
""".replace("__DEPENDENCY_POLICY__", cypher_dependency_predicate()).replace("__PATH_NODES__", PATH_NODES).replace("__PATH_EDGES__", PATH_EDGES)


VENDOR_NEIGHBORHOOD = """
// cryptoscan.query=vendor_neighborhood
MATCH (v:Vendor) WHERE v.vendor_id = $start OR v.name = $start
RETURN v AS n, null AS r, null AS m
UNION
MATCH (s:System)-[r:DEPENDS_ON_VENDOR]->(v:Vendor) WHERE v.vendor_id = $start OR v.name = $start
RETURN s AS n, r, v AS m
UNION
MATCH (s:System)-[:DEPENDS_ON_VENDOR]->(v:Vendor) WHERE v.vendor_id = $start OR v.name = $start
MATCH (s)-[r:USES|SUPPORTS]->(m)
RETURN s AS n, r, m
"""
VENDOR_LIST = """
// cryptoscan.query=vendor_list
MATCH (v:Vendor) RETURN v.vendor_id AS id ORDER BY id LIMIT $limit
"""
