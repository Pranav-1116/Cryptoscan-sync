"""Nearest external vendor via a policy-permitted system dependency prefix."""

from __future__ import annotations

from shared_models.dependency_semantics import cypher_dependency_predicate

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
       v.vendor_id AS vendor_id
ORDER BY hops, vendor_id
LIMIT 1
""".replace("__DEPENDENCY_POLICY__", cypher_dependency_predicate())
