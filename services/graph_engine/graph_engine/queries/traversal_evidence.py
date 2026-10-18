"""Fetch bounded witness payloads separately from uncapped membership counts."""

from shared_models.dependency_semantics import cypher_dependency_predicate

PATH_NODES = "[n IN nodes(path) | CASE WHEN n:Vendor THEN 'vendor:' + n.vendor_id ELSE n.system_id END]"
PATH_EDGES = """[r IN relationships(path) | {from: startNode(r).system_id,
 to: CASE WHEN endNode(r):Vendor THEN 'vendor:' + endNode(r).vendor_id ELSE endNode(r).system_id END,
 type: type(r), properties: properties(r)}]"""


def _query(reverse):
    match = "(t:System)-[:CALLS*1..12]->(s)" if reverse else "(s)-[:CALLS*1..12]->(t:System)"
    nodes = f"reverse({PATH_NODES})" if reverse else PATH_NODES
    edges = f"reverse({PATH_EDGES})" if reverse else PATH_EDGES
    return f"""
// cryptoscan.query=witness_{"upstream" if reverse else "downstream"}
MATCH (s:System) WHERE s.system_id IN $starts
MATCH path = {match}
WHERE t.system_id IN $targets AND length(path) <= $hops
 AND all(n IN nodes(path) WHERE n:System)
 AND all(r IN relationships(path) WHERE {cypher_dependency_predicate()})
WITH t, path, {nodes} AS witness_nodes
ORDER BY length(path), witness_nodes, [r IN relationships(path) | coalesce(r.relation, r.protocol, 'CALLS') + coalesce(r.record_id, '') + coalesce(r.source, '')]
WITH t, head(collect({{path_nodes: witness_nodes, path_edges: {edges}}})) AS witness
RETURN t.system_id AS id, witness.path_nodes AS path_nodes, witness.path_edges AS path_edges
ORDER BY id LIMIT $witness_limit
"""


WITNESS_DOWNSTREAM = _query(False)
WITNESS_UPSTREAM = _query(True)


DOMAIN_LINKS = """
// cryptoscan.query=domain_links
MATCH (s:System)-[r]->(n)
WHERE s.system_id IN $system_ids AND type(r) IN $relations
 AND ($target_asset IS NULL OR (n:CryptoAsset AND n.asset_id = $target_asset))
RETURN s.system_id AS source, type(r) AS relation, properties(r) AS properties,
 CASE WHEN n:BusinessProcess THEN 'process:' + n.process_id
      WHEN n:BusinessOwner THEN 'owner:' + n.owner_id
      WHEN n:ComplianceScope THEN 'scope:' + n.standard_name
      WHEN n:CryptoAsset THEN 'asset:' + n.asset_id ELSE null END AS target
ORDER BY source, relation, target LIMIT $domain_limit
"""
