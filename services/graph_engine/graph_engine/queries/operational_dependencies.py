"""Selected operational assertions, no whole-graph export or synthetic paths."""
OPERATIONAL_LINKS = """
// cryptoscan.query=operational_links
MATCH (a:System)-[r:CALLS]->(b:System)
WHERE a.system_id IN $system_ids AND b.system_id IN $system_ids
AND (a.tenant_id = $tenant OR ($tenant = 'platform' AND a.tenant_id IS NULL))
AND (b.tenant_id = $tenant OR ($tenant = 'platform' AND b.tenant_id IS NULL))
RETURN a.system_id AS source, b.system_id AS target, properties(r) AS properties
ORDER BY source, target
"""
OPERATIONAL_SYSTEMS = """
// cryptoscan.query=operational_systems
MATCH (s:System)
WHERE s.system_id IN $ids
AND (s.tenant_id = $tenant OR ($tenant = 'platform' AND s.tenant_id IS NULL))
RETURN s.system_id AS id
"""
