"""Identity-bearing support assertions and separately deduplicated context."""

from __future__ import annotations

IMPACT_FROM_SYSTEMS = """
// cryptoscan.query=business_impact
MATCH (s:System)
WHERE s.system_id IN $system_ids
OPTIONAL MATCH (s)-[:OWNED_BY]->(owner:BusinessOwner)
OPTIONAL MATCH (s)-[:MUST_COMPLY_WITH]->(cs:ComplianceScope)
RETURN collect(DISTINCT owner.name) AS owners,
       collect(DISTINCT cs.standard_name) AS scopes
"""

PROCESS_LINKS = """
// cryptoscan.query=process_links
MATCH (s:System)-[r:SUPPORTS]->(bp:BusinessProcess)
WHERE s.system_id IN $system_ids
RETURN s.system_id AS system_id, bp.process_id AS id, bp.name AS name,
       bp.revenue_daily AS revenue_daily, bp.customer_count AS customer_count,
       properties(r) AS properties
ORDER BY id, system_id
"""
