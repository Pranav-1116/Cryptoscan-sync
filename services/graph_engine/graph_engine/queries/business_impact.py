"""Revenue / customer aggregation across the blast radius."""

from __future__ import annotations

IMPACT_FROM_SYSTEMS = """
// cryptoscan.query=business_impact
MATCH (s:System)
WHERE s.system_id IN $system_ids
OPTIONAL MATCH (s)-[:SUPPORTS]->(bp:BusinessProcess)
OPTIONAL MATCH (s)-[:OWNED_BY]->(owner:BusinessOwner)
OPTIONAL MATCH (s)-[:MUST_COMPLY_WITH]->(cs:ComplianceScope)
RETURN collect(DISTINCT bp.name) AS processes,
       collect(DISTINCT bp.revenue_daily) AS revenues,
       collect(DISTINCT bp.customer_count) AS customers,
       collect(DISTINCT owner.name) AS owners,
       collect(DISTINCT cs.standard_name) AS scopes
"""
