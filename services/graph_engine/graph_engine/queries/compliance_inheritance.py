"""Compliance scopes inherited through CALLS."""

from __future__ import annotations

COMPLIANCE_INHERITANCE = """
// cryptoscan.query=compliance_inheritance
MATCH (s:System)
WHERE s.system_id IN $system_ids
OPTIONAL MATCH (s)-[:MUST_COMPLY_WITH]->(cs:ComplianceScope)
RETURN collect(DISTINCT cs.standard_name) AS scopes
"""
