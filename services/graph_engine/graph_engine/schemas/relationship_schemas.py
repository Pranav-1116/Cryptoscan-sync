"""Relationship types stored in Neo4j."""

from __future__ import annotations

RELATIONSHIP_TYPES = (
    "USES",
    "CALLS",
    "SUPPORTS",
    "OWNED_BY",
    "MUST_COMPLY_WITH",
    "SECURED_BY",
    "DEPLOYED_ON",
    "DEPENDS_ON_VENDOR",
    "PROTECTED_BY",
)
