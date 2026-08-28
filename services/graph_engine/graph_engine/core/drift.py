"""Graph drift: is the persisted Neo4j graph behind the relational inventory?

Honest by construction: with no Neo4j configured there is a single graph
and nothing to compare — `checked: False` with the reason, never a
fabricated "no drift" answer.
"""

from __future__ import annotations

from typing import Any

from graph_engine.connection.health_check import probe_neo4j
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore


def graph_drift(payload: dict[str, Any], *, driver=None) -> dict[str, Any]:
    """Diff the fresh in-memory graph (built from SQL rows) against the
    persisted Neo4j graph (via its vis export)."""
    if driver is None:
        return {"checked": False, "reason": "neo4j_unavailable", "detail": "single in-memory backend; nothing to compare"}
    health = probe_neo4j(driver)
    if not health.get("ok"):
        return {"checked": False, "reason": "neo4j_unhealthy", "health": health}
    fresh = GraphEngine().build(**payload)
    persisted = GraphEngine.from_vis(Neo4jGraphStore(driver).to_vis())
    # diff(old, new): persisted is the stale state, fresh is the inventory truth —
    # nodes_added/edges_added are what a re-sync would write to Neo4j.
    diff = persisted.diff(fresh)
    return {
        "checked": True,
        "backend": "neo4j",
        "direction": "drift = what the persisted graph is missing relative to the inventory",
        **diff,
    }
