"""Keep Neo4j aligned with the relational inventory."""

from __future__ import annotations

import logging
from typing import Any

from graph_engine.connection.health_check import probe_neo4j
from graph_engine.connection.neo4j_driver import get_driver
from graph_engine.core.store import Neo4jGraphStore

logger = logging.getLogger(__name__)


def sync_payload(payload: dict[str, Any], *, driver=None) -> dict[str, Any]:
    handle = driver if driver is not None else get_driver()
    if handle is None:
        return {"backend": "memory", "synced": False, "reason": "neo4j_unavailable"}
    store = Neo4jGraphStore(handle)
    try:
        store.apply_schema()
    except Exception:
        logger.debug("neo4j_schema_skipped", exc_info=True)
    result = store.sync(**payload)
    result["synced"] = True
    return result


def ensure_populated(payload: dict[str, Any], *, driver=None) -> dict[str, Any]:
    handle = driver if driver is not None else get_driver()
    health = probe_neo4j(handle)
    if not health.get("ok"):
        return {"backend": "memory", "synced": False, "health": health}
    store = Neo4jGraphStore(handle)
    counts = store.counts()
    if counts.get("nodes", 0) == 0:
        result = sync_payload(payload, driver=handle)
        result["health"] = health
        return result
    return {"backend": "neo4j", "synced": False, "reason": "already_populated", **counts, "health": health}
