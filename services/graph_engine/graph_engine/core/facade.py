"""Pick Neo4j when Bolt is healthy, otherwise the in-process engine."""

from __future__ import annotations

from typing import Any

from graph_engine.config.settings import get_graph_settings
from graph_engine.connection.health_check import probe_neo4j
from graph_engine.connection.neo4j_driver import get_driver
from graph_engine.core.engine import GraphEngine
from graph_engine.core.store import Neo4jGraphStore
from graph_engine.core.sync_coordinator import ensure_populated


def memory_graph(**payload) -> GraphEngine:
    return GraphEngine().build(**payload)


def resolve_graph(payload: dict[str, Any], *, driver=None, sync_if_empty: bool = True):
    handle = driver if driver is not None else get_driver()
    health = probe_neo4j(handle)
    if handle is not None and health.get("ok"):
        store = Neo4jGraphStore(handle)
        if sync_if_empty:
            ensure_populated(payload, driver=handle)
        return store
    return memory_graph(**payload)


def graph_health(driver=None) -> dict[str, Any]:
    health = probe_neo4j(driver)
    settings = get_graph_settings()
    health["fallback"] = not health.get("ok")
    health["required"] = settings.NEO4J_REQUIRED
    return health
